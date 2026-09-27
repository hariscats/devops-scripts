"""Minimal Azure REST client shared by the ``azure-tools`` commands.

Only ``requests`` and ``azure-identity`` are needed. The client:

- authenticates with ``DefaultAzureCredential`` (``az login``, managed identity, service
  principal environment variables, ...) and caches one access token per scope;
- retries throttled (429), transient (408/5xx) and connection failures with capped
  exponential backoff, honouring ``Retry-After`` style headers;
- follows ``nextLink`` paging and Azure Resource Graph ``$skipToken`` paging;
- turns ARM error payloads into readable :class:`AzureError` messages.

It is meant for read operations: every request it sends is safe to retry.
Only the Azure public cloud endpoints are supported.
"""

from __future__ import annotations

import base64
import email.utils
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
from urllib.parse import quote, urlsplit

import requests

if TYPE_CHECKING:  # pragma: no cover
    from azure.core.credentials import AccessToken, TokenCredential

logger = logging.getLogger(__name__)

ARM_ENDPOINT = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
RESOURCE_GRAPH_API_VERSION = "2024-04-01"
SUBSCRIPTIONS_API_VERSION = "2022-12-01"
RETRY_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})
TOKEN_REFRESH_MARGIN_SECONDS = 300
RESOURCE_GRAPH_MAX_PAGE_SIZE = 1000
USER_AGENT = "devops-tools-azure"

_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HMS_RE = re.compile(r"^(\d+):(\d{1,2}):(\d{1,2})(?:\.\d+)?$")


class AzureError(Exception):
    """An Azure REST call failed (after any retries)."""

    def __init__(
        self, message: str, status: Optional[int] = None, code: Optional[str] = None
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


def is_guid(value: str) -> bool:
    """Return True when *value* looks like a GUID (for example a subscription ID)."""
    return bool(_GUID_RE.match(value.strip()))


def parse_retry_after(value: Optional[str], now: Optional[datetime] = None) -> Optional[float]:
    """Parse a ``Retry-After`` header value (delta-seconds or HTTP-date) into seconds."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return max(0.0, (when - current).total_seconds())


def _parse_hms(value: Optional[str]) -> Optional[float]:
    """Parse an ``HH:MM:SS`` duration (Resource Graph quota reset header) into seconds."""
    match = _HMS_RE.match((value or "").strip())
    if not match:
        return None
    hours, minutes, seconds = (int(part) for part in match.groups())
    return float(hours * 3600 + minutes * 60 + seconds)


def token_claims(token: str) -> Dict[str, Any]:
    """Decode the payload of a JWT access token *without* verifying it (display only)."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def bearer(token: str) -> str:
    """Build an HTTP ``Authorization`` header value for an access token."""
    return "Bearer " + token


def strip_query(url: str) -> str:
    """Drop the query string (skip tokens, filters) from a URL for use in messages."""
    return url.split("?", 1)[0]


def _encode_params(params: Mapping[str, Any]) -> str:
    return "&".join(
        f"{quote(str(key), safe='$')}={quote(str(value), safe='')}"
        for key, value in params.items()
        if value is not None
    )


def _same_host(first: str, second: str) -> bool:
    a, b = urlsplit(first), urlsplit(second)
    return b.scheme == "https" and (a.hostname or "").lower() == (b.hostname or "").lower()


def _error_details(resp: requests.Response) -> Tuple[Optional[str], str]:
    """Extract ``(code, message)`` from an ARM / data-plane error response."""
    code: Optional[str] = None
    message: Optional[str] = None
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        error = payload.get("error", payload)
        if isinstance(error, dict):
            if isinstance(error.get("code"), str):
                code = error["code"]
            if isinstance(error.get("message"), str):
                message = error["message"]
            details = [
                d for d in error.get("details") or [] if isinstance(d, dict) and d.get("message")
            ]
            if details:
                extra = "; ".join(
                    f"{d['code']}: {d['message']}" if d.get("code") else str(d["message"])
                    for d in details
                )
                message = f"{message} {extra}" if message else extra
    if not message:
        message = (resp.text or "").strip()[:500] or (resp.reason or "request failed")
    return code, message


class AzureClient:
    """Small Azure REST client with token caching, retries and paging.

    Relative URLs (starting with ``/``) are sent to Azure Resource Manager. Absolute URLs
    are used for data-plane calls (for example Key Vault) together with a matching
    token *scope*.
    """

    def __init__(
        self,
        credential: Optional["TokenCredential"] = None,
        session: Optional[requests.Session] = None,
        timeout: float = 60.0,
        max_retries: int = 4,
        max_backoff: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._credential = credential
        self._session = session or requests.Session()
        self._timeout = timeout
        self._max_retries = max_retries
        self._max_backoff = max_backoff
        self._sleep = sleep
        self._tokens: Dict[str, "AccessToken"] = {}
        self._subscriptions: Optional[List[Dict[str, Any]]] = None

    # Authentication --------------------------------------------------------

    @property
    def credential(self) -> "TokenCredential":
        if self._credential is None:
            from azure.identity import DefaultAzureCredential

            self._credential = DefaultAzureCredential()
        return self._credential

    def token(self, scope: str = ARM_SCOPE) -> str:
        """Return a cached access token for *scope*, refreshing it shortly before expiry."""
        cached = self._tokens.get(scope)
        if cached is None or cached.expires_on - TOKEN_REFRESH_MARGIN_SECONDS <= time.time():
            cached = self.credential.get_token(scope)
            self._tokens[scope] = cached
        return cached.token

    # HTTP ------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Any] = None,
        scope: str = ARM_SCOPE,
    ) -> Any:
        """Send a request and return the decoded JSON body (``{}`` when empty)."""
        full_url = self._url(url, params)
        attempt = 0
        token_refreshed = False
        while True:
            headers = {
                "Authorization": bearer(self.token(scope)),
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
            try:
                resp = self._session.request(
                    method, full_url, headers=headers, json=json_body, timeout=self._timeout
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                if attempt >= self._max_retries:
                    raise AzureError(f"{method} {strip_query(full_url)} failed: {exc}") from exc
                attempt += 1
                delay = self._backoff(attempt)
                logger.warning(
                    "%s %s failed (%s); retrying in %.1fs (retry %d/%d)",
                    method,
                    strip_query(full_url),
                    type(exc).__name__,
                    delay,
                    attempt,
                    self._max_retries,
                )
                self._sleep(delay)
                continue

            if resp.status_code == 401 and not token_refreshed:
                # The cached token may have been revoked or expired early: retry once.
                token_refreshed = True
                self._tokens.pop(scope, None)
                continue
            if resp.status_code in RETRY_STATUS_CODES and attempt < self._max_retries:
                attempt += 1
                delay = self._retry_delay(resp, attempt)
                logger.warning(
                    "HTTP %s from %s %s; retrying in %.1fs (retry %d/%d)",
                    resp.status_code,
                    method,
                    strip_query(full_url),
                    delay,
                    attempt,
                    self._max_retries,
                )
                self._sleep(delay)
                continue
            if resp.status_code >= 400:
                code, message = _error_details(resp)
                text = f"HTTP {resp.status_code} from {method} {strip_query(full_url)}"
                if code:
                    text += f" [{code}]"
                raise AzureError(f"{text}: {message}", status=resp.status_code, code=code)
            if resp.status_code == 204 or not resp.content:
                return {}
            try:
                return resp.json()
            except ValueError as exc:
                raise AzureError(
                    f"Unexpected non-JSON response from {method} {strip_query(full_url)}",
                    status=resp.status_code,
                ) from exc

    def get(
        self, url: str, *, params: Optional[Mapping[str, Any]] = None, scope: str = ARM_SCOPE
    ) -> Any:
        return self.request("GET", url, params=params, scope=scope)

    def post(
        self,
        url: str,
        body: Optional[Any] = None,
        *,
        params: Optional[Mapping[str, Any]] = None,
        scope: str = ARM_SCOPE,
    ) -> Any:
        return self.request("POST", url, params=params, json_body=body, scope=scope)

    def paged(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        scope: str = ARM_SCOPE,
        item_key: str = "value",
    ) -> Iterator[Dict[str, Any]]:
        """Yield items from a list operation, following ``nextLink`` pages."""
        first_url = self._url(url, None)
        page = self.get(url, params=params, scope=scope)
        while True:
            if not isinstance(page, dict):
                return
            for item in page.get(item_key) or []:
                yield item
            next_link = page.get("nextLink")
            if not next_link:
                return
            if not _same_host(first_url, str(next_link)):
                raise AzureError(
                    f"Refusing to follow nextLink to another host: {strip_query(str(next_link))}"
                )
            page = self.get(str(next_link), scope=scope)

    # Azure Resource Manager helpers -----------------------------------------

    def list_subscriptions(self) -> List[Dict[str, Any]]:
        """Return the subscriptions the signed-in identity can access (cached)."""
        if self._subscriptions is None:
            self._subscriptions = list(
                self.paged("/subscriptions", params={"api-version": SUBSCRIPTIONS_API_VERSION})
            )
        return self._subscriptions

    def resource_graph(
        self,
        query: str,
        *,
        subscriptions: Optional[Sequence[str]] = None,
        management_groups: Optional[Sequence[str]] = None,
        page_size: int = RESOURCE_GRAPH_MAX_PAGE_SIZE,
        max_rows: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Run an Azure Resource Graph query and return all rows (following skip tokens).

        Without *subscriptions* or *management_groups* the query covers every
        subscription the identity can access.
        """
        page_size = max(1, min(page_size, RESOURCE_GRAPH_MAX_PAGE_SIZE))
        rows: List[Dict[str, Any]] = []
        skip_token: Optional[str] = None
        total: Optional[int] = None
        truncated = False
        while True:
            top = page_size if max_rows is None else max(1, min(page_size, max_rows - len(rows)))
            options: Dict[str, Any] = {"resultFormat": "objectArray", "$top": top}
            if skip_token:
                options["$skipToken"] = skip_token
            body: Dict[str, Any] = {"query": query, "options": options}
            if subscriptions:
                body["subscriptions"] = list(subscriptions)
            if management_groups:
                body["managementGroups"] = list(management_groups)
            page = self.post(
                "/providers/Microsoft.ResourceGraph/resources",
                body,
                params={"api-version": RESOURCE_GRAPH_API_VERSION},
            )
            data = page.get("data") or []
            rows.extend(data)
            if page.get("totalRecords") is not None:
                total = int(page["totalRecords"])
            truncated = str(page.get("resultTruncated", "false")).lower() == "true"
            skip_token = page.get("$skipToken")
            if max_rows is not None and len(rows) >= max_rows:
                return rows[:max_rows]
            if not skip_token or not data:
                break
        if truncated or (total is not None and len(rows) < total):
            logger.warning(
                "Resource Graph returned %d of %s rows. Queries without an 'id' column "
                "(for example 'summarize') cannot be paged; narrow the query if rows are "
                "missing.",
                len(rows),
                total if total is not None else "more",
            )
        return rows

    # Internals ---------------------------------------------------------------

    def _url(self, url: str, params: Optional[Mapping[str, Any]]) -> str:
        if url.startswith("/"):
            url = ARM_ENDPOINT + url
        if not url.lower().startswith("https://"):
            raise ValueError(f"Only https:// URLs are supported: {url}")
        if params:
            query = _encode_params(params)
            if query:
                url = f"{url}{'&' if '?' in url else '?'}{query}"
        return url

    def _backoff(self, attempt: int) -> float:
        return float(min(self._max_backoff, 2 ** (attempt - 1)))

    def _retry_delay(self, resp: requests.Response, attempt: int) -> float:
        delay: Optional[float] = None
        for header in ("retry-after-ms", "x-ms-retry-after-ms"):
            raw = resp.headers.get(header)
            if raw:
                try:
                    delay = float(raw) / 1000.0
                    break
                except ValueError:
                    continue
        if delay is None:
            delay = parse_retry_after(resp.headers.get("Retry-After"))
        if delay is None:
            delay = _parse_hms(resp.headers.get("x-ms-user-quota-resets-after"))
        if delay is None:
            delay = self._backoff(attempt)
        return min(self._max_backoff, max(0.0, delay))
