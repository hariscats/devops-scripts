#!/usr/bin/env python3
"""
Azure API Management (APIM) subscription key rotation script.

Regenerates the primary and/or secondary key of one or more APIM subscription
entities (SIDs). Full keys are never logged; at DEBUG level only short key
prefixes are shown. Writes a JSON summary of the results.

Zero-downtime rotation: rotate one key at a time and move clients in between::

    azure-apim-rotate --keys secondary   # clients keep using the primary key
    # ...switch clients to the new secondary key...
    azure-apim-rotate --keys primary

Configuration (command-line flags override environment variables):
  --subscription-id   AZURE_SUBSCRIPTION_ID  (required)
  --resource-group    RESOURCE_GROUP         (required)
  --service-name      APIM_SERVICE_NAME      (required)
  --sid (repeatable)  SUBSCRIPTION_SID_1, SUBSCRIPTION_SID_2 (default: sub1, sub2)
  --rotate-order      APIM_ROTATE_ORDER      (primary-first | secondary-first)
  --keys              APIM_ROTATE_KEYS       (both | primary | secondary; default: both)
  --summary-file      APIM_SUMMARY_FILE      (default: apim_key_rotation_summary.json)
  LOG_LEVEL           (e.g. DEBUG to log key prefixes before/after each step)

Authentication:
  Uses DefaultAzureCredential (supports az login, Managed Identity, Service Principal).
  The identity needs the "API Management Service Contributor" role on the APIM
  instance (or a custom role with the subscriptions regenerate*/listSecrets actions).

Exit codes: 0 = all requested keys rotated, 1 = a rotation or sign-in failed,
2 = invalid configuration.

Usage:
  az login
  azure-apim-rotate -g my-rg -n my-apim --sid sub1 --sid sub2 --dry-run
  azure-apim-rotate -g my-rg -n my-apim --sid sub1 --sid sub2
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential

if TYPE_CHECKING:
    from azure.core.credentials import AccessToken, TokenCredential

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_VERSION = "2024-05-01"
ARM_SCOPE = "https://management.azure.com/.default"
BASE_URL = "https://management.azure.com"
SUCCESS_CODES: Tuple[int, ...] = (200, 201, 202, 204)
DEFAULT_TIMEOUT = 30
RETRY_STATUS_CODES: Tuple[int, ...] = (408, 429, 500, 502, 503, 504)
RETRY_ATTEMPTS = 3
MAX_RETRY_DELAY = 60.0
TOKEN_REFRESH_MARGIN = 300
SUMMARY_FILE = "apim_key_rotation_summary.json"
KEY_PREFIX_LEN = 8
KEY_CHOICES = ("both", "primary", "secondary")
AUTH_FAILED_MESSAGE = "Azure sign-in failed (run 'az login' or configure a managed identity)"
USER_AGENT = "devops-scripts/apim-key-rotation"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("apim.key_rotation")


def _configure_logging(level_name: Optional[str]) -> None:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    level = logging.getLevelName((level_name or "INFO").upper())
    if isinstance(level, int):
        logger.setLevel(level)
    else:
        logger.setLevel(logging.INFO)
        logger.warning("Ignoring invalid LOG_LEVEL %r (using INFO)", level_name)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class APIMPath:
    subscription_id: str
    resource_group: str
    service_name: str


@dataclass
class OperationResult:
    sid: str
    regenerate_primary_status: Optional[int]
    regenerate_secondary_status: Optional[int]
    ok: bool = True
    error: Optional[str] = None


@dataclass
class ApiResponse:
    ok: bool
    status: int
    data: Dict[str, Any]
    error: Optional[Any]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class APIMClientError(RuntimeError):
    """Raised for unrecoverable APIM client issues."""


class APIMAuthError(APIMClientError):
    """Raised when no Azure access token could be obtained."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer(token: str) -> str:
    return "Bearer " + token


def parse_retry_after(value: Optional[str], now: Optional[datetime] = None) -> Optional[float]:
    """Parse a ``Retry-After`` header (delay in seconds or an HTTP date) into seconds."""
    if not value or not value.strip():
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - (now or datetime.now(timezone.utc))).total_seconds())


def error_text(resp: ApiResponse) -> str:
    """Human-readable error from an ARM error payload (``{"error": {"code", "message"}}``)."""
    error = resp.data.get("error") if isinstance(resp.data, dict) else None
    if isinstance(error, dict):
        code, message = error.get("code"), error.get("message")
        return ": ".join(str(part) for part in (code, message) if part)
    return str(resp.error or "")[:500]


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class APIMClient:
    """Minimal APIM REST client for subscription key operations."""

    def __init__(
        self,
        path: APIMPath,
        credential: Optional[TokenCredential] = None,
        session: Optional[requests.Session] = None,
        timeout: int = DEFAULT_TIMEOUT,
        retry_attempts: int = RETRY_ATTEMPTS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._path = path
        self._credential = credential or DefaultAzureCredential()
        self._session = session or requests.Session()
        self._timeout = timeout
        self._retry_attempts = max(1, retry_attempts)
        self._sleep = sleep
        self._access_token: Optional[AccessToken] = None
        self._auth_failed = False

    # Public operations -----------------------------------------------------

    def get_subscription(self, sid: str) -> ApiResponse:
        return self._execute("GET", self._sid_url(sid))

    def regenerate_primary(self, sid: str) -> ApiResponse:
        return self._execute("POST", self._sid_url(sid, "regeneratePrimaryKey"))

    def regenerate_secondary(self, sid: str) -> ApiResponse:
        return self._execute("POST", self._sid_url(sid, "regenerateSecondaryKey"))

    def list_secrets(self, sid: str) -> ApiResponse:
        return self._execute("POST", self._sid_url(sid, "listSecrets"))

    # Internal helpers -----------------------------------------------------

    def _token(self) -> str:
        if self._auth_failed:
            raise APIMAuthError(AUTH_FAILED_MESSAGE)
        cached = self._access_token
        if cached is None or cached.expires_on - TOKEN_REFRESH_MARGIN <= time.time():
            try:
                cached = self._access_token = self._credential.get_token(ARM_SCOPE)
            except ClientAuthenticationError as exc:
                # Fail fast for the remaining calls instead of re-running the credential chain.
                self._auth_failed = True
                logger.error("%s\n%s", AUTH_FAILED_MESSAGE, exc.message)
                raise APIMAuthError(AUTH_FAILED_MESSAGE) from exc
        return cached.token

    def _base(self) -> str:
        p = self._path
        return (
            f"{BASE_URL}/subscriptions/{quote(p.subscription_id, safe='')}"
            f"/resourceGroups/{quote(p.resource_group, safe='')}"
            f"/providers/Microsoft.ApiManagement/service/{quote(p.service_name, safe='')}"
        )

    def _sid_url(self, sid: str, action: Optional[str] = None) -> str:
        suffix = f"/{action}" if action else ""
        return (
            f"{self._base()}/subscriptions/{quote(sid, safe='')}{suffix}?api-version={API_VERSION}"
        )

    def _execute(self, method: str, url: str) -> ApiResponse:
        path = url.split("?", 1)[0]
        operation = method + " " + "/".join(path.rsplit("/", 2)[-2:])
        last_error: Optional[Exception] = None
        for attempt in range(1, self._retry_attempts + 1):
            last_attempt = attempt == self._retry_attempts
            headers = {
                "Authorization": _bearer(self._token()),
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            }
            try:
                resp = self._session.request(method, url, headers=headers, timeout=self._timeout)
            except requests.RequestException as exc:
                last_error = exc
                if last_attempt:
                    break
                delay = self._backoff(attempt)
                logger.warning(
                    "%s: request error on attempt %d/%d (%s); retrying in %.0fs",
                    operation,
                    attempt,
                    self._retry_attempts,
                    exc,
                    delay,
                )
                self._sleep(delay)
                continue
            if resp.status_code not in RETRY_STATUS_CODES or last_attempt:
                return self._parse(resp)
            retry_after = parse_retry_after(resp.headers.get("Retry-After"))
            delay = min(
                MAX_RETRY_DELAY, retry_after if retry_after is not None else self._backoff(attempt)
            )
            logger.warning(
                "%s: transient HTTP %s on attempt %d/%d; retrying in %.0fs",
                operation,
                resp.status_code,
                attempt,
                self._retry_attempts,
                delay,
            )
            self._sleep(delay)
        raise APIMClientError(
            f"{operation}: no response after {self._retry_attempts} attempts: {last_error}"
        )

    @staticmethod
    def _backoff(attempt: int) -> float:
        return float(min(30, 2**attempt))

    @staticmethod
    def _parse(resp: requests.Response) -> ApiResponse:
        try:
            data: Any = resp.json() if resp.content else {}
        except ValueError:
            data = {"raw": resp.text}
        if not isinstance(data, dict):
            data = {"value": data}
        ok = resp.status_code in SUCCESS_CODES
        return ApiResponse(
            ok=ok, status=resp.status_code, data=data, error=None if ok else data or resp.text
        )


# ---------------------------------------------------------------------------
# High-level rotation
# ---------------------------------------------------------------------------


def key_preview(key: Optional[str]) -> str:
    if not key:
        return "N/A"
    return f"{key[:KEY_PREFIX_LEN]}..."


def _snapshot(client: APIMClient, sid: str, label: str) -> Optional[Dict[str, Any]]:
    """Fetch the current keys (kept in memory only) to verify that a rotation took effect."""
    try:
        resp = client.list_secrets(sid)
    except APIMClientError as exc:
        logger.warning("SID=%s: listSecrets %s failed: %s", sid, label, exc)
        return None
    if not resp.ok:
        logger.warning("SID=%s: listSecrets %s failed (HTTP %s)", sid, label, resp.status)
        return None
    logger.debug(
        "SID=%s: %s primary=%s secondary=%s",
        sid,
        label,
        key_preview(resp.data.get("primaryKey")),
        key_preview(resp.data.get("secondaryKey")),
    )
    return resp.data


def rotate_for_sid(client: APIMClient, sid: str, order: List[str]) -> OperationResult:
    """
    Rotate keys for a SID following the specified order.

    order: list like ["primary","secondary"], ["secondary","primary"] or a single key.
    Stops at the first failure so the other key keeps working.
    """
    logger.info("SID=%s: starting rotation order=%s", sid, "->".join(order))
    statuses: Dict[str, Optional[int]] = {}
    error: Optional[str] = None
    before = _snapshot(client, sid, "before rotation")

    for which in order:
        regenerate = (
            client.regenerate_primary if which == "primary" else client.regenerate_secondary
        )
        try:
            resp = regenerate(sid)
        except APIMClientError as exc:
            statuses[which] = None
            error = f"regenerate {which}: {exc}"
            logger.error("SID=%s: %s", sid, error)
            break
        statuses[which] = resp.status
        if not resp.ok:
            error = f"regenerate {which}: HTTP {resp.status} {error_text(resp)}".strip()
            logger.error("SID=%s: %s", sid, error)
            break
        logger.info("SID=%s: regenerate %s -> %s OK", sid, which, resp.status)

        after = _snapshot(client, sid, f"after {which}")
        field = f"{which}Key"
        if before and after and before.get(field) and before.get(field) == after.get(field):
            logger.warning("SID=%s: listSecrets still returns the old %s key", sid, which)
        before = after or before

    return OperationResult(
        sid=sid,
        regenerate_primary_status=statuses.get("primary"),
        regenerate_secondary_status=statuses.get("secondary"),
        ok=error is None,
        error=error,
    )


def describe_sid(client: APIMClient, sid: str, order: List[str]) -> bool:
    """Dry run: confirm the SID exists and log what would be rotated."""
    try:
        resp = client.get_subscription(sid)
    except APIMClientError as exc:
        logger.error("[dry-run] SID=%s: lookup failed: %s", sid, exc)
        return False
    if not resp.ok:
        logger.error(
            "[dry-run] SID=%s: lookup failed: HTTP %s %s", sid, resp.status, error_text(resp)
        )
        return False
    props = resp.data.get("properties") or {}
    logger.info(
        "[dry-run] SID=%s: found (displayName=%s, state=%s, scope=%s); would regenerate %s",
        sid,
        props.get("displayName"),
        props.get("state"),
        str(props.get("scope") or "").rsplit("/", 1)[-1] or "-",
        " then ".join(order),
    )
    return True


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="azure-apim-rotate",
        description="APIM subscription key rotation",
        epilog="Flags override the environment variables shown in brackets.",
    )
    parser.add_argument("--subscription-id", help="Azure subscription ID [AZURE_SUBSCRIPTION_ID]")
    parser.add_argument("-g", "--resource-group", help="Resource group [RESOURCE_GROUP]")
    parser.add_argument("-n", "--service-name", help="APIM instance name [APIM_SERVICE_NAME]")
    parser.add_argument(
        "--sid",
        dest="sids",
        action="append",
        metavar="SID",
        help="APIM subscription ID to rotate; repeatable "
        "[SUBSCRIPTION_SID_1, SUBSCRIPTION_SID_2; default: sub1 sub2]",
    )
    parser.add_argument(
        "--rotate-order",
        choices=["primary-first", "secondary-first"],
        help="Override rotation order (default: primary-first or env APIM_ROTATE_ORDER)",
    )
    parser.add_argument(
        "--keys",
        choices=KEY_CHOICES,
        help="Which keys to regenerate [APIM_ROTATE_KEYS; default: both]",
    )
    parser.add_argument(
        "--summary-file",
        help=f"Where to write the JSON summary [APIM_SUMMARY_FILE; default: {SUMMARY_FILE}]",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check that each SID exists and show what would be rotated, without changing keys",
    )
    return parser.parse_args(argv)


def resolve_order(arg_value: Optional[str], keys: str = "both") -> List[str]:
    # Priority: CLI flag > env var > default
    val = (arg_value or os.getenv("APIM_ROTATE_ORDER") or "primary-first").lower()
    if keys in ("primary", "secondary"):
        return [keys]
    if val == "secondary-first":
        return ["secondary", "primary"]
    # Fallback default
    return ["primary", "secondary"]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_env() -> Tuple[str, str, str, List[str]]:
    sub_id = os.getenv("AZURE_SUBSCRIPTION_ID", "<your-azure-subscription-id>")
    rg = os.getenv("RESOURCE_GROUP", "<your-resource-group>")
    svc = os.getenv("APIM_SERVICE_NAME", "<your-apim-service>")
    sids = [
        os.getenv("SUBSCRIPTION_SID_1", "sub1"),
        os.getenv("SUBSCRIPTION_SID_2", "sub2"),
    ]
    return sub_id, rg, svc, sids


def validate_required(sub_id: str, rg: str, svc: str) -> bool:
    placeholders = [
        ("AZURE_SUBSCRIPTION_ID", sub_id),
        ("RESOURCE_GROUP", rg),
        ("APIM_SERVICE_NAME", svc),
    ]
    missing = [name for name, val in placeholders if not val.strip() or val.startswith("<")]
    if missing:
        logger.error("Missing required configuration: %s", ", ".join(missing))
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_logging(os.getenv("LOG_LEVEL"))
    args = parse_args(argv)

    env_sub, env_rg, env_svc, env_sids = load_env()
    sub_id = (args.subscription_id or env_sub).strip()
    rg = (args.resource_group or env_rg).strip()
    svc = (args.service_name or env_svc).strip()
    sids = [sid.strip() for sid in (args.sids or env_sids) if sid.strip()]
    if not validate_required(sub_id, rg, svc):
        return 2
    if not sids:
        logger.error("No APIM subscription IDs to rotate (use --sid or SUBSCRIPTION_SID_1/2)")
        return 2
    keys = (args.keys or os.getenv("APIM_ROTATE_KEYS") or "both").lower()
    if keys not in KEY_CHOICES:
        logger.error(
            "Invalid APIM_ROTATE_KEYS %r (expected one of %s)", keys, ", ".join(KEY_CHOICES)
        )
        return 2

    order = resolve_order(args.rotate_order, keys)
    logger.info(
        "APIM context subscription=%s resourceGroup=%s service=%s rotateOrder=%s",
        sub_id,
        rg,
        svc,
        "->".join(order),
    )
    logger.info("Target SIDs: %s", ", ".join(sids))

    client = APIMClient(APIMPath(sub_id, rg, svc))

    if args.dry_run:
        found = [describe_sid(client, sid, order) for sid in sids]
        logger.info("[dry-run] No keys were changed")
        return 0 if all(found) else 1

    results = [rotate_for_sid(client, sid, order) for sid in sids]

    summary_file = args.summary_file or os.getenv("APIM_SUMMARY_FILE") or SUMMARY_FILE
    with open(summary_file, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in results], fh, indent=2)

    failed = [r.sid for r in results if not r.ok]
    if failed:
        logger.error("Rotation failed for: %s", ", ".join(failed))
    print(f"Summary saved to {summary_file}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
