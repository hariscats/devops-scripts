"""Fakes and fixtures for the Azure tool tests (no network access, no real credentials)."""

import json
import time
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

import pytest
from azure.core.credentials import AccessToken
from click.testing import CliRunner
from requests.structures import CaseInsensitiveDict

from devops_tools.azure.cli import cli
from devops_tools.azure.client import AzureClient
from devops_tools.azure.common import AzureContext


class FakeResponse:
    """Just enough of ``requests.Response`` for the code under test."""

    def __init__(
        self,
        status: int = 200,
        json_data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        text: Optional[str] = None,
        reason: str = "",
    ) -> None:
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {})
        if text is None:
            text = "" if json_data is None else json.dumps(json_data)
        self.text = text
        self.content = text.encode("utf-8")
        self.reason = reason

    def json(self) -> Any:
        return json.loads(self.text)


class Call:
    def __init__(self, method: str, url: str, headers: Dict[str, str], body: Any) -> None:
        self.method = method
        self.url = url
        self.headers = headers
        self.json = body


class FakeSession:
    """Routes requests by HTTP method and URL substring to canned responses.

    ``reply(method, pattern, *specs)`` registers responses; each spec is a dict of
    ``FakeResponse`` arguments (``status``, ``json_data``, ``headers``, ``text``) or an
    exception to raise. Several specs are returned in order (the last one repeats).
    ``handler`` computes the spec from the :class:`Call` instead.
    """

    def __init__(self) -> None:
        self.routes: List[List[Any]] = []
        self.calls: List[Call] = []

    def reply(
        self,
        method: str,
        pattern: str,
        *specs: Any,
        handler: Optional[Callable[[Call], Any]] = None,
    ) -> None:
        self.routes.append([method.upper(), pattern, list(specs), handler])

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Any = None,
        timeout: Any = None,
        **kwargs: Any,
    ) -> FakeResponse:
        call = Call(method.upper(), url, dict(headers or {}), json)
        self.calls.append(call)
        for route_method, pattern, specs, handler in self.routes:
            if route_method != call.method or pattern not in url:
                continue
            spec = handler(call) if handler else (specs.pop(0) if len(specs) > 1 else specs[0])
            if isinstance(spec, BaseException):
                raise spec
            return FakeResponse(**spec)
        raise AssertionError(f"unexpected request: {method} {url}")

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.request("POST", url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        pass

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc: Any) -> None:
        pass

    def find(self, pattern: str, method: Optional[str] = None) -> List[Call]:
        return [c for c in self.calls if pattern in c.url and method in (None, c.method)]


class FakeCredential:
    """Token credential returning a fixed token (or raising ``error``)."""

    def __init__(
        self, token: str = "fake-token", expires_in: int = 3600, error: Optional[Exception] = None
    ) -> None:
        self.token = token
        self.expires_in = expires_in
        self.error = error
        self.scopes: List[str] = []

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        self.scopes.extend(scopes)
        if self.error is not None:
            raise self.error
        return AccessToken(self.token, int(time.time()) + self.expires_in)


def arg_page(rows: List[Dict[str, Any]], skip_token: Optional[str] = None) -> Dict[str, Any]:
    """A Resource Graph response spec."""
    body: Dict[str, Any] = {"totalRecords": len(rows), "count": len(rows), "data": rows}
    if skip_token:
        body["$skipToken"] = skip_token
    return {"json_data": body}


def make_runner() -> CliRunner:
    try:
        return CliRunner(mix_stderr=False)  # Click < 8.2
    except TypeError:
        return CliRunner()  # Click >= 8.2 keeps stderr separate


@pytest.fixture
def fakes() -> SimpleNamespace:
    """The fake classes and helpers, for tests that need to build their own."""
    return SimpleNamespace(
        FakeResponse=FakeResponse,
        FakeSession=FakeSession,
        FakeCredential=FakeCredential,
        arg_page=arg_page,
        make_runner=make_runner,
    )


@pytest.fixture
def azure_session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def azure_credential() -> FakeCredential:
    return FakeCredential()


@pytest.fixture
def sleeps() -> List[float]:
    return []


@pytest.fixture
def azure_client(
    azure_session: FakeSession, azure_credential: FakeCredential, sleeps: List[float]
) -> AzureClient:
    return AzureClient(credential=azure_credential, session=azure_session, sleep=sleeps.append)


@pytest.fixture
def run_azure(azure_client: AzureClient, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Any]:
    """Invoke ``azure-tools`` with the fake client; returns the Click result."""
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    monkeypatch.setattr("devops_tools.azure.common.az_cli_subscription", lambda: None)

    def run(*args: str) -> Any:
        return make_runner().invoke(
            cli, list(args), obj=AzureContext(client=azure_client), env={"COLUMNS": "200"}
        )

    return run
