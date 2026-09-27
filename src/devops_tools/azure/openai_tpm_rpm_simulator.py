#!/usr/bin/env python3
"""
Azure OpenAI TPM/RPM simulator.

- Sends N chat completion requests to a single deployment.
- Prints HTTP status, latency, token usage and the x-ratelimit-* headers.
- Lets you vary max tokens, prompt size and pacing to see throttling (HTTP 429)
  behavior, then prints a summary with the observed requests/tokens per minute.

Azure OpenAI admits each request against the TPM limit using an estimate of the
prompt tokens plus max tokens (times n), so a large --max-tokens is throttled
sooner even when the completions are short.

Configuration (command-line flags override environment variables):
  --endpoint     AOAI_ENDPOINT     https://<your-resource>.openai.azure.com
  --deployment   AOAI_DEPLOYMENT   <deployment-name>
  --api-key      AOAI_API_KEY      optional: without a key, Microsoft Entra ID is used
                                   (DefaultAzureCredential, role "Cognitive Services
                                   OpenAI User")
  --api-version  AOAI_API_VERSION  default: 2024-10-21

Examples:
  azure-openai-sim --calls 20 --interval 0 --max-tokens 2000
  azure-openai-sim --calls 10 --interval 2 --respect-retry-after --show-body
  # Reasoning (o-series) models:
  azure-openai-sim --api-version 2024-12-01-preview \\
      --max-tokens-param max_completion_tokens --temperature none

Exit codes: 0 = no errors other than throttling, 1 = a request failed,
2 = invalid configuration or sign-in failure.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Union
from urllib.parse import quote

import requests

if TYPE_CHECKING:
    from azure.core.credentials import AccessToken, TokenCredential

PROMPT = (
    "Write a detailed essay on the impact of artificial intelligence on modern society. "
    "Cover the following points:\n\n"
    "1. Introduction to artificial intelligence and its historical development.\n"
    "2. The various applications of AI in different sectors such as healthcare, finance, "
    "education, and transportation.\n"
    "3. The benefits of AI, including increased efficiency, accuracy, and the potential for "
    "innovation.\n"
    "4. The ethical considerations and potential risks associated with AI, including issues "
    "of privacy, job displacement, and decision-making biases.\n"
    "5. The future of AI, including emerging technologies, potential advancements, and their "
    "implications for society.\n"
    "6. Conclude with a balanced view on how society can best leverage AI while addressing "
    "its challenges."
)

# -------- defaults for the command-line options --------
TOTAL_CALLS = 6  # Number of requests to send
SPACING_SECONDS = 10.0  # Time between requests
MAX_TOKENS = 800  # Maximum tokens for completion
N_CHOICES = 1  # Number of choices per request
TEMPERATURE = 0.7
TIMEOUT_SEC = 60.0
DEFAULT_API_VERSION = "2024-10-21"
# --------------------------------------------------------

COGNITIVE_SERVICES_SCOPE = "https://cognitiveservices.azure.com/.default"
TOKEN_REFRESH_MARGIN = 300
RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit-requests",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-reset-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-tokens",
)
INFO_HEADERS = ("retry-after", "retry-after-ms", "x-ms-region", "apim-request-id", "x-request-id")


def _bearer(token: str) -> str:
    return "Bearer " + token


def _to_float(value: Optional[str]) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def _to_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class ApiKeyAuth:
    """``api-key`` header authentication."""

    description = "api-key"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def headers(self) -> Dict[str, str]:
        return {"api-key": self._api_key}


class EntraAuth:
    """Microsoft Entra ID bearer token authentication (token cached until near expiry)."""

    description = "Microsoft Entra ID"

    def __init__(self, credential: Optional[TokenCredential] = None) -> None:
        self._credential = credential
        self._token: Optional[AccessToken] = None

    def headers(self) -> Dict[str, str]:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential

            self._credential = DefaultAzureCredential()
        token = self._token
        if token is None or token.expires_on - TOKEN_REFRESH_MARGIN <= time.time():
            token = self._token = self._credential.get_token(COGNITIVE_SERVICES_SCOPE)
        return {"Authorization": _bearer(token.token)}


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


@dataclass
class CallResult:
    index: int
    status: Optional[int]  # None when no HTTP response was received
    latency: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    content: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def throttled(self) -> bool:
        return self.status == 429

    @property
    def retry_after(self) -> Optional[float]:
        """Seconds to wait before retrying, from ``retry-after-ms`` or ``retry-after``."""
        millis = _to_float(self.headers.get("retry-after-ms"))
        if millis is not None:
            return millis / 1000.0
        return _to_float(self.headers.get("retry-after"))


def build_url(endpoint: str, deployment: str, api_version: str) -> str:
    return (
        f"{endpoint.rstrip('/')}/openai/deployments/{quote(deployment, safe='')}"
        f"/chat/completions?api-version={quote(api_version, safe='')}"
    )


def build_body(
    prompt: str,
    max_tokens: int = MAX_TOKENS,
    max_tokens_param: str = "max_tokens",
    temperature: Optional[float] = TEMPERATURE,
    n: int = N_CHOICES,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt},
        ],
        max_tokens_param: max_tokens,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if n > 1:
        body["n"] = n
    return body


def _error_message(data: Dict[str, Any], text: str) -> str:
    error = data.get("error")
    if isinstance(error, dict):
        return ": ".join(str(p) for p in (error.get("code"), error.get("message")) if p)
    return text[:300]


def one_call(
    session: requests.Session,
    i: int,
    url: str,
    headers: Dict[str, str],
    body: Dict[str, Any],
    timeout: float = TIMEOUT_SEC,
) -> CallResult:
    t0 = time.monotonic()
    try:
        resp = session.post(url, headers=headers, json=body, timeout=timeout)
    except requests.RequestException as exc:
        return CallResult(index=i, status=None, latency=time.monotonic() - t0, error=str(exc))
    latency = time.monotonic() - t0

    try:
        data = resp.json()
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    usage = data.get("usage") or {}
    wanted = RATE_LIMIT_HEADERS + INFO_HEADERS
    result = CallResult(
        index=i,
        status=resp.status_code,
        latency=latency,
        prompt_tokens=_to_int(usage.get("prompt_tokens")),
        completion_tokens=_to_int(usage.get("completion_tokens")),
        total_tokens=_to_int(usage.get("total_tokens")),
        headers={k.lower(): v for k, v in resp.headers.items() if k.lower() in wanted},
    )
    if not result.ok:
        result.error = _error_message(data, resp.text)
    else:
        try:
            result.content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            result.content = None
    return result


def print_call(result: CallResult, show_body: bool = False) -> None:
    h = result.headers
    status = f"HTTP {result.status}" if result.status is not None else "NO RESPONSE"
    extras = "".join(
        f" | {label}={h[key]}"
        for label, key in (("region", "x-ms-region"), ("request-id", "apim-request-id"))
        if h.get(key)
    )
    print(f"\n== Call {result.index} | {status} | {result.latency:.2f}s{extras} ==")
    if result.ok:
        print(
            f"usage  prompt={result.prompt_tokens} completion={result.completion_tokens} "
            f"total={result.total_tokens}"
        )
    print(
        f"RPM    limit={h.get('x-ratelimit-limit-requests')} "
        f"remaining={h.get('x-ratelimit-remaining-requests')} "
        f"reset={h.get('x-ratelimit-reset-requests')}"
    )
    print(
        f"TPM    limit={h.get('x-ratelimit-limit-tokens')} "
        f"remaining={h.get('x-ratelimit-remaining-tokens')} "
        f"reset={h.get('x-ratelimit-reset-tokens')}"
    )
    if result.retry_after is not None:
        print(f"retry-after={result.retry_after:g}s")
    if result.throttled:
        print(f"THROTTLED: {result.error}")
    elif not result.ok:
        print(f"ERROR: {result.error}")
    elif show_body and result.content:
        snippet = result.content[:160].replace("\n", " ")
        print(f"body: {snippet} …")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def summarize(results: Sequence[CallResult], elapsed: float) -> Dict[str, Any]:
    ok = [r for r in results if r.ok]
    minutes = elapsed / 60.0

    def lowest(header: str) -> Optional[int]:
        values = [_to_float(r.headers.get(header)) for r in results]
        numbers = [int(v) for v in values if v is not None]
        return min(numbers) if numbers else None

    tokens = sum(r.total_tokens for r in ok)
    return {
        "calls": len(results),
        "ok": len(ok),
        "throttled": sum(1 for r in results if r.throttled),
        "errors": sum(1 for r in results if not r.ok and not r.throttled),
        "elapsed_s": elapsed,
        "latency_avg_s": sum(r.latency for r in ok) / len(ok) if ok else None,
        "latency_max_s": max((r.latency for r in ok), default=None),
        "prompt_tokens": sum(r.prompt_tokens for r in ok),
        "completion_tokens": sum(r.completion_tokens for r in ok),
        "total_tokens": tokens,
        "requests_per_min": len(results) / minutes if minutes > 0 else None,
        "tokens_per_min": tokens / minutes if minutes > 0 else None,
        "lowest_remaining_requests": lowest("x-ratelimit-remaining-requests"),
        "lowest_remaining_tokens": lowest("x-ratelimit-remaining-tokens"),
    }


def _fmt(value: Optional[float], suffix: str = "", digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}{suffix}"


def print_summary(summary: Dict[str, Any]) -> None:
    print("\n== Summary ==")
    print(
        f"calls={summary['calls']} ok={summary['ok']} throttled={summary['throttled']} "
        f"errors={summary['errors']} elapsed={summary['elapsed_s']:.1f}s"
    )
    print(
        f"latency avg={_fmt(summary['latency_avg_s'], 's')} "
        f"max={_fmt(summary['latency_max_s'], 's')} (successful calls)"
    )
    print(
        f"tokens  prompt={summary['prompt_tokens']} completion={summary['completion_tokens']} "
        f"total={summary['total_tokens']}"
    )
    print(
        f"observed rate: {_fmt(summary['requests_per_min'], digits=1)} requests/min, "
        f"{_fmt(summary['tokens_per_min'], digits=0)} tokens/min"
    )
    print(
        f"lowest remaining: requests={summary['lowest_remaining_requests']} "
        f"tokens={summary['lowest_remaining_tokens']}"
    )


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _temperature(value: str) -> Optional[float]:
    if value.strip().lower() == "none":
        return None
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid temperature: {value!r}") from None
    if not 0.0 <= number <= 2.0:
        raise argparse.ArgumentTypeError("temperature must be between 0 and 2 (or 'none')")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return number


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="azure-openai-sim",
        description="Send chat completion requests to an Azure OpenAI deployment and report "
        "rate-limit headers, throttling and usage.",
        epilog="Flags override the environment variables shown in brackets.",
    )
    parser.add_argument(
        "--endpoint",
        default=os.getenv("AOAI_ENDPOINT"),
        help="https://<resource>.openai.azure.com [AOAI_ENDPOINT]",
    )
    parser.add_argument(
        "--deployment", default=os.getenv("AOAI_DEPLOYMENT"), help="Deployment [AOAI_DEPLOYMENT]"
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("AOAI_API_KEY"),
        help="API key [AOAI_API_KEY]; when unset, a Microsoft Entra ID token is used",
    )
    parser.add_argument(
        "--api-version",
        default=os.getenv("AOAI_API_VERSION", DEFAULT_API_VERSION),
        help=f"Inference API version [AOAI_API_VERSION; default: {DEFAULT_API_VERSION}]",
    )
    parser.add_argument("--calls", type=_positive_int, default=TOTAL_CALLS, help="Requests to send")
    parser.add_argument(
        "--interval",
        type=_non_negative_float,
        default=SPACING_SECONDS,
        help=f"Seconds to wait between requests (default: {SPACING_SECONDS:g})",
    )
    parser.add_argument(
        "--respect-retry-after",
        action="store_true",
        help="After a 429, wait at least the retry-after time before the next request",
    )
    parser.add_argument(
        "--max-tokens", type=_positive_int, default=MAX_TOKENS, help="Completion token limit"
    )
    parser.add_argument(
        "--max-tokens-param",
        choices=["max_tokens", "max_completion_tokens"],
        default="max_tokens",
        help="Request field for the token limit (reasoning models need max_completion_tokens)",
    )
    parser.add_argument(
        "--temperature",
        type=_temperature,
        default=TEMPERATURE,
        help=f"Sampling temperature, or 'none' to omit it (default: {TEMPERATURE})",
    )
    parser.add_argument("--n", type=_positive_int, default=N_CHOICES, help="Choices per request")
    parser.add_argument(
        "--timeout",
        type=_non_negative_float,
        default=TIMEOUT_SEC,
        help="Per-request timeout in seconds",
    )
    prompt = parser.add_mutually_exclusive_group()
    prompt.add_argument("--prompt", help="User prompt (default: a long essay request)")
    prompt.add_argument("--prompt-file", help="Read the user prompt from a file")
    parser.add_argument(
        "--show-body", action="store_true", help="Print the start of each completion"
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    missing = [
        name
        for name, value in (
            ("--endpoint/AOAI_ENDPOINT", args.endpoint),
            ("--deployment/AOAI_DEPLOYMENT", args.deployment),
        )
        if not value
    ]
    if missing:
        print(f"Missing required configuration: {', '.join(missing)}", file=sys.stderr)
        return 2
    if not args.endpoint.lower().startswith("https://"):
        print("The endpoint must start with https://", file=sys.stderr)
        return 2
    prompt = args.prompt or PROMPT
    if args.prompt_file:
        try:
            with open(args.prompt_file, encoding="utf-8") as fh:
                prompt = fh.read()
        except OSError as exc:
            print(f"Cannot read prompt file: {exc}", file=sys.stderr)
            return 2

    auth: Union[ApiKeyAuth, EntraAuth] = ApiKeyAuth(args.api_key) if args.api_key else EntraAuth()
    try:
        auth.headers()
    except Exception as exc:  # azure-identity raises ClientAuthenticationError subclasses
        print(f"Could not get a Microsoft Entra ID token: {exc}", file=sys.stderr)
        return 2

    url = build_url(args.endpoint, args.deployment, args.api_version)
    body = build_body(prompt, args.max_tokens, args.max_tokens_param, args.temperature, args.n)
    print(
        f"Starting Azure OpenAI TPM/RPM simulation: deployment={args.deployment} "
        f"calls={args.calls} interval={args.interval:g}s {args.max_tokens_param}={args.max_tokens} "
        f"auth={auth.description}"
    )

    results: List[CallResult] = []
    started = time.monotonic()
    finished = started
    with requests.Session() as session:
        for i in range(1, args.calls + 1):
            try:
                headers = dict(auth.headers(), **{"Content-Type": "application/json"})
            except Exception as exc:  # token refresh failed mid-run
                print(f"Stopping: could not refresh the access token: {exc}", file=sys.stderr)
                break
            result = one_call(session, i, url, headers, body, args.timeout)
            finished = time.monotonic()
            results.append(result)
            print_call(result, args.show_body)
            if i < args.calls:
                wait = args.interval
                if args.respect_retry_after and result.throttled and result.retry_after:
                    wait = max(wait, result.retry_after)
                if wait > 0:
                    time.sleep(wait)

    summary = summarize(results, finished - started)
    print_summary(summary)
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
