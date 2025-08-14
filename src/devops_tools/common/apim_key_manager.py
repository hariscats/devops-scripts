#!/usr/bin/env python3
"""
Azure API Management (APIM) subscription key rotation script.

Rotates primary and secondary keys for two APIM subscription entities (SIDs).
Shows only short key prefixes, never full keys. Writes a JSON summary.

Environment:
  AZURE_SUBSCRIPTION_ID   (required unless placeholder replaced)
  RESOURCE_GROUP          (required)
  APIM_SERVICE_NAME       (required)
  SUBSCRIPTION_SID_1      (default: sub1)
  SUBSCRIPTION_SID_2      (default: sub2)

Authentication:
  Uses DefaultAzureCredential (supports az login, Managed Identity, Service Principal).

Usage:
  az login
  export AZURE_SUBSCRIPTION_ID=...
  export RESOURCE_GROUP=...
  export APIM_SERVICE_NAME=...
  python apim_key_manager.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence

import requests
from azure.identity import DefaultAzureCredential

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_VERSION = "2024-05-01"
ARM_SCOPE = "https://management.azure.com/.default"
BASE_URL = "https://management.azure.com"
SUCCESS_CODES: tuple[int, ...] = (200, 201, 202, 204)
DEFAULT_TIMEOUT = 30
RETRY_STATUS_CODES: tuple[int, ...] = (429,)
RETRY_ATTEMPTS = 3
SUMMARY_FILE = "apim_key_rotation_summary.json"
KEY_PREFIX_LEN = 8

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("apim.key_rotation")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.INFO)

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


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class APIMClient:
    """Minimal APIM REST client for subscription key operations."""

    def __init__(
        self,
        path: APIMPath,
        credential: Optional[DefaultAzureCredential] = None,
        session: Optional[requests.Session] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._path = path
        self._credential = credential or DefaultAzureCredential()
        self._session = session or requests.Session()
        self._timeout = timeout

    # Public operations -----------------------------------------------------

    def regenerate_primary(self, sid: str) -> ApiResponse:
        return self._execute(
            "POST",
            f"{self._base()}/subscriptions/{sid}/regeneratePrimaryKey?api-version={API_VERSION}",
        )

    def regenerate_secondary(self, sid: str) -> ApiResponse:
        return self._execute(
            "POST",
            f"{self._base()}/subscriptions/{sid}/regenerateSecondaryKey?api-version={API_VERSION}",
        )

    def list_secrets(self, sid: str) -> ApiResponse:
        return self._execute(
            "POST",
            f"{self._base()}/subscriptions/{sid}/listSecrets?api-version={API_VERSION}",
        )

    # Internal helpers -----------------------------------------------------

    def _token(self) -> str:
        return self._credential.get_token(ARM_SCOPE).token  # type: ignore[return-value]

    def _base(self) -> str:
        p = self._path
        return (
            f"{BASE_URL}/subscriptions/{p.subscription_id}"
            f"/resourceGroups/{p.resource_group}"
            f"/providers/Microsoft.ApiManagement/service/{p.service_name}"
        )

    def _execute(self, method: str, url: str) -> ApiResponse:
        headers = {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": "application/json",
            "User-Agent": "devops-scripts/apim-key-rotation",
        }
        last_resp: Optional[requests.Response] = None
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                resp = self._session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self._timeout,
                )
                if resp.status_code not in RETRY_STATUS_CODES:
                    return self._parse(resp)
                retry_after = int(resp.headers.get("Retry-After", "2"))
                sleep_for = min(30, retry_after * attempt)
                logger.warning(
                    "Transient status %s on attempt %d (sleep %ss)",
                    resp.status_code,
                    attempt,
                    sleep_for,
                )
                last_resp = resp
                time.sleep(sleep_for)
            except requests.RequestException as exc:
                logger.warning("Request error on attempt %d: %s", attempt, exc)
                last_resp = None
                time.sleep(min(30, attempt * 2))
        if last_resp is None:
            raise APIMClientError("Failed to obtain a response after retries")
        return self._parse(last_resp)

    @staticmethod
    def _parse(resp: requests.Response) -> ApiResponse:
        try:
            data = resp.json() if resp.text else {}
        except ValueError:
            data = {"raw": resp.text}
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


def rotate_for_sid(client: APIMClient, sid: str, order: list[str]) -> OperationResult:
    """
    Rotate keys for a SID following the specified order.

    order: list like ["primary","secondary"] or ["secondary","primary"]
    """
    logger.info("SID=%s: starting rotation order=%s", sid, "->".join(order))

    r_primary: Optional[ApiResponse] = None
    r_secondary: Optional[ApiResponse] = None

    # Pre-snapshot (only logged at debug level)
    pre = client.list_secrets(sid)
    if pre.ok:
        logger.debug(
            "SID=%s: pre primary=%s secondary=%s",
            sid,
            key_preview(pre.data.get("primaryKey")),
            key_preview(pre.data.get("secondaryKey")),
        )

    for which in order:
        if which == "primary":
            r_primary = client.regenerate_primary(sid)
            logger.info(
                "SID=%s: regenerate primary -> %s",
                sid,
                f"{r_primary.status}{' OK' if r_primary.ok else ' FAIL'}",
            )
        else:
            r_secondary = client.regenerate_secondary(sid)
            logger.info(
                "SID=%s: regenerate secondary -> %s",
                sid,
                f"{r_secondary.status}{' OK' if r_secondary.ok else ' FAIL'}",
            )

        snap = client.list_secrets(sid)
        if snap.ok:
            logger.debug(
                "SID=%s: snapshot after %s primary=%s secondary=%s",
                sid,
                which,
                key_preview(snap.data.get("primaryKey")),
                key_preview(snap.data.get("secondaryKey")),
            )
        else:
            logger.warning(
                "SID=%s: listSecrets failed after %s (HTTP %s)",
                sid,
                which,
                snap.status,
            )

    return OperationResult(
        sid=sid,
        regenerate_primary_status=r_primary.status if r_primary else None,
        regenerate_secondary_status=r_secondary.status if r_secondary else None,
    )


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="APIM subscription key rotation")
    parser.add_argument(
        "--rotate-order",
        choices=["primary-first", "secondary-first"],
        help="Override rotation order (default: primary-first or env APIM_ROTATE_ORDER)",
    )
    return parser.parse_args(argv)


def resolve_order(arg_value: Optional[str]) -> list[str]:
    # Priority: CLI flag > env var > default
    val = arg_value or os.getenv("APIM_ROTATE_ORDER", "primary-first").lower()
    if val == "secondary-first":
        return ["secondary", "primary"]
    # Fallback default
    return ["primary", "secondary"]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_env() -> tuple[str, str, str, List[str]]:
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
    missing = [name for name, val in placeholders if val.startswith("<")]
    if missing:
        logger.error("Missing required configuration: %s", ", ".join(missing))
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    user_level = os.getenv("LOG_LEVEL")
    if user_level:
        logger.setLevel(user_level.upper())

    args = parse_args(argv)

    sub_id, rg, svc, sids = load_env()
    if not validate_required(sub_id, rg, svc):
        return 2

    order = resolve_order(args.rotate_order)
    logger.info(
        "APIM context subscription=%s resourceGroup=%s service=%s rotateOrder=%s",
        sub_id,
        rg,
        svc,
        "->".join(order),
    )
    logger.info("Target SIDs: %s", ", ".join(sids))

    client = APIMClient(APIMPath(sub_id, rg, svc))

    results: List[OperationResult] = []
    for sid in sids:
        try:
            results.append(rotate_for_sid(client, sid, order))
        except APIMClientError as exc:
            logger.error("SID=%s: rotation aborted: %s", sid, exc)

    summary_serializable = [asdict(r) for r in results]
    with open(SUMMARY_FILE, "w", encoding="utf-8") as fh:
        json.dump(summary_serializable, fh, indent=2)

    print(f"Summary saved to {SUMMARY_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
