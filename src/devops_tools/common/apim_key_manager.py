#!/usr/bin/env python3
"""
Minimal Azure API Management (APIM) subscription key rotation script.

- Auth: DefaultAzureCredential (works with `az login`, Managed Identity, or SP env vars)
- Endpoints used: regeneratePrimaryKey, regenerateSecondaryKey, listSecrets
- Demo: rotates keys for two APIM subscriptions: sub1 and sub2

Usage:
  1) Ensure authentication is available (e.g., `az login` or SP env vars)
  2) Set environment variables (or edit defaults below):
     AZURE_SUBSCRIPTION_ID, RESOURCE_GROUP, APIM_SERVICE_NAME,
     SUBSCRIPTION_SID_1, SUBSCRIPTION_SID_2 (optional)
  3) Run: python apim_key_manager.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, Optional, cast

import requests
from azure.identity import DefaultAzureCredential

API_VERSION = "2024-05-01"
BASE_URL = "https://management.azure.com"


@dataclass
class APIMPath:
    subscription_id: str
    resource_group: str
    service_name: str


class APIMClient:
    """Very small APIM REST client for key operations."""

    def __init__(self, path: APIMPath, credential: Optional[DefaultAzureCredential] = None):
        """Initialize client with APIM path context and optional credential."""
        self.path = path
        self.credential = credential or DefaultAzureCredential()

    def _token(self) -> str:
        """Acquire a bearer token for Azure Resource Manager scope."""
        return cast(str, self.credential.get_token("https://management.azure.com/.default").token)

    def _request(
        self, method: str, url: str, json_body: Optional[Dict] = None
    ) -> requests.Response:
        headers = {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}
        # Minimal retry for 429 (rate limiting)
        last = None
        for attempt in range(3):
            resp = requests.request(method, url, headers=headers, json=json_body, timeout=30)
            if resp.status_code != 429:
                return resp
            retry_after = int(resp.headers.get("Retry-After", "2"))
            time.sleep(min(30, retry_after * (attempt + 1)))
            last = resp
        return last or resp

    def _base(self) -> str:
        return (
            f"{BASE_URL}/subscriptions/{self.path.subscription_id}"
            f"/resourceGroups/{self.path.resource_group}"
            f"/providers/Microsoft.ApiManagement/service/{self.path.service_name}"
        )

    def regenerate_primary(self, sid: str) -> Dict:
        url = f"{self._base()}/subscriptions/{sid}/regeneratePrimaryKey?api-version={API_VERSION}"
        return self._parse(self._request("POST", url))

    def regenerate_secondary(self, sid: str) -> Dict:
        url = f"{self._base()}/subscriptions/{sid}/regenerateSecondaryKey?api-version={API_VERSION}"
        return self._parse(self._request("POST", url))

    def list_secrets(self, sid: str) -> Dict:
        url = f"{self._base()}/subscriptions/{sid}/listSecrets?api-version={API_VERSION}"
        return self._parse(self._request("POST", url))

    @staticmethod
    def _parse(resp: requests.Response) -> Dict:
        try:
            data = resp.json() if resp.text else {}
        except ValueError:
            data = {"raw": resp.text}
        return {
            "ok": resp.status_code in (200, 201, 202, 204),
            "status": resp.status_code,
            "data": data,
            "error": None if 200 <= resp.status_code < 300 else (data or resp.text),
        }


def main() -> int:
    # Basic configuration (env vars or edit defaults)
    sub_id = os.getenv("AZURE_SUBSCRIPTION_ID", "<your-azure-subscription-id>")
    rg = os.getenv("RESOURCE_GROUP", "<your-resource-group>")
    svc = os.getenv("APIM_SERVICE_NAME", "<your-apim-service>")

    # Demo subscriptions (APIM subscription entity IDs)
    target_sids = [
        os.getenv("SUBSCRIPTION_SID_1", "sub1"),
        os.getenv("SUBSCRIPTION_SID_2", "sub2"),
    ]

    client = APIMClient(APIMPath(sub_id, rg, svc))

    summary = []
    for sid in target_sids:
        print(f"\n== Rotating keys for APIM subscription '{sid}' ==")

        # Regenerate primary
        r_primary = client.regenerate_primary(sid)
        print(
            f"Regenerate primary: HTTP {r_primary['status']} -> {'OK' if r_primary['ok'] else 'FAIL'}"
        )

        # Show keys (if caller has permission)
        secrets = client.list_secrets(sid)
        if secrets["ok"]:
            pk = secrets["data"].get("primaryKey")
            sk = secrets["data"].get("secondaryKey")
            print(f"Primary (first 8): {pk[:8] + '...' if pk else 'N/A'}")
            print(f"Secondary (first 8): {sk[:8] + '...' if sk else 'N/A'}")
        else:
            print(
                f"Could not retrieve keys (HTTP {secrets['status']}). Ensure correct permissions."
            )

        # Regenerate secondary (optional but shown for completeness)
        r_secondary = client.regenerate_secondary(sid)
        print(
            f"Regenerate secondary: HTTP {r_secondary['status']} -> {'OK' if r_secondary['ok'] else 'FAIL'}"
        )

        # Verify again
        secrets_after = client.list_secrets(sid)
        if secrets_after["ok"]:
            pk2 = secrets_after["data"].get("primaryKey")
            sk2 = secrets_after["data"].get("secondaryKey")
            print(f"After rotation - Primary (first 8): {pk2[:8] + '...' if pk2 else 'N/A'}")
            print(f"After rotation - Secondary (first 8): {sk2[:8] + '...' if sk2 else 'N/A'}")

        summary.append(
            {
                "sid": sid,
                "regeneratePrimary": r_primary["status"],
                "regenerateSecondary": r_secondary["status"],
            }
        )

    out = "apim_key_rotation_summary.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to {out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
