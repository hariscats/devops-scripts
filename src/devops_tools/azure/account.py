"""``whoami``: which identity am I using, and which subscriptions can it see?"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .client import token_claims
from .common import AzureContext, Row, default_subscription, output_option, pass_azure, render


def identity_from_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Summarise the (unverified) claims of an ARM access token for display."""
    if claims.get("xms_mirid"):
        kind = "managed identity"
    elif claims.get("idtyp") == "app" or "scp" not in claims:
        kind = "service principal"
    else:
        kind = "user"
    expires: Optional[str] = None
    if isinstance(claims.get("exp"), (int, float)):
        expires = datetime.fromtimestamp(claims["exp"], tz=timezone.utc).isoformat()
    return {
        "type": kind,
        "name": claims.get("name"),
        "signInName": claims.get("upn")
        or claims.get("preferred_username")
        or claims.get("unique_name"),
        "objectId": claims.get("oid"),
        "tenantId": claims.get("tid"),
        "appId": claims.get("appid") or claims.get("azp"),
        "managedIdentityResourceId": claims.get("xms_mirid"),
        "tokenExpires": expires,
    }


def subscription_rows(subscriptions: List[Dict[str, Any]], default: Optional[str]) -> List[Row]:
    rows = [
        {
            "default": sub.get("subscriptionId", "").lower() == (default or ""),
            "name": sub.get("displayName"),
            "subscriptionId": sub.get("subscriptionId"),
            "state": sub.get("state"),
            "tenantId": sub.get("tenantId"),
        }
        for sub in subscriptions
    ]
    return sorted(rows, key=lambda row: str(row["name"] or "").lower())


@click.command("whoami")
@output_option
@pass_azure
def whoami(azure: AzureContext, output: str) -> None:
    """Show the signed-in identity and the subscriptions it can access.

    Handy for checking which credential DefaultAzureCredential picked up (Azure
    CLI user, service principal, managed identity...) before running anything else.
    """
    client = azure.client
    identity = identity_from_claims(token_claims(client.token()))
    subscriptions = client.list_subscriptions()
    try:
        default: Optional[str] = default_subscription(client)
    except click.ClickException:
        default = None
    rows = subscription_rows(subscriptions, default)

    if output == "json":
        payload = {"identity": identity, "defaultSubscription": default, "subscriptions": rows}
        click.echo(json.dumps(payload, indent=2))
        return
    if output == "csv":
        render(rows, [(key, key) for key in ("default", "name", "subscriptionId", "state")], output)
        return

    details = Table(show_header=False, box=None)
    details.add_column(style="bold")
    details.add_column()
    for key, label in (
        ("type", "Identity type"),
        ("name", "Name"),
        ("signInName", "Sign-in name"),
        ("appId", "Application ID"),
        ("managedIdentityResourceId", "Managed identity"),
        ("objectId", "Object ID"),
        ("tenantId", "Tenant ID"),
        ("tokenExpires", "Token expires"),
    ):
        if identity.get(key):
            details.add_row(Text(label), Text(str(identity[key])))
    Console().print(details)
    render(
        [dict(row, default="*" if row["default"] else "") for row in rows],
        [("default", "Default"), ("name", "Name"), ("subscriptionId", "ID"), ("state", "State")],
        output,
        title="Subscriptions",
        empty_message="This identity cannot see any subscriptions.",
        row_style=lambda row: "bold green" if row["default"] else None,
    )
