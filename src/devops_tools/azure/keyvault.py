"""``kv-expiry``: Key Vault secrets, certificates and keys that are expired or expire soon."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import click

from .client import AzureClient, AzureError
from .common import (
    AzureContext,
    Row,
    exit_on_findings,
    kql_in,
    output_option,
    parallel_map,
    pass_azure,
    progress,
    render,
    resolve_subscriptions,
    subscriptions_option,
    warn,
)

KEYVAULT_SCOPE = "https://vault.azure.net/.default"
KEYVAULT_API_VERSION = "7.5"
KEYVAULT_HOST_SUFFIX = ".vault.azure.net"
KINDS = ("secrets", "certificates", "keys")
_KIND_LABELS = {"secrets": "secret", "certificates": "certificate", "keys": "key"}
_VAULT_NAME_RE = re.compile(r"^[A-Za-z0-9-]{3,24}$")


@dataclass(frozen=True)
class Vault:
    name: str
    uri: str
    subscription_id: str = ""
    resource_group: str = ""


def vault_uri(value: str) -> Optional[str]:
    """Normalise a Key Vault URL; ``None`` unless it is an https ``*.vault.azure.net`` URL."""
    parts = urlsplit(value.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host.endswith(KEYVAULT_HOST_SUFFIX):
        return None
    return f"https://{host}/"


def resolve_vaults(
    client: AzureClient, values: Sequence[str], subscriptions: Sequence[str]
) -> List[Vault]:
    """Vaults to scan: explicit names/URLs, or every vault visible in Resource Graph."""
    vaults: List[Vault] = []
    names: List[str] = []
    for value in values:
        if value.lower().startswith(("https://", "http://")):
            uri = vault_uri(value)
            if uri is None:
                raise click.BadParameter(
                    f"'{value}' is not an https://<name>{KEYVAULT_HOST_SUFFIX} URL",
                    param_hint="'--vault'",
                )
            vaults.append(Vault(name=uri[len("https://") :].split(".")[0], uri=uri))
        elif _VAULT_NAME_RE.match(value):
            names.append(value)
        else:
            raise click.BadParameter(f"'{value}' is not a valid vault name", param_hint="'--vault'")
    if values and not names:
        return vaults

    query = "Resources\n| where type =~ 'microsoft.keyvault/vaults'"
    if names:
        query += f"\n| where {kql_in('name', names)}"
    query += (
        "\n| project id, name, subscriptionId, resourceGroup,"
        " vaultUri = tostring(properties.vaultUri)\n| order by name asc"
    )
    found = client.resource_graph(query, subscriptions=list(subscriptions) or None)
    seen = set()
    for row in found:
        name = str(row.get("name") or "")
        uri = vault_uri(str(row.get("vaultUri") or "")) or vault_uri(
            f"https://{name.lower()}{KEYVAULT_HOST_SUFFIX}/"
        )
        if not uri:
            continue
        seen.add(name.lower())
        vaults.append(
            Vault(
                name=name,
                uri=uri,
                subscription_id=str(row.get("subscriptionId") or ""),
                resource_group=str(row.get("resourceGroup") or ""),
            )
        )
    for name in names:
        if name.lower() not in seen:
            warn(
                f"vault '{name}' was not found in Resource Graph; "
                f"trying https://{name.lower()}{KEYVAULT_HOST_SUFFIX}/"
            )
            vaults.append(Vault(name=name, uri=f"https://{name.lower()}{KEYVAULT_HOST_SUFFIX}/"))
    unique: Dict[str, Vault] = {}
    for vault in vaults:
        unique.setdefault(vault.uri, vault)
    return list(unique.values())


def classify_item(
    vault: Vault,
    kind: str,
    item: Dict[str, Any],
    now: datetime,
    days: int,
    include_no_expiry: bool = False,
) -> Optional[Row]:
    """Return a report row for a list item, or ``None`` if it needs no attention."""
    if item.get("managed"):
        # Secrets and keys backing a certificate: the certificate itself is reported.
        return None
    attributes = item.get("attributes") or {}
    if attributes.get("enabled") is False:
        return None
    item_id = str(item.get("id") or item.get("kid") or "")
    expires: Optional[str] = None
    days_left: Optional[int] = None
    exp = attributes.get("exp")
    if exp is None:
        if not include_no_expiry:
            return None
        status = "no expiry"
    else:
        expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc)
        remaining = (expires_at - now).total_seconds() / 86400
        if remaining < 0:
            status = "EXPIRED"
        elif remaining <= days:
            status = "expiring"
        else:
            return None
        days_left = math.floor(remaining)
        expires = expires_at.strftime("%Y-%m-%d %H:%M")
    return {
        "vault": vault.name,
        "kind": _KIND_LABELS.get(kind, kind),
        "name": item_id.rstrip("/").split("/")[-1],
        "expires": expires,
        "daysLeft": days_left,
        "status": status,
        "subscriptionId": vault.subscription_id,
        "id": item_id,
    }


def scan_vault(
    client: AzureClient,
    vault: Vault,
    kinds: Sequence[str],
    now: datetime,
    days: int,
    include_no_expiry: bool = False,
) -> Tuple[List[Row], List[str]]:
    """List item metadata (never values) in one vault. Returns ``(rows, problems)``."""
    rows: List[Row] = []
    problems: List[str] = []
    for kind in kinds:
        try:
            items = list(
                client.paged(
                    f"{vault.uri}{kind}",
                    params={"api-version": KEYVAULT_API_VERSION, "maxresults": 25},
                    scope=KEYVAULT_SCOPE,
                )
            )
        except AzureError as exc:
            problems.append(f"{vault.name}: cannot list {kind}: {exc}")
            if exc.status is None:
                # Network-level failure (firewall, private endpoint, DNS): skip this vault.
                break
            continue
        for item in items:
            row = classify_item(vault, kind, item, now, days, include_no_expiry)
            if row is not None:
                rows.append(row)
    return rows, problems


def _sort_key(row: Row) -> Tuple[bool, int, str, str]:
    days_left = row.get("daysLeft")
    return (
        days_left is None,
        days_left if days_left is not None else 0,
        str(row.get("vault", "")).lower(),
        str(row.get("name", "")).lower(),
    )


def _row_style(row: Row) -> Optional[str]:
    return {"EXPIRED": "red", "expiring": "yellow"}.get(str(row.get("status")))


@click.command("kv-expiry")
@click.option(
    "--days",
    type=click.IntRange(min=0),
    default=30,
    show_default=True,
    help="Report items that expire within this many days.",
)
@click.option(
    "--vault",
    "vaults",
    multiple=True,
    metavar="NAME|URL",
    help="Vault to check (repeatable). Default: every vault visible in Resource Graph.",
)
@subscriptions_option
@click.option(
    "--kind",
    "kinds",
    multiple=True,
    type=click.Choice(KINDS),
    help="Object types to check (repeatable). Default: all.",
)
@click.option(
    "--include-no-expiry", is_flag=True, help="Also list enabled items without an expiry date."
)
@click.option(
    "--fail-on-findings",
    is_flag=True,
    help="Exit with status 1 when anything is reported or a vault could not be scanned.",
)
@output_option
@pass_azure
def kv_expiry(
    azure: AzureContext,
    days: int,
    vaults: Tuple[str, ...],
    subscriptions: Tuple[str, ...],
    kinds: Tuple[str, ...],
    include_no_expiry: bool,
    fail_on_findings: bool,
    output: str,
) -> None:
    """Find Key Vault secrets, certificates and keys that are expired or expire soon.

    Only metadata is read, never secret values. Requires the 'Key Vault Reader' role
    (or list permissions in the vault access policy) and network access to each vault.
    Disabled items and certificate-backed secrets/keys are skipped.
    """
    client = azure.client
    subs = resolve_subscriptions(client, subscriptions)
    with progress("Finding key vaults..."):
        targets = resolve_vaults(client, vaults, subs)
    selected = list(kinds) or list(KINDS)
    rows: List[Row] = []
    problems: List[str] = []
    if targets:
        client.token(KEYVAULT_SCOPE)  # sign in once before scanning vaults concurrently
        now = datetime.now(timezone.utc)
        with progress(f"Scanning {len(targets)} key vault(s)..."):
            results = parallel_map(
                lambda vault: scan_vault(client, vault, selected, now, days, include_no_expiry),
                targets,
            )
        for vault_rows, vault_problems in results:
            rows.extend(vault_rows)
            problems.extend(vault_problems)
    for problem in problems:
        warn(problem)
    rows.sort(key=_sort_key)
    expired = sum(1 for row in rows if row["status"] == "EXPIRED")
    expiring = sum(1 for row in rows if row["status"] == "expiring")
    render(
        rows,
        [
            ("vault", "Vault"),
            ("kind", "Kind"),
            ("name", "Name"),
            ("expires", "Expires (UTC)"),
            ("daysLeft", "Days left"),
            ("status", "Status"),
        ],
        output,
        caption=(
            f"{len(targets)} vault(s) scanned: {expired} expired, "
            f"{expiring} expiring within {days} days"
        ),
        empty_message=(
            "No key vaults found." if not targets else f"Nothing expires within {days} days."
        ),
        row_style=_row_style,
    )
    exit_on_findings(fail_on_findings, len(rows) + len(problems))
