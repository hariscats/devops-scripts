"""``vm-capacity``: can these VM sizes be deployed here? (SKU restrictions, zones, quota)."""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import click

from .common import (
    AzureContext,
    Row,
    exit_on_findings,
    normalize_location,
    output_option,
    pass_azure,
    pick_subscription,
    progress,
    render,
    subscription_option,
)

SKUS_API_VERSION = "2021-07-01"
USAGES_API_VERSION = "2024-07-01"
_LOCATION_RE = re.compile(r"^[a-z0-9]+$")


def _capability(sku: Dict[str, Any], name: str) -> Optional[str]:
    for capability in sku.get("capabilities") or []:
        if str(capability.get("name", "")).lower() == name.lower():
            value = capability.get("value")
            return None if value is None else str(value)
    return None


def _number(value: Optional[str]) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def sku_availability(sku: Dict[str, Any], location: str) -> Tuple[Optional[str], List[str]]:
    """Return ``(restriction_reason, available_zones)`` for *sku* in *location*.

    ``restriction_reason`` is ``None`` when the size can be deployed in the region.
    """
    location = location.lower()
    zones: Set[str] = set()
    for info in sku.get("locationInfo") or []:
        if str(info.get("location", "")).lower() == location:
            zones.update(str(zone) for zone in info.get("zones") or [])
    restricted_zones: Set[str] = set()
    for restriction in sku.get("restrictions") or []:
        info = restriction.get("restrictionInfo") or {}
        locations = info.get("locations") or restriction.get("values") or []
        if location not in {str(loc).lower() for loc in locations}:
            continue
        if restriction.get("type") == "Location":
            return str(restriction.get("reasonCode") or "Restricted"), []
        if restriction.get("type") == "Zone":
            restricted_zones.update(str(zone) for zone in info.get("zones") or [])
    return None, sorted(zones - restricted_zones)


def _usage_map(usages: Iterable[Dict[str, Any]]) -> Dict[str, Tuple[int, int]]:
    result: Dict[str, Tuple[int, int]] = {}
    for usage in usages:
        name = str((usage.get("name") or {}).get("value") or "").lower()
        if name:
            result[name] = (int(usage.get("currentValue") or 0), int(usage.get("limit") or 0))
    return result


def _fmt_usage(value: Optional[Tuple[int, int]]) -> str:
    return f"{value[0]}/{value[1]}" if value else "unknown"


def capacity_rows(
    skus: Iterable[Dict[str, Any]],
    usages: Iterable[Dict[str, Any]],
    location: str,
    patterns: Sequence[str],
    count: int = 1,
) -> List[Row]:
    """Evaluate each size matching *patterns* in one region."""
    vm_skus = [sku for sku in skus if sku.get("resourceType") == "virtualMachines"]
    usage = _usage_map(usages)
    regional = usage.get("cores")
    rows: List[Row] = []
    reported: Set[str] = set()
    for pattern in patterns:
        matched = [
            sku
            for sku in vm_skus
            if fnmatch.fnmatchcase(str(sku.get("name", "")).lower(), pattern.lower())
        ]
        if not matched:
            rows.append(
                {
                    "location": location,
                    "size": pattern,
                    "status": "not offered in this region",
                    "deployable": False,
                }
            )
            continue
        for sku in sorted(matched, key=lambda s: str(s.get("name", "")).lower()):
            name = str(sku.get("name", ""))
            if name.lower() in reported:
                continue
            reported.add(name.lower())
            rows.append(_evaluate(sku, location, usage, regional, count))
    return rows


def _evaluate(
    sku: Dict[str, Any],
    location: str,
    usage: Dict[str, Tuple[int, int]],
    regional: Optional[Tuple[int, int]],
    count: int,
) -> Row:
    family = str(sku.get("family") or "")
    vcpus_value = _number(_capability(sku, "vCPUs"))
    vcpus = int(vcpus_value) if vcpus_value is not None else None
    family_usage = usage.get(family.lower())
    reason, zones = sku_availability(sku, location)
    needed = vcpus * count if vcpus is not None else None

    if reason:
        status, deployable = f"restricted ({reason})", False
    elif needed is None or family_usage is None or regional is None:
        status, deployable = "available (quota not checked)", True
    elif needed > family_usage[1] - family_usage[0]:
        free = max(0, family_usage[1] - family_usage[0])
        status, deployable = f"quota: needs {needed} vCPUs, {free} free in family", False
    elif needed > regional[1] - regional[0]:
        free = max(0, regional[1] - regional[0])
        status, deployable = f"quota: needs {needed} vCPUs, {free} free in region", False
    else:
        status, deployable = "available", True
    return {
        "location": location,
        "size": sku.get("name"),
        "family": family,
        "vCPUs": vcpus,
        "memoryGiB": _number(_capability(sku, "MemoryGB")),
        "zones": zones,
        "vCPUsNeeded": needed,
        "familyQuota": _fmt_usage(family_usage),
        "regionalQuota": _fmt_usage(regional),
        "status": status,
        "deployable": deployable,
    }


@click.command("vm-capacity")
@click.option(
    "-l",
    "--location",
    "locations",
    multiple=True,
    required=True,
    help="Region such as eastus or 'West Europe' (repeatable).",
)
@click.option(
    "--size",
    "sizes",
    multiple=True,
    required=True,
    metavar="SIZE",
    help="VM size or glob pattern such as 'Standard_D*s_v5' (repeatable, case-insensitive).",
)
@click.option(
    "--count",
    type=click.IntRange(min=1),
    default=1,
    show_default=True,
    help="Number of VMs you plan to deploy (for the vCPU quota check).",
)
@subscription_option
@click.option(
    "--fail-if-unavailable",
    is_flag=True,
    help="Exit with status 1 if any requested size cannot be deployed.",
)
@output_option
@pass_azure
def vm_capacity(
    azure: AzureContext,
    locations: Tuple[str, ...],
    sizes: Tuple[str, ...],
    count: int,
    subscription: Optional[str],
    fail_if_unavailable: bool,
    output: str,
) -> None:
    """Check VM size availability, zones and vCPU quota before deploying.

    Combines the Resource SKUs API (region and zone restrictions for your
    subscription) with Compute usage (family and total regional vCPU quota).

    \b
    Example:
      azure-tools vm-capacity -l eastus -l westeurope --size Standard_D4s_v5 --count 10
    """
    regions = []
    for value in locations:
        region = normalize_location(value)
        if not _LOCATION_RE.match(region):
            raise click.BadParameter(f"'{value}' is not a valid region", param_hint="'--location'")
        if region not in regions:
            regions.append(region)
    client = azure.client
    subscription_id = pick_subscription(client, subscription)
    base = f"/subscriptions/{subscription_id}/providers/Microsoft.Compute"
    rows: List[Row] = []
    for region in regions:
        with progress(f"Checking {region}..."):
            skus = client.paged(
                f"{base}/skus",
                params={"api-version": SKUS_API_VERSION, "$filter": f"location eq '{region}'"},
            )
            usages = client.paged(
                f"{base}/locations/{region}/usages", params={"api-version": USAGES_API_VERSION}
            )
            rows.extend(capacity_rows(list(skus), list(usages), region, sizes, count))
    render(
        rows,
        [
            ("location", "Location"),
            ("size", "Size"),
            ("vCPUs", "vCPUs"),
            ("memoryGiB", "Memory (GiB)"),
            ("zones", "Zones"),
            ("familyQuota", "Family vCPUs used/limit"),
            ("regionalQuota", "Regional vCPUs used/limit"),
            ("status", "Status"),
        ],
        output,
        caption=f"Subscription {subscription_id}, {count} VM(s) per size",
        row_style=lambda row: None if row.get("deployable") else "red",
    )
    exit_on_findings(fail_if_unavailable, sum(1 for row in rows if not row.get("deployable")))
