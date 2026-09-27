"""Resource Graph based commands: ``graph``, ``inventory``, ``tag-audit`` and ``orphans``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, TextIO, Tuple

import click

from .common import (
    AzureContext,
    Row,
    discover_columns,
    exit_on_findings,
    fail_on_findings_option,
    kql_in,
    kql_string,
    output_option,
    pass_azure,
    progress,
    render,
    resolve_subscriptions,
    resource_groups_option,
    subscriptions_option,
)

RESOURCE_GROUP_TYPE = "microsoft.resources/subscriptions/resourcegroups"


def _where(filters: Sequence[str]) -> str:
    return "".join(f"\n| where {f}" for f in filters)


# graph ---------------------------------------------------------------------


@click.command("graph")
@click.argument("query", required=False)
@click.option(
    "-f",
    "--file",
    "query_file",
    type=click.File("r"),
    help="Read the query from a file ('-' for stdin).",
)
@subscriptions_option
@click.option(
    "-m",
    "--management-group",
    "management_groups",
    multiple=True,
    metavar="ID",
    help="Management group ID to query instead of subscriptions (repeatable).",
)
@click.option("--first", type=click.IntRange(min=1), help="Return at most N rows.")
@output_option
@pass_azure
def graph(
    azure: AzureContext,
    query: Optional[str],
    query_file: Optional[TextIO],
    subscriptions: Tuple[str, ...],
    management_groups: Tuple[str, ...],
    first: Optional[int],
    output: str,
) -> None:
    """Run an Azure Resource Graph (KQL) query across subscriptions.

    Results are paged automatically. Tip: 'project' only the columns you need,
    or use '-o json' for wide results.

    \b
    Examples:
      azure-tools graph "Resources | summarize count() by type | order by count_ desc"
      azure-tools graph -f stale-disks.kql -s Production -o csv > disks.csv
    """
    if query and query_file:
        raise click.UsageError("Pass either QUERY or --file, not both.")
    if query_file is not None:
        query = query_file.read()
    if not query or not query.strip():
        raise click.UsageError("Missing QUERY (or --file).")
    if subscriptions and management_groups:
        raise click.UsageError("Use either --subscription or --management-group, not both.")
    subs = resolve_subscriptions(azure.client, subscriptions)
    with progress("Querying Azure Resource Graph..."):
        rows = azure.client.resource_graph(
            query,
            subscriptions=subs or None,
            management_groups=list(management_groups) or None,
            max_rows=first,
        )
    render(rows, [(key, key) for key in discover_columns(rows)], output)


# inventory -----------------------------------------------------------------

_INVENTORY_GROUPS: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {
    "type": (
        "summarize resourceCount = count() by type",
        [("type", "Type"), ("resourceCount", "Resources")],
    ),
    "location": (
        "summarize resourceCount = count() by location",
        [("location", "Location"), ("resourceCount", "Resources")],
    ),
    "resource-group": (
        "summarize resourceCount = count() by subscriptionId, resourceGroup",
        [
            ("resourceGroup", "Resource group"),
            ("subscriptionId", "Subscription"),
            ("resourceCount", "Resources"),
        ],
    ),
    "subscription": (
        "summarize resourceCount = count() by subscriptionId"
        "\n| join kind=leftouter (ResourceContainers"
        " | where type =~ 'microsoft.resources/subscriptions'"
        " | project subscriptionId, subscriptionName = name) on subscriptionId"
        "\n| project subscriptionName, subscriptionId, resourceCount",
        [
            ("subscriptionName", "Subscription"),
            ("subscriptionId", "Subscription ID"),
            ("resourceCount", "Resources"),
        ],
    ),
}


def inventory_query(
    group_by: str, resource_groups: Sequence[str] = (), types: Sequence[str] = ()
) -> str:
    filters = []
    if resource_groups:
        filters.append(kql_in("resourceGroup", resource_groups))
    if types:
        filters.append(kql_in("type", types))
    summarize, _ = _INVENTORY_GROUPS[group_by]
    return f"Resources{_where(filters)}\n| {summarize}\n| order by resourceCount desc"


@click.command("inventory")
@click.option(
    "--by",
    "group_by",
    type=click.Choice(list(_INVENTORY_GROUPS)),
    default="type",
    show_default=True,
    help="How to group resources.",
)
@subscriptions_option
@resource_groups_option
@click.option(
    "-t",
    "--type",
    "types",
    multiple=True,
    metavar="TYPE",
    help="Resource type filter, e.g. microsoft.compute/virtualmachines (repeatable).",
)
@click.option("--top", type=click.IntRange(min=1), help="Show only the N largest groups.")
@output_option
@pass_azure
def inventory(
    azure: AzureContext,
    group_by: str,
    subscriptions: Tuple[str, ...],
    resource_groups: Tuple[str, ...],
    types: Tuple[str, ...],
    top: Optional[int],
    output: str,
) -> None:
    """Count resources by type, location, resource group or subscription."""
    subs = resolve_subscriptions(azure.client, subscriptions)
    with progress("Counting resources..."):
        rows = azure.client.resource_graph(
            inventory_query(group_by, resource_groups, types),
            subscriptions=subs or None,
            max_rows=top,
        )
    total = sum(int(row.get("resourceCount") or 0) for row in rows)
    _, columns = _INVENTORY_GROUPS[group_by]
    caption = f"{total:,} resources in {len(rows):,} groups"
    render(rows, columns, output, caption=caption)


# tag-audit -----------------------------------------------------------------


def missing_tags(tags: Optional[Mapping[str, Any]], required: Sequence[str]) -> List[str]:
    """Required tag names that are absent or empty (tag names are case-insensitive)."""
    present = {str(key).lower(): value for key, value in (tags or {}).items()}
    return [name for name in required if not str(present.get(name.lower()) or "").strip()]


def _tag_may_be_missing(name: str) -> str:
    key = f'"{name}":'
    empty_value = key + '""'
    return (
        f"tostring(tags) !contains {kql_string(key)}"
        f" or tostring(tags) contains {kql_string(empty_value)}"
    )


def tag_audit_query(
    required: Sequence[str],
    resource_groups: Sequence[str] = (),
    types: Sequence[str] = (),
    include_resource_groups: bool = True,
) -> str:
    """Resource Graph query returning resources that *may* lack a required tag.

    ``contains`` is case-insensitive, so this is a cheap server-side pre-filter; the
    exact (case-insensitive, empty-value aware) check happens client-side.
    """
    rg_filter = [kql_in("resourceGroup", resource_groups)] if resource_groups else []
    type_filter = [kql_in("type", types)] if types else []
    query = "Resources" + _where(rg_filter + type_filter)
    if include_resource_groups and not types:
        query += (
            f"\n| union (ResourceContainers | where type =~ '{RESOURCE_GROUP_TYPE}'"
            f"{_where(rg_filter)})"
        )
    maybe_missing = " or ".join(_tag_may_be_missing(name) for name in required)
    return (
        f"{query}\n| where {maybe_missing}"
        "\n| project id, name, type, resourceGroup, subscriptionId, location, tags"
        "\n| order by subscriptionId asc, resourceGroup asc, name asc"
    )


@click.command("tag-audit")
@click.option(
    "-t",
    "--tag",
    "tags",
    multiple=True,
    required=True,
    metavar="NAME",
    help="Required tag name (repeatable; case-insensitive).",
)
@subscriptions_option
@resource_groups_option
@click.option(
    "--type",
    "types",
    multiple=True,
    metavar="TYPE",
    help="Only audit these resource types (repeatable). Resource groups are then skipped.",
)
@click.option(
    "--include-resource-groups/--exclude-resource-groups",
    default=True,
    show_default=True,
    help="Also audit the tags on resource groups.",
)
@fail_on_findings_option
@output_option
@pass_azure
def tag_audit(
    azure: AzureContext,
    tags: Tuple[str, ...],
    subscriptions: Tuple[str, ...],
    resource_groups: Tuple[str, ...],
    types: Tuple[str, ...],
    include_resource_groups: bool,
    fail_on_findings: bool,
    output: str,
) -> None:
    """Find resources and resource groups missing required tags (or with empty values).

    \b
    Example:
      azure-tools tag-audit -t owner -t costCenter -s Production --fail-on-findings
    """
    required = [t.strip() for t in tags if t.strip()]
    if not required:
        raise click.BadParameter("tag names must not be empty", param_hint="'--tag'")
    subs = resolve_subscriptions(azure.client, subscriptions)
    with progress("Auditing tags..."):
        candidates = azure.client.resource_graph(
            tag_audit_query(required, resource_groups, types, include_resource_groups),
            subscriptions=subs or None,
        )
    rows: List[Row] = []
    for item in candidates:
        missing = missing_tags(item.get("tags"), required)
        if missing:
            rows.append({**item, "missingTags": missing})
    counts = ", ".join(
        f"{name}: {sum(1 for r in rows if name in r['missingTags'])}" for name in required
    )
    render(
        rows,
        [
            ("name", "Name"),
            ("type", "Type"),
            ("resourceGroup", "Resource group"),
            ("subscriptionId", "Subscription"),
            ("missingTags", "Missing tags"),
        ],
        output,
        caption=f"{len(rows):,} non-compliant ({counts})",
        empty_message="All audited resources have the required tags.",
    )
    exit_on_findings(fail_on_findings, len(rows))


# orphans -------------------------------------------------------------------

_PROJECT = "\n| project id, name, type, resourceGroup, subscriptionId, location, details"


def _empty(expr: str) -> str:
    return f"(isnull({expr}) or array_length({expr}) == 0)"


@dataclass(frozen=True)
class OrphanCheck:
    key: str
    title: str
    why: str
    query: str


ORPHAN_CHECKS: Tuple[OrphanCheck, ...] = (
    OrphanCheck(
        "disks",
        "Unattached managed disks",
        "Billed for provisioned size; nothing uses them.",
        "Resources"
        "\n| where type =~ 'microsoft.compute/disks'"
        "\n| where tostring(properties.diskState) =~ 'Unattached'"
        "\n| where not(name endswith '-ASRReplica' or name startswith 'ms-asr-'"
        " or name startswith 'asrseeddisk-')"
        "\n| where tostring(tags) !contains 'kubernetes.io-created-for-pvc'"
        " and tostring(tags) !contains 'ASR-ReplicaDisk'"
        " and tostring(tags) !contains 'asrseeddisk'"
        " and tostring(tags) !contains 'RSVaultBackup'"
        "\n| extend details = strcat(tostring(sku.name), ', ',"
        " tostring(properties.diskSizeGB), ' GiB')" + _PROJECT,
    ),
    OrphanCheck(
        "public-ips",
        "Unassociated public IP addresses",
        "Standard public IPs are billed even when not attached.",
        "Resources"
        "\n| where type =~ 'microsoft.network/publicipaddresses'"
        "\n| where isnull(properties.ipConfiguration) and isnull(properties.natGateway)"
        " and isnull(properties.publicIPPrefix)"
        "\n| extend details = strcat(tostring(sku.name), ', ',"
        " tostring(properties.publicIPAllocationMethod), ' ', tostring(properties.ipAddress))"
        + _PROJECT,
    ),
    OrphanCheck(
        "stopped-vms",
        "VMs stopped but not deallocated",
        "Compute is still billed until the VM is deallocated.",
        "Resources"
        "\n| where type =~ 'microsoft.compute/virtualmachines'"
        "\n| where tostring(properties.extended.instanceView.powerState.code)"
        " =~ 'PowerState/stopped'"
        "\n| extend details = strcat(tostring(properties.hardwareProfile.vmSize),"
        " ', stopped (not deallocated)')" + _PROJECT,
    ),
    OrphanCheck(
        "app-service-plans",
        "App Service plans without apps",
        "Paid plans are billed per instance even when empty.",
        "Resources"
        "\n| where type =~ 'microsoft.web/serverfarms'"
        "\n| where toint(properties.numberOfSites) == 0"
        "\n| where tostring(sku.tier) !in~ ('Free', 'Dynamic')"
        "\n| extend details = strcat(tostring(sku.tier), ' ', tostring(sku.name))" + _PROJECT,
    ),
    OrphanCheck(
        "vnet-gateways",
        "Virtual network gateways without connections",
        "VPN / ExpressRoute gateways are billed hourly.",
        "Resources"
        "\n| where type =~ 'microsoft.network/virtualnetworkgateways'"
        "\n| where isnull(properties.vpnClientConfiguration)"
        "\n| extend gatewayId = tolower(id)"
        "\n| join kind=leftouter (Resources"
        " | where type =~ 'microsoft.network/connections'"
        " | extend gatewayId = tolower(tostring(properties.virtualNetworkGateway1.id))"
        " | summarize connections = count() by gatewayId) on gatewayId"
        "\n| where isnull(connections)"
        "\n| extend details = strcat(tostring(properties.gatewayType), ' ',"
        " tostring(properties.sku.name))" + _PROJECT,
    ),
    OrphanCheck(
        "load-balancers",
        "Load balancers without backend pools or NAT rules",
        "Standard load balancers are billed per rule/hour.",
        "Resources"
        "\n| where type =~ 'microsoft.network/loadbalancers'"
        f"\n| where {_empty('properties.backendAddressPools')}"
        f" and {_empty('properties.inboundNatRules')}"
        "\n| extend details = tostring(sku.name)" + _PROJECT,
    ),
    OrphanCheck(
        "nat-gateways",
        "NAT gateways not attached to a subnet",
        "Billed hourly even without traffic.",
        "Resources"
        "\n| where type =~ 'microsoft.network/natgateways'"
        f"\n| where {_empty('properties.subnets')}"
        "\n| extend details = tostring(sku.name)" + _PROJECT,
    ),
    OrphanCheck(
        "nics",
        "Network interfaces not attached to anything",
        "Clutter; may hold private IPs in your subnets.",
        "Resources"
        "\n| where type =~ 'microsoft.network/networkinterfaces'"
        "\n| where isnull(properties.virtualMachine) and isnull(properties.privateEndpoint)"
        " and isnull(properties.privateLinkService)"
        f" and {_empty('properties.hostedWorkloads')}"
        "\n| extend details = tostring(properties.ipConfigurations[0].properties.privateIPAddress)"
        + _PROJECT,
    ),
    OrphanCheck(
        "nsgs",
        "Network security groups not associated with subnets or NICs",
        "Clutter; unused rules make reviews harder.",
        "Resources"
        "\n| where type =~ 'microsoft.network/networksecuritygroups'"
        f"\n| where {_empty('properties.networkInterfaces')}"
        f" and {_empty('properties.subnets')}"
        "\n| extend details = strcat(tostring(array_length(properties.securityRules)),"
        " ' custom rules')" + _PROJECT,
    ),
    OrphanCheck(
        "route-tables",
        "Route tables not associated with subnets",
        "Clutter; no cost.",
        "Resources"
        "\n| where type =~ 'microsoft.network/routetables'"
        f"\n| where {_empty('properties.subnets')}"
        "\n| extend details = strcat(tostring(array_length(properties.routes)), ' routes')"
        + _PROJECT,
    ),
    OrphanCheck(
        "resource-groups",
        "Empty resource groups",
        "Clutter; no cost.",
        "ResourceContainers"
        f"\n| where type =~ '{RESOURCE_GROUP_TYPE}'"
        "\n| extend rgKey = strcat(tolower(subscriptionId), '/', tolower(resourceGroup))"
        "\n| join kind=leftouter (Resources"
        " | extend rgKey = strcat(tolower(subscriptionId), '/', tolower(resourceGroup))"
        " | summarize resources = count() by rgKey) on rgKey"
        "\n| where isnull(resources)"
        "\n| extend details = 'no resources'" + _PROJECT,
    ),
)

_CHECKS_BY_KEY = {check.key: check for check in ORPHAN_CHECKS}


def orphan_query(check: OrphanCheck, resource_groups: Sequence[str] = ()) -> str:
    if not resource_groups:
        return check.query
    return f"{check.query}{_where([kql_in('resourceGroup', resource_groups)])}"


@click.command("orphans")
@click.option(
    "-c",
    "--check",
    "checks",
    multiple=True,
    type=click.Choice(list(_CHECKS_BY_KEY)),
    help="Run only these checks (repeatable). Default: all.",
)
@click.option("--list-checks", is_flag=True, help="Describe the available checks and exit.")
@subscriptions_option
@resource_groups_option
@fail_on_findings_option
@output_option
@pass_azure
def orphans(
    azure: AzureContext,
    checks: Tuple[str, ...],
    list_checks: bool,
    subscriptions: Tuple[str, ...],
    resource_groups: Tuple[str, ...],
    fail_on_findings: bool,
    output: str,
) -> None:
    """Find orphaned or idle resources that still cost money (read-only).

    Covers unattached disks, unassociated public IPs, stopped-but-allocated VMs,
    empty App Service plans, idle gateways/load balancers and more. Review the
    results before deleting anything.
    """
    selected = [_CHECKS_BY_KEY[key] for key in checks] if checks else list(ORPHAN_CHECKS)
    if list_checks:
        render(
            [{"check": c.key, "title": c.title, "why": c.why} for c in selected],
            [("check", "Check"), ("title", "Finds"), ("why", "Why it matters")],
            output,
        )
        return
    subs = resolve_subscriptions(azure.client, subscriptions)
    rows: List[Row] = []
    for check in selected:
        with progress(f"Checking {check.title.lower()}..."):
            found = azure.client.resource_graph(
                orphan_query(check, resource_groups), subscriptions=subs or None
            )
        found.sort(
            key=lambda r: (
                str(r.get("subscriptionId", "")),
                str(r.get("resourceGroup", "")).lower(),
                str(r.get("name", "")).lower(),
            )
        )
        rows.extend({"check": check.key, **item} for item in found)
    summary = ", ".join(f"{c.key}: {sum(1 for r in rows if r['check'] == c.key)}" for c in selected)
    render(
        rows,
        [
            ("check", "Check"),
            ("name", "Name"),
            ("resourceGroup", "Resource group"),
            ("subscriptionId", "Subscription"),
            ("location", "Location"),
            ("details", "Details"),
        ],
        output,
        caption=f"{len(rows):,} findings ({summary})",
        empty_message="No orphaned resources found.",
    )
    exit_on_findings(fail_on_findings, len(rows))
