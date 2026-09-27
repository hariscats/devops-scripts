"""``aks``: AKS cluster versions, support status and available upgrades."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import click

from .client import AzureClient, AzureError
from .common import (
    AzureContext,
    Row,
    exit_on_findings,
    fail_on_findings_option,
    kql_in,
    output_option,
    pass_azure,
    progress,
    render,
    resolve_subscriptions,
    resource_groups_option,
    subscriptions_option,
    warn,
)

AKS_API_VERSION = "2024-10-01"
PROBLEM_STATUSES = ("unsupported", "LTS only")

_CLUSTERS_QUERY = """Resources
| where type =~ 'microsoft.containerservice/managedclusters'{filters}
| project id, name, resourceGroup, subscriptionId, location,
    kubernetesVersion = tostring(properties.kubernetesVersion),
    currentKubernetesVersion = tostring(properties.currentKubernetesVersion),
    provisioningState = tostring(properties.provisioningState),
    powerState = tostring(properties.powerState.code),
    supportPlan = tostring(properties.supportPlan),
    tier = tostring(sku.tier),
    agentPoolProfiles = properties.agentPoolProfiles
| order by subscriptionId asc, resourceGroup asc, name asc"""


def version_key(version: str) -> Tuple[int, ...]:
    """``'1.30.4'`` -> ``(1, 30, 4)`` for ordering (non-numeric parts are ignored)."""
    return tuple(int(part) for part in re.findall(r"\d+", version))


def minor_version(version: str) -> str:
    """``'1.30.4'`` -> ``'1.30'``."""
    return ".".join(version.split(".")[:2])


@dataclass
class RegionVersions:
    """Kubernetes versions AKS offers in one region."""

    official: Set[str] = field(default_factory=set)
    lts: Set[str] = field(default_factory=set)
    preview: Set[str] = field(default_factory=set)
    patches: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def latest(self) -> Optional[str]:
        candidates = [p for minor in self.official for p in self.patches.get(minor, [])]
        return max(candidates, key=version_key) if candidates else None

    def latest_patch(self, minor: str) -> Optional[str]:
        patches = self.patches.get(minor) or []
        return patches[-1] if patches else None


def parse_region_versions(payload: Dict[str, Any]) -> RegionVersions:
    info = RegionVersions()
    for entry in payload.get("values") or []:
        minor = minor_version(str(entry.get("version") or ""))
        if not minor:
            continue
        if entry.get("isPreview"):
            info.preview.add(minor)
            continue
        plans = (entry.get("capabilities") or {}).get("supportPlan") or ["KubernetesOfficial"]
        if "KubernetesOfficial" in plans:
            info.official.add(minor)
        if "AKSLongTermSupport" in plans:
            info.lts.add(minor)
        info.patches[minor] = sorted((entry.get("patchVersions") or {}).keys(), key=version_key)
    return info


def support_status(version: str, support_plan: str, info: Optional[RegionVersions]) -> str:
    if info is None or not version:
        return "unknown"
    minor = minor_version(version)
    if minor in info.official:
        oldest = min(info.official, key=version_key)
        return "oldest supported" if minor == oldest and len(info.official) > 1 else "supported"
    if minor in info.lts:
        return "supported (LTS)" if support_plan == "AKSLongTermSupport" else "LTS only"
    if minor in info.preview:
        return "preview"
    return "unsupported"


def node_pool_summary(pools: Any, control_plane: str) -> Tuple[str, bool]:
    """Summarise node pools as ``name: version xN`` and flag version drift."""
    parts: List[str] = []
    drift = False
    for pool in pools if isinstance(pools, list) else []:
        version = str(
            pool.get("currentOrchestratorVersion") or pool.get("orchestratorVersion") or ""
        )
        if version and control_plane and version != control_plane:
            drift = True
        count = pool.get("count")
        parts.append(f"{pool.get('name')}: {version or '?'} x{count if count is not None else '?'}")
    return "; ".join(parts), drift


def cluster_row(cluster: Dict[str, Any], info: Optional[RegionVersions]) -> Row:
    version = str(cluster.get("currentKubernetesVersion") or cluster.get("kubernetesVersion") or "")
    status = support_status(version, str(cluster.get("supportPlan") or ""), info)
    pools, drift = node_pool_summary(cluster.get("agentPoolProfiles"), version)
    latest_patch = info.latest_patch(minor_version(version)) if info and version else None
    latest = info.latest if info else None
    upgrades = []
    if latest_patch and version_key(latest_patch) > version_key(version):
        upgrades.append(latest_patch)
    if latest and version_key(latest) > version_key(latest_patch or version):
        upgrades.append(latest)
    return {
        "name": cluster.get("name"),
        "resourceGroup": cluster.get("resourceGroup"),
        "subscriptionId": cluster.get("subscriptionId"),
        "location": cluster.get("location"),
        "version": version,
        "status": status,
        "upgrades": upgrades,
        "nodePools": pools,
        "nodePoolDrift": drift,
        "tier": cluster.get("tier"),
        "supportPlan": cluster.get("supportPlan"),
        "powerState": cluster.get("powerState"),
        "provisioningState": cluster.get("provisioningState"),
        "state": ", ".join(
            part
            for part in (
                str(cluster.get("provisioningState") or ""),
                "stopped" if cluster.get("powerState") == "Stopped" else "",
            )
            if part
        ),
        "id": cluster.get("id"),
    }


def _region_versions(
    client: AzureClient, subscription_id: str, location: str
) -> Optional[RegionVersions]:
    url = (
        f"/subscriptions/{subscription_id}/providers/Microsoft.ContainerService"
        f"/locations/{location}/kubernetesVersions"
    )
    try:
        return parse_region_versions(client.get(url, params={"api-version": AKS_API_VERSION}))
    except AzureError as exc:
        warn(f"could not list AKS versions for {location}: {exc}")
        return None


def is_problem(row: Row) -> bool:
    return row["status"] in PROBLEM_STATUSES or row.get("provisioningState") == "Failed"


@click.command("aks")
@subscriptions_option
@resource_groups_option
@fail_on_findings_option
@output_option
@pass_azure
def aks(
    azure: AzureContext,
    subscriptions: Tuple[str, ...],
    resource_groups: Tuple[str, ...],
    fail_on_findings: bool,
    output: str,
) -> None:
    """Check AKS clusters: Kubernetes version support, upgrades and node pool drift.

    Status is 'supported', 'oldest supported' (next to leave support; plan an
    upgrade), 'LTS only' (needs the Premium tier's long-term support plan),
    'unsupported', 'preview' or 'unknown'. --fail-on-findings exits with status 1
    for 'unsupported' / 'LTS only' clusters and clusters in a failed state.
    """
    client = azure.client
    subs = resolve_subscriptions(client, subscriptions)
    filters = f"\n| where {kql_in('resourceGroup', resource_groups)}" if resource_groups else ""
    with progress("Finding AKS clusters..."):
        clusters = client.resource_graph(
            _CLUSTERS_QUERY.format(filters=filters), subscriptions=subs or None
        )
    versions: Dict[str, Optional[RegionVersions]] = {}
    rows: List[Row] = []
    for cluster in clusters:
        location = str(cluster.get("location") or "").lower()
        if location not in versions:
            with progress(f"Listing AKS versions in {location}..."):
                versions[location] = _region_versions(
                    client, str(cluster.get("subscriptionId")), location
                )
        rows.append(cluster_row(cluster, versions[location]))
    problems = sum(1 for row in rows if is_problem(row))
    render(
        rows,
        [
            ("name", "Cluster"),
            ("resourceGroup", "Resource group"),
            ("location", "Location"),
            ("version", "Version"),
            ("status", "Support"),
            ("upgrades", "Upgrades available"),
            ("nodePools", "Node pools"),
            ("state", "State"),
        ],
        output,
        caption=f"{len(rows)} cluster(s), {problems} need attention",
        empty_message="No AKS clusters found.",
        row_style=lambda row: "red" if is_problem(row) else None,
    )
    exit_on_findings(fail_on_findings, problems)
