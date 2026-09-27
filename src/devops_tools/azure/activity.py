"""``activity``: recent changes (create, update, delete) from the Azure Activity Log."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import click

from .common import (
    AzureContext,
    Row,
    output_option,
    pass_azure,
    pick_subscription,
    progress,
    render,
    short_resource_id,
    subscription_option,
)

ACTIVITY_LOG_API_VERSION = "2015-04-01"
MAX_LOOKBACK_HOURS = 90 * 24
FINAL_STATUSES = ("succeeded", "failed", "canceled")
SELECT_FIELDS = (
    "eventTimestamp,caller,operationName,status,subStatus,resourceId,resourceGroupName,"
    "category,operationId,correlationId,level"
)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _odata_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def activity_filter(
    start: datetime,
    end: datetime,
    resource_group: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> str:
    """Build the Activity Log ``$filter`` (it allows at most one extra condition)."""
    parts = [f"eventTimestamp ge '{_iso(start)}'", f"eventTimestamp le '{_iso(end)}'"]
    if resource_group:
        parts.append(f"resourceGroupName eq {_odata_string(resource_group)}")
    elif resource_id:
        parts.append(f"resourceUri eq {_odata_string(resource_id)}")
    return " and ".join(parts)


def _value(field: Any) -> str:
    if isinstance(field, dict):
        return str(field.get("value") or field.get("localizedValue") or "")
    return str(field or "")


def _localized(field: Any) -> str:
    if isinstance(field, dict):
        return str(field.get("localizedValue") or field.get("value") or "")
    return str(field or "")


def _status_message(event: Dict[str, Any]) -> str:
    """Short error text from ``properties.statusMessage`` (present on failed operations)."""
    raw = (event.get("properties") or {}).get("statusMessage")
    if not raw:
        return ""
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)[:300]
    error = data.get("error", data) if isinstance(data, dict) else {}
    if not isinstance(error, dict):
        return str(raw)[:300]
    code, message = error.get("code"), error.get("message")
    text = f"{code}: {message}" if code and message else str(message or code or raw)
    return text[:300]


def summarize_events(
    events: Iterable[Dict[str, Any]],
    *,
    include_actions: bool = False,
    failed_only: bool = False,
    caller: Optional[str] = None,
) -> List[Row]:
    """Keep completed administrative write/delete operations, newest first, de-duplicated."""
    suffixes: Tuple[str, ...] = ("/write", "/delete") + (("/action",) if include_actions else ())
    seen: Set[Tuple[str, str]] = set()
    rows: List[Row] = []
    for event in events:
        if _value(event.get("category")).lower() != "administrative":
            continue
        status = _value(event.get("status"))
        if status.lower() not in FINAL_STATUSES or (failed_only and status.lower() != "failed"):
            continue
        operation = _value(event.get("operationName"))
        if not operation.lower().endswith(suffixes):
            continue
        who = str(event.get("caller") or "")
        if caller and caller.lower() not in who.lower():
            continue
        operation_id = str(event.get("operationId") or "")
        if operation_id:
            key = (operation_id, status.lower())
            if key in seen:
                continue
            seen.add(key)
        resource_id = str(event.get("resourceId") or "")
        timestamp = str(event.get("eventTimestamp") or "")
        rows.append(
            {
                "time": timestamp[:19].replace("T", " "),
                "caller": who,
                "operationName": _localized(event.get("operationName")),
                "operation": operation,
                "status": status,
                "subStatus": _localized(event.get("subStatus")),
                "resourceGroup": event.get("resourceGroupName"),
                "resource": short_resource_id(resource_id),
                "resourceId": resource_id,
                "correlationId": event.get("correlationId"),
                "error": _status_message(event),
                "eventTimestamp": timestamp,
            }
        )
    rows.sort(key=lambda row: str(row["eventTimestamp"]), reverse=True)
    return rows


@click.command("activity")
@subscription_option
@click.option(
    "--hours",
    type=click.FloatRange(min=0, min_open=True, max=MAX_LOOKBACK_HOURS),
    default=24.0,
    show_default=True,
    help="How far back to look (max 2160 = 90 days).",
)
@click.option("-g", "--resource-group", help="Only changes in this resource group.")
@click.option("--resource-id", help="Only changes to this resource (full resource ID).")
@click.option("--caller", help="Only changes by callers containing this text (case-insensitive).")
@click.option("--failed-only", is_flag=True, help="Only failed operations (shows the error).")
@click.option(
    "--include-actions",
    is_flag=True,
    help="Also include POST actions such as restart, start/stop or listKeys.",
)
@click.option("--first", type=click.IntRange(min=1), help="Show only the N most recent changes.")
@output_option
@pass_azure
def activity(
    azure: AzureContext,
    subscription: Optional[str],
    hours: float,
    resource_group: Optional[str],
    resource_id: Optional[str],
    caller: Optional[str],
    failed_only: bool,
    include_actions: bool,
    first: Optional[int],
    output: str,
) -> None:
    """Show who changed what: recent create/update/delete operations in a subscription.

    \b
    Examples:
      azure-tools activity --hours 4
      azure-tools activity -g rg-prod --failed-only
      azure-tools activity --caller alice@contoso.com --hours 168 -o csv
    """
    if resource_group and resource_id:
        raise click.UsageError("Use either --resource-group or --resource-id, not both.")
    client = azure.client
    subscription_id = pick_subscription(client, subscription)
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {
        "api-version": ACTIVITY_LOG_API_VERSION,
        "$filter": activity_filter(start, end, resource_group, resource_id),
        "$select": SELECT_FIELDS + (",properties" if failed_only else ""),
    }
    url = (
        f"/subscriptions/{subscription_id}/providers/Microsoft.Insights"
        "/eventtypes/management/values"
    )
    with progress("Reading the activity log..."):
        events = list(client.paged(url, params=params))
    rows = summarize_events(
        events, include_actions=include_actions, failed_only=failed_only, caller=caller
    )
    if first:
        rows = rows[:first]
    columns = [
        ("time", "Time (UTC)"),
        ("caller", "Caller"),
        ("operationName", "Operation"),
        ("status", "Status"),
        ("resourceGroup", "Resource group"),
        ("resource", "Resource"),
    ]
    if failed_only:
        columns.append(("error", "Error"))
    render(
        rows,
        columns,
        output,
        caption=f"Subscription {subscription_id}, last {hours:g}h",
        empty_message="No matching changes found.",
    )
