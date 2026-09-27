"""Shared helpers for the ``azure-tools`` commands: context, options, scopes and output."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
)

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .client import AzureClient, is_guid

Row = Dict[str, Any]
Columns = Sequence[Tuple[str, str]]
F = TypeVar("F", bound=Callable[..., Any])
T = TypeVar("T")
R = TypeVar("R")

OUTPUT_FORMATS = ("table", "json", "csv")


class AzureContext:
    """State shared by all ``azure-tools`` commands (stored in ``click.Context.obj``)."""

    def __init__(self, client: Optional[AzureClient] = None) -> None:
        self._client = client

    @property
    def client(self) -> AzureClient:
        if self._client is None:
            self._client = AzureClient()
        return self._client


pass_azure = click.make_pass_decorator(AzureContext, ensure=True)


# Options -------------------------------------------------------------------


def output_option(func: F) -> F:
    return click.option(
        "-o",
        "--output",
        type=click.Choice(OUTPUT_FORMATS, case_sensitive=False),
        default="table",
        show_default=True,
        help="Output format.",
    )(func)


def subscriptions_option(func: F) -> F:
    return click.option(
        "-s",
        "--subscription",
        "subscriptions",
        multiple=True,
        metavar="ID|NAME",
        help="Subscription ID or name (repeatable). Default: every subscription you can access.",
    )(func)


def subscription_option(func: F) -> F:
    return click.option(
        "-s",
        "--subscription",
        "subscription",
        metavar="ID|NAME",
        help="Subscription ID or name. Default: $AZURE_SUBSCRIPTION_ID, then the Azure CLI "
        "default subscription ('az account show').",
    )(func)


def resource_groups_option(func: F) -> F:
    return click.option(
        "-g",
        "--resource-group",
        "resource_groups",
        multiple=True,
        metavar="NAME",
        help="Only resources in this resource group (repeatable).",
    )(func)


def fail_on_findings_option(func: F) -> F:
    return click.option(
        "--fail-on-findings",
        is_flag=True,
        help="Exit with status 1 when anything is reported (useful in pipelines).",
    )(func)


# Subscriptions -------------------------------------------------------------


def resolve_subscriptions(client: AzureClient, values: Iterable[str]) -> List[str]:
    """Resolve subscription IDs or display names to subscription IDs (order preserved)."""
    resolved: List[str] = []
    for raw in values:
        value = raw.strip()
        if not value:
            continue
        if is_guid(value):
            sub_id = value.lower()
        else:
            matches = [
                sub
                for sub in client.list_subscriptions()
                if str(sub.get("displayName", "")).lower() == value.lower()
            ]
            if not matches:
                raise click.BadParameter(
                    f"no accessible subscription is named '{value}'",
                    param_hint="'--subscription'",
                )
            if len(matches) > 1:
                raise click.BadParameter(
                    f"'{value}' matches {len(matches)} subscriptions; use the subscription ID",
                    param_hint="'--subscription'",
                )
            sub_id = str(matches[0]["subscriptionId"]).lower()
        if sub_id not in resolved:
            resolved.append(sub_id)
    return resolved


def az_cli_subscription() -> Optional[str]:
    """Return the Azure CLI's current subscription ID, if the CLI is installed and signed in."""
    az = shutil.which("az")
    if not az:
        return None
    try:
        proc = subprocess.run(
            [az, "account", "show", "--query", "id", "--output", "tsv"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = proc.stdout.strip()
    return value.lower() if proc.returncode == 0 and is_guid(value) else None


def default_subscription(client: AzureClient) -> str:
    """Pick the subscription for single-subscription commands.

    Order: ``$AZURE_SUBSCRIPTION_ID``, the Azure CLI default subscription, then the only
    enabled subscription the identity can access.
    """
    from_env = os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
    if from_env:
        return resolve_subscriptions(client, [from_env])[0]
    from_cli = az_cli_subscription()
    if from_cli:
        return from_cli
    enabled = [s for s in client.list_subscriptions() if s.get("state", "Enabled") == "Enabled"]
    if len(enabled) == 1:
        return str(enabled[0]["subscriptionId"]).lower()
    raise click.UsageError(
        "No subscription selected. Pass --subscription, set AZURE_SUBSCRIPTION_ID or run "
        "'az account set --subscription <id>'."
    )


def pick_subscription(client: AzureClient, value: Optional[str]) -> str:
    """Resolve ``--subscription`` for single-subscription commands (with defaults)."""
    if value:
        return resolve_subscriptions(client, [value])[0]
    return default_subscription(client)


# Resource Graph (KQL) helpers ----------------------------------------------


def kql_string(value: str) -> str:
    """Quote *value* as a KQL string literal."""
    escaped = (
        value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
    )
    return f"'{escaped}'"


def kql_in(column: str, values: Iterable[str]) -> str:
    """Build a case-insensitive ``column in~ (...)`` filter."""
    return f"{column} in~ ({', '.join(kql_string(v) for v in values)})"


def normalize_location(value: str) -> str:
    """``'East US 2'`` -> ``'eastus2'`` (the form ARM uses in URLs and filters)."""
    return value.replace(" ", "").lower()


def short_resource_id(resource_id: str) -> str:
    """``/subscriptions/../providers/Microsoft.Web/sites/app`` -> ``Microsoft.Web/sites/app``."""
    marker = "/providers/"
    index = resource_id.lower().rfind(marker)
    if index >= 0:
        return resource_id[index + len(marker) :]
    parts = resource_id.strip("/").split("/")
    return "/".join(parts[2:]) if len(parts) > 2 else resource_id


# Output --------------------------------------------------------------------


def cell(value: Any) -> str:
    """Format a value for table / CSV output."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, tuple)) and all(
        not isinstance(item, (dict, list, tuple)) for item in value
    ):
        return ", ".join(cell(item) for item in value)
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def discover_columns(rows: Sequence[Row]) -> List[str]:
    """Column names in order of first appearance across *rows*."""
    seen: Dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key, None)
    return list(seen)


def render(
    rows: Sequence[Row],
    columns: Columns,
    output: str,
    *,
    title: Optional[str] = None,
    caption: Optional[str] = None,
    empty_message: str = "No results.",
    row_style: Optional[Callable[[Row], Optional[str]]] = None,
) -> None:
    """Print *rows* as a table (default), JSON (all fields) or CSV (*columns* only)."""
    fmt = output.lower()
    if fmt == "json":
        click.echo(json.dumps(list(rows), indent=2, default=str))
        return
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([key for key, _ in columns])
        for row in rows:
            writer.writerow([cell(row.get(key)) for key, _ in columns])
        click.echo(buffer.getvalue(), nl=False)
        return
    console = Console()
    if not rows:
        console.print(Text(empty_message))
        return
    table = Table(
        title=Text(title) if title else None,
        caption=Text(caption) if caption else None,
        header_style="bold",
    )
    for _, header in columns:
        table.add_column(header, overflow="fold")
    for row in rows:
        style = row_style(row) if row_style else None
        table.add_row(*(Text(cell(row.get(key))) for key, _ in columns), style=style)
    console.print(table)


def warn(message: str) -> None:
    """Print a warning to stderr (keeps stdout clean for data)."""
    click.secho(f"Warning: {message}", fg="yellow", err=True)


def progress(message: str) -> ContextManager[Any]:
    """Show a spinner on interactive terminals while slow work runs."""
    if sys.stderr.isatty():
        return Console(stderr=True).status(message)
    return contextlib.nullcontext()


def exit_on_findings(enabled: bool, findings: int) -> None:
    """Exit with status 1 when ``--fail-on-findings`` is set and something was reported."""
    if enabled and findings:
        click.get_current_context().exit(1)


def parallel_map(func: Callable[[T], R], items: Sequence[T], max_workers: int = 8) -> List[R]:
    """Apply *func* to *items* concurrently and return the results in input order."""
    if len(items) <= 1 or max_workers <= 1:
        return [func(item) for item in items]
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as pool:
        return list(pool.map(func, items))
