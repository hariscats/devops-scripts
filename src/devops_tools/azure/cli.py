"""``azure-tools``: read-only Azure productivity commands.

Authentication uses ``DefaultAzureCredential`` (Azure CLI login, environment
service principal, managed identity, ...). Every command only reads data.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import click
from azure.core.exceptions import ClientAuthenticationError

from .account import whoami
from .activity import activity
from .aks import aks
from .client import AzureError
from .common import AzureContext
from .compute import vm_capacity
from .keyvault import kv_expiry
from .resources import graph, inventory, orphans, tag_audit

AUTH_HINT = (
    "Sign in with 'az login' (or configure a managed identity / service principal "
    "for DefaultAzureCredential)."
)

EPILOG = """\b
Authentication: DefaultAzureCredential (az login, AZURE_CLIENT_ID/AZURE_TENANT_ID/
AZURE_CLIENT_SECRET, managed identity, ...). On a workstation, set
AZURE_TOKEN_CREDENTIALS=dev to skip the managed identity probe.
Single-subscription commands use --subscription, then AZURE_SUBSCRIPTION_ID,
then the Azure CLI default subscription.
All commands are read-only and target the Azure public cloud.
"""


class AzureGroup(click.Group):
    """Click group that turns Azure errors into clean CLI errors."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except ClientAuthenticationError as exc:
            message = str(getattr(exc, "message", None) or exc).strip().splitlines()
            summary = message[0] if message else "authentication failed"
            raise click.ClickException(f"Azure authentication failed: {summary}\n{AUTH_HINT}")
        except AzureError as exc:
            hint = f"\n{AUTH_HINT}" if exc.status == 401 else ""
            if exc.status == 403:
                hint = "\nThe signed-in identity needs read access (e.g. the Reader role)."
            raise click.ClickException(f"{exc}{hint}")


def _configure_logging(verbose: bool) -> None:
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("devops_tools.azure").setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger("azure").setLevel(logging.DEBUG if verbose else logging.ERROR)


@click.group(
    cls=AzureGroup, epilog=EPILOG, context_settings={"help_option_names": ["-h", "--help"]}
)
@click.option("-v", "--verbose", is_flag=True, help="Log HTTP retries and credential details.")
@click.version_option(package_name="devops-tools", message="%(prog)s %(version)s")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Read-only Azure productivity tools built on Azure Resource Manager APIs."""
    _configure_logging(verbose)
    ctx.ensure_object(AzureContext)


for command in (
    whoami,
    graph,
    inventory,
    tag_audit,
    orphans,
    activity,
    kv_expiry,
    vm_capacity,
    aks,
):
    cli.add_command(command)


def main(argv: Optional[list] = None) -> None:
    """Console-script entry point."""
    cli.main(args=argv, prog_name="azure-tools")


if __name__ == "__main__":  # pragma: no cover
    main()
