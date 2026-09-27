"""Tests for the shared azure-tools helpers (subscriptions, KQL quoting, output)."""

import json

import click
import pytest

from devops_tools.azure import common
from devops_tools.azure.common import (
    cell,
    default_subscription,
    kql_in,
    kql_string,
    normalize_location,
    parallel_map,
    render,
    resolve_subscriptions,
    short_resource_id,
)

SUB_A = "00000000-0000-0000-0000-00000000000a"
SUB_B = "00000000-0000-0000-0000-00000000000b"
SUBSCRIPTIONS = {
    "value": [
        {"subscriptionId": SUB_A, "displayName": "Production", "state": "Enabled"},
        {"subscriptionId": SUB_B, "displayName": "Dev", "state": "Enabled"},
    ]
}


@pytest.fixture
def with_subscriptions(azure_session):
    azure_session.reply("GET", "/subscriptions?", {"json_data": SUBSCRIPTIONS})


class TestResolveSubscriptions:
    def test_ids_are_normalised_and_deduplicated(self, azure_client):
        assert resolve_subscriptions(azure_client, [SUB_A.upper(), SUB_A, " "]) == [SUB_A]

    def test_names_are_case_insensitive(self, azure_client, with_subscriptions):
        assert resolve_subscriptions(azure_client, ["production", "Dev"]) == [SUB_A, SUB_B]

    def test_unknown_name(self, azure_client, with_subscriptions):
        with pytest.raises(click.BadParameter, match="no accessible subscription"):
            resolve_subscriptions(azure_client, ["Nope"])

    def test_ambiguous_name(self, azure_client, azure_session):
        duplicate = {
            "value": [{"subscriptionId": s, "displayName": "Same"} for s in (SUB_A, SUB_B)]
        }
        azure_session.reply("GET", "/subscriptions?", {"json_data": duplicate})
        with pytest.raises(click.BadParameter, match="matches 2 subscriptions"):
            resolve_subscriptions(azure_client, ["Same"])


class TestDefaultSubscription:
    def test_environment_variable_wins(self, azure_client, monkeypatch):
        monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB_B)
        monkeypatch.setattr(common, "az_cli_subscription", lambda: SUB_A)
        assert default_subscription(azure_client) == SUB_B

    def test_azure_cli_default(self, azure_client, monkeypatch):
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
        monkeypatch.setattr(common, "az_cli_subscription", lambda: SUB_A)
        assert default_subscription(azure_client) == SUB_A

    def test_single_enabled_subscription(self, azure_client, azure_session, monkeypatch):
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
        monkeypatch.setattr(common, "az_cli_subscription", lambda: None)
        subs = {
            "value": [
                {"subscriptionId": SUB_A, "state": "Enabled"},
                {"subscriptionId": SUB_B, "state": "Disabled"},
            ]
        }
        azure_session.reply("GET", "/subscriptions?", {"json_data": subs})
        assert default_subscription(azure_client) == SUB_A

    def test_no_default(self, azure_client, with_subscriptions, monkeypatch):
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
        monkeypatch.setattr(common, "az_cli_subscription", lambda: None)
        with pytest.raises(click.UsageError, match="No subscription selected"):
            default_subscription(azure_client)

    def test_az_cli_subscription_without_cli(self, monkeypatch):
        monkeypatch.setattr(common.shutil, "which", lambda name: None)
        assert common.az_cli_subscription() is None


class TestFormatting:
    def test_kql_string_escapes(self):
        assert kql_string("it's") == "'it\\'s'"
        assert kql_string("a\\b") == "'a\\\\b'"
        assert kql_string("x\ny") == "'x\\ny'"

    def test_kql_in(self):
        assert kql_in("type", ["a", "b'c"]) == "type in~ ('a', 'b\\'c')"

    def test_normalize_location(self):
        assert normalize_location("West Europe") == "westeurope"

    def test_short_resource_id(self):
        rid = f"/subscriptions/{SUB_A}/resourceGroups/rg/providers/Microsoft.Web/sites/app"
        assert short_resource_id(rid) == "Microsoft.Web/sites/app"
        assert short_resource_id(f"/subscriptions/{SUB_A}/resourceGroups/rg") == "resourceGroups/rg"

    @pytest.mark.parametrize(
        "value, expected",
        [
            (None, ""),
            (True, "true"),
            (1.5, "1.5"),
            (3, "3"),
            (["a", "b"], "a, b"),
            ({"k": 1}, '{"k": 1}'),
            ([{"k": 1}], '[{"k": 1}]'),
        ],
    )
    def test_cell(self, value, expected):
        assert cell(value) == expected

    def test_parallel_map_keeps_order(self):
        assert parallel_map(lambda n: n * 2, [3, 1, 2]) == [6, 2, 4]


class TestRender:
    ROWS = [{"name": "vm1", "tags": {"env": "prod"}}, {"name": "[red]x[/red]", "tags": None}]
    COLUMNS = [("name", "Name"), ("tags", "Tags")]

    def test_json_contains_all_fields(self, capsys):
        render(self.ROWS, [("name", "Name")], "json")
        assert json.loads(capsys.readouterr().out) == self.ROWS

    def test_csv(self, capsys):
        render(self.ROWS, self.COLUMNS, "csv")
        lines = capsys.readouterr().out.splitlines()
        assert lines == ["name,tags", 'vm1,"{""env"": ""prod""}"', "[red]x[/red],"]

    def test_table_does_not_interpret_markup(self, capsys, monkeypatch):
        monkeypatch.setenv("COLUMNS", "120")
        render(self.ROWS, self.COLUMNS, "table", caption="2 rows")
        out = capsys.readouterr().out
        assert "[red]x[/red]" in out
        assert "Name" in out and "2 rows" in out

    def test_empty_table_message(self, capsys):
        render([], self.COLUMNS, "table", empty_message="Nothing here.")
        assert "Nothing here." in capsys.readouterr().out
