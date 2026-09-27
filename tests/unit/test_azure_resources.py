"""Tests for the Resource Graph commands: graph, inventory, tag-audit and orphans."""

import json

from devops_tools.azure.resources import (
    ORPHAN_CHECKS,
    inventory_query,
    missing_tags,
    orphan_query,
    tag_audit_query,
)

SUB = "00000000-0000-0000-0000-000000000001"
ARG = "Microsoft.ResourceGraph/resources"


class TestGraph:
    def test_runs_query_and_prints_json(self, run_azure, azure_session, fakes):
        rows = [{"name": "vm1", "type": "microsoft.compute/virtualmachines"}]
        azure_session.reply("POST", ARG, fakes.arg_page(rows))
        result = run_azure("graph", "Resources | take 1", "-s", SUB, "-o", "json")
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == rows
        body = azure_session.calls[0].json
        assert body["query"] == "Resources | take 1"
        assert body["subscriptions"] == [SUB]

    def test_reads_query_from_file(self, run_azure, azure_session, fakes, tmp_path):
        query_file = tmp_path / "q.kql"
        query_file.write_text("Resources | project name")
        azure_session.reply("POST", ARG, fakes.arg_page([{"name": "a"}]))
        result = run_azure("graph", "-f", str(query_file), "-m", "mg1", "--first", "5")
        assert result.exit_code == 0, result.output
        assert "a" in result.stdout
        body = azure_session.calls[0].json
        assert body["query"] == "Resources | project name"
        assert body["managementGroups"] == ["mg1"]
        assert body["options"]["$top"] == 5

    def test_table_columns_come_from_rows(self, run_azure, azure_session, fakes):
        azure_session.reply("POST", ARG, fakes.arg_page([{"type": "t1", "count_": 3}]))
        result = run_azure("graph", "Resources | summarize count() by type")
        assert result.exit_code == 0, result.output
        assert "count_" in result.stdout and "t1" in result.stdout

    def test_usage_errors(self, run_azure):
        assert run_azure("graph").exit_code == 2
        assert run_azure("graph", "Resources", "-s", SUB, "-m", "mg").exit_code == 2


class TestInventory:
    def test_query_filters(self):
        query = inventory_query("type", ["rg1"], ["microsoft.web/sites"])
        assert "| where resourceGroup in~ ('rg1')" in query
        assert "| where type in~ ('microsoft.web/sites')" in query
        assert "summarize resourceCount = count() by type" in query

    def test_by_subscription_csv(self, run_azure, azure_session, fakes):
        rows = [
            {"subscriptionName": "Prod", "subscriptionId": SUB, "resourceCount": 7},
            {"subscriptionName": "Dev", "subscriptionId": "x", "resourceCount": 3},
        ]
        azure_session.reply("POST", ARG, fakes.arg_page(rows))
        result = run_azure("inventory", "--by", "subscription", "-o", "csv")
        assert result.exit_code == 0, result.output
        assert result.stdout.splitlines() == [
            "subscriptionName,subscriptionId,resourceCount",
            f"Prod,{SUB},7",
            "Dev,x,3",
        ]
        assert "join kind=leftouter" in azure_session.calls[0].json["query"]

    def test_table_caption_totals(self, run_azure, azure_session, fakes):
        rows = [{"type": "a", "resourceCount": 1200}, {"type": "b", "resourceCount": 3}]
        azure_session.reply("POST", ARG, fakes.arg_page(rows))
        result = run_azure("inventory", "--top", "2")
        assert result.exit_code == 0, result.output
        assert "1,203 resources in 2 groups" in result.stdout
        assert azure_session.calls[0].json["options"]["$top"] == 2


class TestTagAudit:
    def test_missing_tags_is_case_insensitive_and_treats_empty_as_missing(self):
        tags = {"Owner": "alice", "costcenter": " ", "env": "prod"}
        assert missing_tags(tags, ["owner", "CostCenter", "app"]) == ["CostCenter", "app"]
        assert missing_tags(None, ["owner"]) == ["owner"]

    def test_query_includes_resource_groups_unless_types_given(self):
        query = tag_audit_query(["owner"], resource_groups=["rg1"])
        assert "union (ResourceContainers" in query
        assert query.count("resourceGroup in~ ('rg1')") == 2
        assert "tostring(tags) !contains '\"owner\":'" in query
        assert "union" not in tag_audit_query(["owner"], types=["microsoft.web/sites"])
        assert "union" not in tag_audit_query(["owner"], include_resource_groups=False)

    def test_reports_only_non_compliant_resources(self, run_azure, azure_session, fakes):
        candidates = [
            {"name": "ok", "tags": {"OWNER": "bob", "costCenter": "42"}},
            {"name": "no-tags", "tags": None},
            {"name": "empty-owner", "tags": {"owner": "", "costCenter": "1"}},
        ]
        azure_session.reply("POST", ARG, fakes.arg_page(candidates))
        result = run_azure("tag-audit", "-t", "owner", "-t", "costCenter", "-o", "json")
        assert result.exit_code == 0, result.output
        rows = json.loads(result.stdout)
        assert [(r["name"], r["missingTags"]) for r in rows] == [
            ("no-tags", ["owner", "costCenter"]),
            ("empty-owner", ["owner"]),
        ]

    def test_fail_on_findings(self, run_azure, azure_session, fakes):
        azure_session.reply("POST", ARG, fakes.arg_page([{"name": "x", "tags": {}}]))
        result = run_azure("tag-audit", "-t", "owner", "--fail-on-findings")
        assert result.exit_code == 1
        assert "1 non-compliant (owner: 1)" in result.stdout

    def test_compliant(self, run_azure, azure_session, fakes):
        azure_session.reply("POST", ARG, fakes.arg_page([{"name": "x", "tags": {"owner": "a"}}]))
        result = run_azure("tag-audit", "-t", "owner", "--fail-on-findings")
        assert result.exit_code == 0
        assert "All audited resources have the required tags." in result.stdout


class TestOrphans:
    def test_every_check_projects_the_same_columns(self):
        for check in ORPHAN_CHECKS:
            assert check.query.rstrip().endswith(
                "| project id, name, type, resourceGroup, subscriptionId, location, details"
            ), check.key

    def test_resource_group_filter(self):
        query = orphan_query(ORPHAN_CHECKS[0], ["rg-a"])
        assert query.endswith("| where resourceGroup in~ ('rg-a')")

    def test_list_checks_needs_no_azure_calls(self, run_azure, azure_session):
        result = run_azure("orphans", "--list-checks", "-o", "csv")
        assert result.exit_code == 0, result.output
        assert len(result.stdout.splitlines()) == len(ORPHAN_CHECKS) + 1
        assert azure_session.calls == []

    def test_runs_selected_checks(self, run_azure, azure_session, fakes):
        def handler(call):
            if "microsoft.compute/disks" in call.json["query"]:
                return fakes.arg_page(
                    [
                        {"name": "disk-b", "resourceGroup": "rg", "details": "P10, 128 GiB"},
                        {"name": "disk-a", "resourceGroup": "rg", "details": "P10, 64 GiB"},
                    ]
                )
            return fakes.arg_page([])

        azure_session.reply("POST", ARG, handler=handler)
        result = run_azure(
            "orphans", "-c", "disks", "-c", "public-ips", "-o", "json", "--fail-on-findings"
        )
        assert result.exit_code == 1
        rows = json.loads(result.stdout)
        assert [(r["check"], r["name"]) for r in rows] == [
            ("disks", "disk-a"),
            ("disks", "disk-b"),
        ]
        assert len(azure_session.calls) == 2

    def test_nothing_found(self, run_azure, azure_session, fakes):
        azure_session.reply("POST", ARG, fakes.arg_page([]))
        result = run_azure("orphans", "-c", "nics")
        assert result.exit_code == 0
        assert "No orphaned resources found." in result.stdout
