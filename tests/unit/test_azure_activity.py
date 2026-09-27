"""Tests for the activity command (Azure Activity Log changes)."""

import json
from datetime import datetime, timezone
from urllib.parse import unquote

from devops_tools.azure.activity import activity_filter, summarize_events

SUB = "00000000-0000-0000-0000-000000000001"
ACTIVITY_URL = "/providers/Microsoft.Insights/eventtypes/management/values"


def event(op, status="Succeeded", when="2025-01-02T10:00:00.123Z", **extra):
    base = {
        "category": {"value": "Administrative"},
        "status": {"value": status, "localizedValue": status},
        "operationName": {"value": op, "localizedValue": op.split("/")[-2].title()},
        "caller": "alice@contoso.com",
        "operationId": f"{op}-{when}",
        "eventTimestamp": when,
        "resourceGroupName": "rg1",
        "resourceId": f"/subscriptions/{SUB}/resourceGroups/rg1/providers/{op.rsplit('/', 1)[0]}/x",
    }
    base.update(extra)
    return base


def test_activity_filter():
    start = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2025, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    assert activity_filter(start, end) == (
        "eventTimestamp ge '2025-01-01T00:00:00Z' and eventTimestamp le '2025-01-02T00:00:00Z'"
    )
    assert activity_filter(start, end, resource_group="it's").endswith(
        "and resourceGroupName eq 'it''s'"
    )
    assert activity_filter(start, end, resource_id="/x/y").endswith("and resourceUri eq '/x/y'")


def test_summarize_events_filters_and_sorts():
    events = [
        event("Microsoft.Compute/virtualMachines/write", when="2025-01-02T09:00:00Z"),
        event("Microsoft.Compute/virtualMachines/write", status="Started"),
        event("Microsoft.Compute/virtualMachines/restart/action", when="2025-01-02T11:00:00Z"),
        event("Microsoft.Storage/storageAccounts/delete", when="2025-01-02T12:00:00Z"),
        event("Microsoft.Storage/storageAccounts/delete", when="2025-01-02T12:00:00Z"),  # dup
        event("Microsoft.Web/sites/write", category={"value": "Policy"}),
        event("Microsoft.Web/sites/write", caller="bob@contoso.com"),
    ]
    rows = summarize_events(events, caller="ALICE")
    assert [(r["operation"], r["time"]) for r in rows] == [
        ("Microsoft.Storage/storageAccounts/delete", "2025-01-02 12:00:00"),
        ("Microsoft.Compute/virtualMachines/write", "2025-01-02 09:00:00"),
    ]
    with_actions = summarize_events(events, include_actions=True)
    assert "Microsoft.Compute/virtualMachines/restart/action" in [
        r["operation"] for r in with_actions
    ]
    assert rows[0]["resource"] == "Microsoft.Storage/storageAccounts/x"


def test_failed_only_shows_error_message():
    status_message = json.dumps({"error": {"code": "QuotaExceeded", "message": "Not enough."}})
    events = [
        event("Microsoft.Compute/virtualMachines/write"),
        event(
            "Microsoft.Compute/virtualMachines/write",
            status="Failed",
            when="2025-01-02T11:00:00Z",
            properties={"statusMessage": status_message},
        ),
    ]
    rows = summarize_events(events, failed_only=True)
    assert len(rows) == 1
    assert rows[0]["error"] == "QuotaExceeded: Not enough."


def test_activity_command(run_azure, azure_session):
    events = [event("Microsoft.KeyVault/vaults/write"), event("Microsoft.Web/sites/delete")]
    azure_session.reply("GET", ACTIVITY_URL, {"json_data": {"value": events}})
    result = run_azure("activity", "-s", SUB, "--hours", "2", "-g", "rg1", "-o", "json")
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)) == 2
    url = unquote(azure_session.calls[0].url)
    assert f"/subscriptions/{SUB}{ACTIVITY_URL}" in url
    assert "resourceGroupName eq 'rg1'" in url
    assert "$select=" in url and ",properties" not in url


def test_activity_retries_without_select_on_bad_request(run_azure, azure_session):
    def handler(call):
        if "%24select" in call.url or "$select" in call.url:
            return {"status": 400, "json_data": {"error": {"code": "BadRequest", "message": "x"}}}
        return {"json_data": {"value": [event("Microsoft.Web/sites/write")]}}

    azure_session.reply("GET", ACTIVITY_URL, handler=handler)
    result = run_azure("activity", "-s", SUB, "-o", "json")
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)) == 1
    assert len(azure_session.calls) == 2


def test_activity_uses_default_subscription(run_azure, azure_session, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    azure_session.reply("GET", ACTIVITY_URL, {"json_data": {"value": []}})
    result = run_azure("activity", "--failed-only")
    assert result.exit_code == 0, result.output
    assert "No matching changes found." in result.stdout
    assert ",properties" in unquote(azure_session.calls[0].url)


def test_activity_rejects_conflicting_scopes(run_azure):
    result = run_azure("activity", "-s", SUB, "-g", "rg", "--resource-id", "/x")
    assert result.exit_code == 2
