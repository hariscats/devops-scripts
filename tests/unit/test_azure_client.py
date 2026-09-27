"""Tests for the shared Azure REST client."""

import base64
import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
import requests

from devops_tools.azure import client as client_module
from devops_tools.azure.client import (
    ARM_SCOPE,
    AzureClient,
    AzureError,
    _encode_params,
    _parse_hms,
    is_guid,
    parse_retry_after,
    token_claims,
)

SUB = "00000000-0000-0000-0000-000000000001"


class TestHelpers:
    def test_parse_retry_after_seconds(self):
        assert parse_retry_after("5") == 5.0
        assert parse_retry_after(" 2.5 ") == 2.5
        assert parse_retry_after("-3") == 0.0

    def test_parse_retry_after_http_date(self):
        now = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert parse_retry_after("Wed, 01 Jan 2025 12:00:30 GMT", now=now) == 30.0
        assert parse_retry_after("Wed, 01 Jan 2025 11:00:00 GMT", now=now) == 0.0

    @pytest.mark.parametrize("value", [None, "", "soon", "Mon, 99 Foo 2025"])
    def test_parse_retry_after_invalid(self, value):
        assert parse_retry_after(value) is None

    def test_parse_hms(self):
        assert _parse_hms("00:01:05") == 65.0
        assert _parse_hms("01:00:00.5") == 3600.0
        assert _parse_hms("later") is None

    def test_is_guid(self):
        assert is_guid(SUB)
        assert is_guid(SUB.upper())
        assert not is_guid("Production")

    def test_token_claims(self):
        payload = base64.urlsafe_b64encode(json.dumps({"oid": "abc"}).encode()).rstrip(b"=")
        assert token_claims(f"e30.{payload.decode()}.sig") == {"oid": "abc"}
        assert token_claims("not-a-jwt") == {}
        assert token_claims("a.!!!.c") == {}

    def test_encode_params_keeps_dollar_keys_and_quotes_values(self):
        query = _encode_params({"api-version": "2021-07-01", "$filter": "location eq 'x'"})
        assert query == "api-version=2021-07-01&$filter=location%20eq%20%27x%27"
        assert _encode_params({"a": None}) == ""


class TestRequest:
    def test_sends_bearer_token_to_arm(self, azure_client, azure_session):
        azure_session.reply("GET", "/subscriptions", {"json_data": {"value": []}})
        assert azure_client.get("/subscriptions", params={"api-version": "1"}) == {"value": []}
        call = azure_session.calls[0]
        assert call.url == "https://management.azure.com/subscriptions?api-version=1"
        assert call.headers["Authorization"] == "Bearer " + "fake-token"
        assert call.headers["Accept"] == "application/json"

    def test_rejects_non_https_urls(self, azure_client):
        with pytest.raises(ValueError):
            azure_client.get("http://management.azure.com/subscriptions")

    def test_retries_throttling_using_retry_after(self, azure_client, azure_session, sleeps):
        azure_session.reply(
            "GET",
            "/x",
            {"status": 429, "headers": {"Retry-After": "3"}},
            {"status": 503},
            {"json_data": {"ok": True}},
        )
        assert azure_client.get("/x") == {"ok": True}
        assert sleeps == [3.0, 2.0]  # Retry-After, then exponential backoff (1, 2, 4, ...)

    def test_retry_after_ms_and_quota_reset_headers(self, azure_client, azure_session, sleeps):
        azure_session.reply(
            "GET",
            "/x",
            {"status": 429, "headers": {"retry-after-ms": "1500", "Retry-After": "9"}},
            {"status": 429, "headers": {"x-ms-user-quota-resets-after": "00:00:04"}},
            {"json_data": {}},
        )
        azure_client.get("/x")
        assert sleeps == [1.5, 4.0]

    def test_retry_delay_is_capped(self, azure_session, azure_credential, sleeps):
        client = AzureClient(
            credential=azure_credential, session=azure_session, sleep=sleeps.append, max_backoff=10
        )
        azure_session.reply(
            "GET", "/x", {"status": 429, "headers": {"Retry-After": "3600"}}, {"json_data": {}}
        )
        client.get("/x")
        assert sleeps == [10.0]

    def test_gives_up_after_max_retries(self, azure_session, azure_credential, sleeps):
        client = AzureClient(
            credential=azure_credential, session=azure_session, sleep=sleeps.append, max_retries=2
        )
        azure_session.reply("GET", "/x", {"status": 500, "text": "boom"})
        with pytest.raises(AzureError) as err:
            client.get("/x")
        assert err.value.status == 500
        assert len(azure_session.calls) == 3
        assert len(sleeps) == 2

    def test_retries_connection_errors(self, azure_client, azure_session, sleeps):
        azure_session.reply(
            "GET", "/x", requests.ConnectionError("reset"), {"json_data": {"ok": 1}}
        )
        assert azure_client.get("/x") == {"ok": 1}
        assert sleeps == [1.0]

    def test_connection_error_after_retries_has_no_status(self, azure_session, azure_credential):
        client = AzureClient(
            credential=azure_credential, session=azure_session, sleep=lambda s: None, max_retries=1
        )
        azure_session.reply("GET", "/x", requests.Timeout("slow"))
        with pytest.raises(AzureError) as err:
            client.get("/x")
        assert err.value.status is None

    def test_refreshes_token_once_on_401(self, azure_client, azure_session, azure_credential):
        azure_session.reply("GET", "/x", {"status": 401}, {"json_data": {"ok": 1}})
        assert azure_client.get("/x") == {"ok": 1}
        assert azure_credential.scopes == [ARM_SCOPE, ARM_SCOPE]

    def test_second_401_raises(self, azure_client, azure_session):
        azure_session.reply("GET", "/x", {"status": 401, "text": "no"})
        with pytest.raises(AzureError) as err:
            azure_client.get("/x")
        assert err.value.status == 401
        assert len(azure_session.calls) == 2

    def test_arm_error_payload_is_readable(self, azure_client, azure_session):
        error = {
            "error": {
                "code": "InvalidTemplate",
                "message": "Bad request.",
                "details": [{"code": "Inner", "message": "Field x is wrong."}],
            }
        }
        azure_session.reply("GET", "/x", {"status": 400, "json_data": error})
        with pytest.raises(AzureError) as err:
            azure_client.get("/x?api-version=1")
        message = str(err.value)
        assert "HTTP 400" in message and "[InvalidTemplate]" in message
        assert "Bad request. Inner: Field x is wrong." in message
        assert "api-version" not in message
        assert err.value.code == "InvalidTemplate"

    def test_empty_and_non_json_bodies(self, azure_client, azure_session):
        azure_session.reply("GET", "/empty", {"status": 204})
        azure_session.reply("GET", "/html", {"text": "<html>"})
        assert azure_client.get("/empty") == {}
        with pytest.raises(AzureError):
            azure_client.get("/html")

    def test_token_is_cached_per_scope(self, azure_client, azure_session, azure_credential):
        azure_session.reply("GET", "/x", {"json_data": {}})
        azure_client.get("/x")
        azure_client.get("/x")
        azure_client.token("https://vault.azure.net/.default")
        assert azure_credential.scopes == [ARM_SCOPE, "https://vault.azure.net/.default"]

    def test_token_near_expiry_is_refreshed(self, fakes, azure_session):
        credential = fakes.FakeCredential(expires_in=60)  # inside the refresh margin
        client = AzureClient(credential=credential, session=azure_session)
        client.token()
        client.token()
        assert len(credential.scopes) == 2

    def test_retries_are_logged(self, azure_client, azure_session, caplog):
        azure_session.reply("GET", "/x", {"status": 503}, {"json_data": {}})
        with caplog.at_level(logging.WARNING, logger=client_module.__name__):
            azure_client.get("/x")
        assert "HTTP 503" in caplog.text


class TestPaging:
    def test_follows_next_link(self, azure_client, azure_session):
        azure_session.reply(
            "GET",
            "/items",
            handler=lambda call: {
                "json_data": (
                    {"value": [{"n": 2}]}
                    if "page=2" in call.url
                    else {
                        "value": [{"n": 1}],
                        "nextLink": "https://management.azure.com/items?page=2",
                    }
                )
            },
        )
        assert [i["n"] for i in azure_client.paged("/items")] == [1, 2]

    @pytest.mark.parametrize(
        "next_link", ["https://evil.example.com/items?page=2", "http://management.azure.com/x"]
    )
    def test_refuses_next_link_to_other_hosts(self, azure_client, azure_session, next_link):
        azure_session.reply("GET", "/items", {"json_data": {"value": [], "nextLink": next_link}})
        with pytest.raises(AzureError, match="nextLink"):
            list(azure_client.paged("/items"))

    def test_list_subscriptions_is_cached(self, azure_client, azure_session):
        azure_session.reply("GET", "/subscriptions", {"json_data": {"value": [{"id": 1}]}})
        assert azure_client.list_subscriptions() == [{"id": 1}]
        assert azure_client.list_subscriptions() == [{"id": 1}]
        assert len(azure_session.calls) == 1


class TestResourceGraph:
    def test_pages_with_skip_token(self, azure_client, azure_session, fakes):
        azure_session.reply(
            "POST",
            "Microsoft.ResourceGraph",
            fakes.arg_page([{"id": "a"}], skip_token="next"),
            fakes.arg_page([{"id": "b"}]),
        )
        rows = azure_client.resource_graph("Resources", subscriptions=[SUB])
        assert rows == [{"id": "a"}, {"id": "b"}]
        first, second = (call.json for call in azure_session.calls)
        assert first["subscriptions"] == [SUB]
        assert first["options"] == {"resultFormat": "objectArray", "$top": 1000}
        assert second["options"]["$skipToken"] == "next"
        assert "api-version=2024-04-01" in azure_session.calls[0].url

    def test_max_rows_limits_page_size_and_results(self, azure_client, azure_session, fakes):
        azure_session.reply(
            "POST", "Microsoft.ResourceGraph", fakes.arg_page([{"id": 1}, {"id": 2}], "more")
        )
        assert azure_client.resource_graph("Resources", max_rows=2) == [{"id": 1}, {"id": 2}]
        assert azure_session.calls[0].json["options"]["$top"] == 2
        assert len(azure_session.calls) == 1

    def test_management_groups(self, azure_client, azure_session, fakes):
        azure_session.reply("POST", "Microsoft.ResourceGraph", fakes.arg_page([]))
        azure_client.resource_graph("Resources", management_groups=["mg1"])
        assert azure_session.calls[0].json["managementGroups"] == ["mg1"]
        assert "subscriptions" not in azure_session.calls[0].json

    def test_warns_when_results_are_truncated(self, azure_client, azure_session, caplog):
        page = {"totalRecords": 5, "data": [{"n": 1}], "resultTruncated": "true"}
        azure_session.reply("POST", "Microsoft.ResourceGraph", {"json_data": page})
        with caplog.at_level(logging.WARNING, logger=client_module.__name__):
            assert azure_client.resource_graph("Resources | summarize count() by type")
        assert "1 of 5 rows" in caplog.text


def test_http_date_retry_after_end_to_end(azure_client, azure_session, sleeps):
    when = (datetime.now(timezone.utc) + timedelta(seconds=20)).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    azure_session.reply(
        "GET", "/x", {"status": 429, "headers": {"Retry-After": when}}, {"json_data": {}}
    )
    azure_client.get("/x")
    assert 15 <= sleeps[0] <= 20
