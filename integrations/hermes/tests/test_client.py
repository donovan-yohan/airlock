from __future__ import annotations

import base64
import json
import struct
import threading
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hermes_plugin_airlock import client as client_module
from hermes_plugin_airlock.client import AirlockClient, AirlockError

REQUEST_ID = "req_" + "A" * 24
RECEIPT_ID = "rec_" + "B" * 24
DIGEST = "a" * 64


def page_cursor(request_id=REQUEST_ID):
    created_at = datetime(2026, 8, 15, 0, 0, tzinfo=UTC)
    raw = struct.pack(">qI", int(created_at.timestamp()), 0) + request_id.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def catalog():
    return {
        "version": "airlock.catalog/v1",
        "issued_at": "2026-08-15T00:00:00Z",
        "expires_at": "2026-08-15T01:00:00Z",
        "trusted_public_key": "must-not-leak",
        "signature": "must-not-leak",
        "capabilities": [
            {
                "id": "github:example-owner",
                "display_name": "GitHub owner authority",
                "actions": ["github.repo.add_collaborator"],
                "constraints": {
                    "owner": "example-owner",
                    "collaborator": "example-agent",
                    "permissions": ["pull", "push"],
                },
            }
        ],
    }


def receipt(decision="approved_for_manual_execution"):
    return {
        "version": "airlock.receipt/v1",
        "id": RECEIPT_ID,
        "request_id": REQUEST_ID,
        "request_digest": DIGEST,
        "decision": decision,
        "reviewer": "reviewer@example.invalid",
        "adapter_version": "github.repo.add_collaborator/v1",
        "created_at": "2026-08-15T00:01:00Z",
        "expires_at": "2026-08-15T01:01:00Z",
        "signature": "must-not-leak",
    }


def record(state="pending", receipts=None):
    return {
        "request": {
            "version": "airlock.request/v1",
            "id": REQUEST_ID,
            "capability_id": "github:example-owner",
            "action": "github.repo.add_collaborator",
            "arguments": {"repository": "demo", "permission": "push"},
            "reason": "allow contribution",
            "created_at": "2026-08-15T00:00:00Z",
            "expires_at": "2026-08-15T00:10:00Z",
            "nonce": "must-not-leak",
            "digest": DIGEST,
        },
        "state": state,
        "receipts": receipts,
    }


@contextmanager
def server(routes):
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _serve(self):
            body = b""
            if self.headers.get("Content-Length"):
                body = self.rfile.read(int(self.headers["Content-Length"]))
            captured.append((self.command, self.path, body))
            status, headers, payload = routes[(self.command, self.path)]
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _serve
        do_POST = _serve

    instance = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{instance.server_port}", captured
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def encoded(value):
    return {"Content-Type": "application/json"}, json.dumps(value).encode()


def test_catalog_and_records_are_sanitized():
    cat_headers, cat_body = encoded(catalog())
    rec_headers, rec_body = encoded(record())
    list_headers, list_body = encoded({"requests": [record()]})
    with server(
        {
            ("GET", "/api/v1/catalog"): (200, cat_headers, cat_body),
            ("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, rec_headers, rec_body),
            ("GET", "/api/v1/requests?limit=1"): (200, list_headers, list_body),
        }
    ) as (url, _captured):
        client = AirlockClient(url)
        got_catalog = client.capabilities()
        got_record = client.request_status(REQUEST_ID)
        got_list = client.list_requests(limit=1)

    serialized = json.dumps([got_catalog, got_record, got_list])
    assert "must-not-leak" not in serialized
    assert got_catalog["capabilities"][0]["constraints"]["owner"] == "example-owner"
    assert got_record["id"] == REQUEST_ID
    assert got_list[0]["state"] == "pending"


def test_state_filter_paginates_until_it_finds_matching_records():
    approved = record("approved", [receipt()])
    approved_id = "req_" + "C" * 24
    approved["request"]["id"] = approved_id
    approved["receipts"][0]["request_id"] = approved_id
    cursor = page_cursor()
    first_headers, first_body = encoded({"requests": [record()], "next_cursor": cursor})
    second_headers, second_body = encoded({"requests": [approved]})
    with server(
        {
            ("GET", "/api/v1/requests?limit=50"): (200, first_headers, first_body),
            ("GET", f"/api/v1/requests?limit=50&cursor={cursor}"): (
                200,
                second_headers,
                second_body,
            ),
        }
    ) as (url, captured):
        result = AirlockClient(url).list_requests(state="approved", limit=1)

    assert [item["id"] for item in result] == [approved_id]
    assert [path for _method, path, _body in captured] == [
        "/api/v1/requests?limit=50",
        f"/api/v1/requests?limit=50&cursor={cursor}",
    ]


def test_state_filter_rejects_a_repeated_page_cursor():
    cursor = page_cursor()
    headers, body = encoded({"requests": [record()], "next_cursor": cursor})
    routes = {
        ("GET", "/api/v1/requests?limit=50"): (200, headers, body),
        ("GET", f"/api/v1/requests?limit=50&cursor={cursor}"): (200, headers, body),
    }
    with server(routes) as (url, captured), pytest.raises(
        AirlockError, match="invalid page cursor"
    ):
        AirlockClient(url).list_requests(state="approved", limit=1)

    assert len(captured) == 2


def test_state_filter_rejects_a_malformed_page_cursor():
    headers, body = encoded({"requests": [record()], "next_cursor": REQUEST_ID})
    with server({("GET", "/api/v1/requests?limit=50"): (200, headers, body)}) as (
        url,
        _captured,
    ), pytest.raises(AirlockError, match="invalid page cursor"):
        AirlockClient(url).list_requests(state="approved", limit=1)


def test_catalog_expiry_is_derived_from_a_validated_rfc3339_window(monkeypatch):
    monkeypatch.setattr(
        client_module, "_utcnow", lambda: datetime(2026, 8, 15, 0, 30, tzinfo=UTC)
    )
    headers, body = encoded(catalog())
    with server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (url, _captured):
        got = AirlockClient(url).capabilities()
    assert got["expired"] is False


def test_receipts_are_validated_and_sanitized():
    headers, body = encoded(record("approved", [receipt()]))
    with server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
        url,
        _captured,
    ):
        got = AirlockClient(url).request_status(REQUEST_ID)
    assert got["receipts"][0]["decision"] == "approved_for_manual_execution"
    assert "must-not-leak" not in json.dumps(got)


def test_expiry_is_derived_from_rfc3339_for_requests_and_receipts(monkeypatch):
    value = record("approved", [receipt()])
    value["request"]["expires_at"] = "2026-08-15T00:10:00.123456789Z"
    value["receipts"][0]["expires_at"] = "2026-08-15T00:10:01+00:00"
    monkeypatch.setattr(
        client_module, "_utcnow", lambda: datetime(2026, 8, 15, 0, 10, 1, tzinfo=UTC)
    )
    headers, body = encoded(value)
    with server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
        url,
        _captured,
    ):
        got = AirlockClient(url).request_status(REQUEST_ID)
    assert got["expired"] is True
    assert got["receipts"][0]["expired"] is True


@pytest.mark.parametrize("field", ["created_at", "expires_at"])
def test_non_rfc3339_request_or_receipt_timestamps_are_rejected(field):
    malformed_request = record()
    malformed_request["request"][field] = "2026-08-15 00:00:00Z"
    malformed_receipt = record("approved", [receipt()])
    malformed_receipt["receipts"][0][field] = "not-a-timestamp"
    for value in (malformed_request, malformed_receipt):
        headers, body = encoded(value)
        with server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
            url,
            _captured,
        ), pytest.raises(AirlockError) as failure:
            AirlockClient(url).request_status(REQUEST_ID)
        assert failure.value.code == "invalid_response"


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_non_rfc3339_catalog_timestamps_are_rejected(field):
    value = catalog()
    value[field] = "2026-08-15 00:00:00Z"
    headers, body = encoded(value)
    with server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (
        url,
        _captured,
    ), pytest.raises(AirlockError) as failure:
        AirlockClient(url).capabilities()
    assert failure.value.code == "invalid_response"


@pytest.mark.parametrize(
    "payload,path",
    [
        (
            {**catalog(), "issued_at": "2026-08-15T01:00:00Z", "expires_at": "2026-08-15T00:00:00Z"},
            "/api/v1/catalog",
        ),
        (
            {**catalog(), "issued_at": "2026-08-15T03:00:00Z", "expires_at": "2026-08-15T04:00:00Z"},
            "/api/v1/catalog",
        ),
        (record(), f"/api/v1/requests/{REQUEST_ID}"),
        (record("approved", [receipt()]), f"/api/v1/requests/{REQUEST_ID}"),
    ],
)
def test_reversed_or_future_time_windows_are_rejected(monkeypatch, payload, path):
    monkeypatch.setattr(
        client_module, "_utcnow", lambda: datetime(2026, 8, 15, 0, 30, tzinfo=UTC)
    )
    if path != "/api/v1/catalog":
        target = payload["request"] if payload["receipts"] is None else payload["receipts"][0]
        if payload["receipts"] is None:
            target["created_at"] = "2026-08-15T01:00:00Z"
            target["expires_at"] = "2026-08-15T00:00:00Z"
        else:
            target["created_at"] = "2026-08-15T03:00:00Z"
            target["expires_at"] = "2026-08-15T04:00:00Z"
    headers, body = encoded(payload)
    with server({("GET", path): (200, headers, body)}) as (url, _captured), pytest.raises(
        AirlockError
    ) as failure:
        client = AirlockClient(url)
        if path == "/api/v1/catalog":
            client.capabilities()
        else:
            client.request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


def test_unsupported_receipt_is_rejected():
    headers, body = encoded(record("approved", [receipt("execute_shell")]))
    with server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
        url,
        _captured,
    ), pytest.raises(AirlockError) as failure:
        AirlockClient(url).request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


def test_create_request_posts_only_typed_fields():
    headers, body = encoded(record())
    with server({("POST", "/api/v1/requests"): (201, headers, body)}) as (url, captured):
        result = AirlockClient(url).create_request(
            capability_id="github:example-owner",
            action="github.repo.add_collaborator",
            repository="demo",
            permission="push",
            reason="allow contribution",
            ttl_seconds=600,
        )
    sent = json.loads(captured[0][2])
    assert result["state"] == "pending"
    assert sent == {
        "capability_id": "github:example-owner",
        "action": "github.repo.add_collaborator",
        "arguments": {"repository": "demo", "permission": "push"},
        "reason": "allow contribution",
        "ttl_seconds": 600,
    }
    assert "command" not in sent and "url" not in sent


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8787",
        "http://192.168.1.4:8787",
        "https://127.0.0.1:8787",
        "http://user:pass@127.0.0.1:8787",  # pragma: allowlist secret
        "http://127.0.0.1:8787/api",
        "http://127.0.0.1:8787?x=1",
        "http://127.0.0.1",
    ],
)
def test_endpoint_is_loopback_only(url):
    with pytest.raises(AirlockError, match="loopback|absolute"):
        AirlockClient(url)


def test_redirects_are_refused():
    with server(
        {
            ("GET", "/api/v1/catalog"): (
                302,
                {"Location": "/api/v1/requests"},
                b"",
            )
        }
    ) as (url, _captured), pytest.raises(AirlockError) as failure:
        AirlockClient(url).capabilities()
    assert failure.value.code == "redirect_refused"


@pytest.mark.parametrize("control", ["\x1b[31m", "\x7f", "\x9b31m"])
def test_requester_error_messages_never_expose_terminal_controls(control):
    headers, body = encoded({"error": f"unsafe {control} requester message"})
    with server({("GET", "/api/v1/catalog"): (400, headers, body)}) as (
        url,
        _captured,
    ), pytest.raises(AirlockError) as failure:
        AirlockClient(url).capabilities()
    assert failure.value.code == "request_rejected"
    assert failure.value.message == "Airlock requester rejected the request"
    assert all(not (ord(character) < 32 or 127 <= ord(character) <= 159) for character in failure.value.message)


def test_loopback_client_never_loads_environment_proxies(monkeypatch):
    def fail_if_loaded():
        raise AssertionError("environment proxy settings must not be loaded")

    monkeypatch.setattr(urllib.request, "getproxies", fail_if_loaded)
    AirlockClient("http://127.0.0.1:8787")


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf")])
def test_timeout_must_be_finite(timeout):
    with pytest.raises(AirlockError) as failure:
        AirlockClient("http://127.0.0.1:8787", timeout)
    assert failure.value.code == "invalid_config"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["capabilities"][0].update(actions=["shell.execute"]),
        lambda value: value["capabilities"][0]["constraints"].update(permissions=["admin"]),
        lambda value: value["capabilities"][0].update(display_name="bad\ninstruction"),
    ],
)
def test_unsupported_catalog_fields_are_rejected(mutate):
    value = catalog()
    mutate(value)
    headers, body = encoded(value)
    with server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (
        url,
        _captured,
    ), pytest.raises(AirlockError) as failure:
        AirlockClient(url).capabilities()
    assert failure.value.code == "invalid_response"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["request"]["arguments"].update(command="gh api ..."),
        lambda value: value["request"].update(action="shell.execute"),
        lambda value: value["request"].update(digest="not-a-digest"),
    ],
)
def test_unsupported_request_record_fields_are_rejected(mutate):
    value = record()
    mutate(value)
    headers, body = encoded(value)
    with server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
        url,
        _captured,
    ), pytest.raises(AirlockError) as failure:
        AirlockClient(url).request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "../owner/repo"),
        ("permission", "admin"),
        ("action", "shell.execute"),
        ("reason", "bad\nreason"),
    ],
)
def test_invalid_create_inputs_never_reach_network(field, value):
    params = {
        "capability_id": "github:example-owner",
        "action": "github.repo.add_collaborator",
        "repository": "demo",
        "permission": "push",
        "reason": "allow contribution",
        "ttl_seconds": 600,
    }
    params[field] = value
    with pytest.raises(AirlockError) as failure:
        AirlockClient("http://127.0.0.1:9", timeout_seconds=0.25).create_request(**params)
    assert failure.value.code == "invalid_input"
