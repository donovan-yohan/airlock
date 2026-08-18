from __future__ import annotations

import base64
import io
import json
import struct
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime

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
        "version": "airlock.catalog/v2",
        "issued_at": "2026-08-15T00:00:00Z",
        "expires_at": "2026-08-15T01:00:00Z",
        "trusted_public_key": "must-not-leak",
        "signature": "must-not-leak",
        "profiles": [
            {
                "id": "github.command",
                "version": "v1",
                "display_name": "GitHub CLI command",
                "authority_label": "Broad GitHub authority",
                "sandbox_label": "Ephemeral private state",
                "network_label": "GitHub network",
                "cwd_label": "Ephemeral directory",
                "output_label": "Bounded sanitized trusted-local output preview",
                "limits": {
                    "max_argv_count": 64,
                    "max_argument_bytes": 4096,
                    "max_aggregate_bytes": 32768,
                },
            }
        ],
    }


def receipt(decision="approved_for_manual_execution"):
    version = "airlock.receipt/v1"
    if decision in {"approved_for_execution", "executed"}:
        version = "airlock.receipt/v3"
    value = {
        "version": version,
        "id": "rec_" + ("C" if decision == "executed" else "B") * 24,
        "request_id": REQUEST_ID,
        "request_digest": DIGEST,
        "decision": decision,
        "reviewer": "reviewer@example.invalid",
        "created_at": "2026-08-15T00:01:00Z",
        "expires_at": "2026-08-15T01:01:00Z",
        "signature": "must-not-leak",
    }
    if version == "airlock.receipt/v3":
        value.update(
            profile_id="github.command", profile_version="v1", plan_digest="b" * 64
        )
    else:
        value["adapter_version"] = "github.repo.add_collaborator/v1"
    return value


def record(state="pending", receipts=None):
    return {
        "request": {
            "version": "airlock.request/v2",
            "id": REQUEST_ID,
            "profile_id": "github.command",
            "profile_version": "v1",
            "argv": ["api", "--method", "POST", "repos/example/demo/issues"],
            "reason": "allow contribution",
            "created_at": "2026-08-15T00:00:00Z",
            "expires_at": "2026-08-15T00:10:00Z",
            "nonce": "must-not-leak",
            "digest": DIGEST,
        },
        "state": state,
        "receipts": receipts,
    }


def legacy_record(state="pending", receipts=None):
    value = record(state, receipts)
    request = value["request"]
    request["version"] = "airlock.request/v1"
    request["capability_id"] = "github:example-owner"
    request["action"] = "github.repo.add_collaborator"
    request["arguments"] = {"repository": "demo", "permission": "push"}
    for field in ("profile_id", "profile_version", "argv"):
        request.pop(field)
    return value


def test_client_accepts_v3_execution_receipts_and_rejects_mixed_versions():
    value = record(
        "executed",
        [receipt("approved_for_execution"), receipt("executed")],
    )
    assert client_module._sanitize_record(value)["state"] == "executed"
    mixed = receipt("executed")
    mixed["version"] = "airlock.receipt/v1"
    with pytest.raises(AirlockError, match="unsupported receipt"):
        client_module._sanitize_receipt(mixed)
    mixed["version"] = []
    with pytest.raises(AirlockError, match="unsupported receipt"):
        client_module._sanitize_receipt(mixed)


def test_receipt_history_rejects_binding_replay_state_and_plan_drift():
    cases = []
    misbound = record("approved_for_execution", [receipt("approved_for_execution")])
    misbound["receipts"][0]["request_digest"] = "c" * 64
    cases.append(misbound)
    replayed = record(
        "executed", [receipt("approved_for_execution"), receipt("executed")]
    )
    replayed["receipts"][1]["id"] = replayed["receipts"][0]["id"]
    cases.append(replayed)
    state_drift = record("pending", [receipt("approved_for_execution")])
    cases.append(state_drift)
    plan_drift = record(
        "executed", [receipt("approved_for_execution"), receipt("executed")]
    )
    plan_drift["receipts"][1]["plan_digest"] = "c" * 64
    cases.append(plan_drift)
    for value in cases:
        with pytest.raises(AirlockError):
            client_module._sanitize_record(value)


def test_historical_v1_request_and_v2_execution_receipts_remain_readable():
    approvals = []
    for index, decision in enumerate(("approved_for_execution", "executed")):
        value = receipt()
        value.update(
            version="airlock.receipt/v2",
            id="rec_" + chr(ord("C") + index) * 24,
            decision=decision,
            adapter_version="github.repo.add_collaborator/v1",
        )
        approvals.append(value)
    sanitized = client_module._sanitize_record(legacy_record("executed", approvals))
    assert sanitized["state"] == "executed"
    assert sanitized["historical_action"] == "github.repo.add_collaborator"
    assert [item["decision"] for item in sanitized["receipts"]] == [
        "approved_for_execution",
        "executed",
    ]


def test_raw_output_and_trusted_paths_are_never_projected():
    value = record("executed", [receipt("approved_for_execution"), receipt("executed")])
    value["raw_output"] = "private-output-canary"
    value["request"]["raw_output"] = "private-output-canary"
    value["receipts"][0]["stdout"] = "private-output-canary"
    value["receipts"][1]["credential_path"] = "/private/config/path"
    sanitized = client_module._sanitize_record(value)
    encoded_value = json.dumps(sanitized)
    assert "private-output-canary" not in encoded_value
    assert "/private/config/path" not in encoded_value


def test_mixed_current_and_historical_protocol_fields_fail_closed():
    mixed_request = record()
    mixed_request["request"]["action"] = "github.repo.add_collaborator"
    with pytest.raises(AirlockError, match="mixed command request"):
        client_module._sanitize_record(mixed_request)

    mixed_receipt = receipt("executed")
    mixed_receipt["adapter_version"] = "github.repo.add_collaborator/v1"
    with pytest.raises(AirlockError, match="mixed command receipt"):
        client_module._sanitize_receipt(mixed_receipt)


@contextmanager
def server(routes):
    captured = []

    class Response:
        def __init__(self, status, headers, payload):
            self.status = status
            self.headers = headers
            self._payload = io.BytesIO(payload)

        def read(self, size=-1):
            return self._payload.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Opener:
        def open(self, request, timeout):
            del timeout
            parsed = urllib.parse.urlsplit(request.full_url)
            target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            method = request.get_method()
            body = request.data or b""
            captured.append((method, target, body))
            status, headers, payload = routes[(method, target)]
            if status >= 300:
                raise urllib.error.HTTPError(
                    request.full_url,
                    status,
                    "synthetic response",
                    headers,
                    io.BytesIO(payload),
                )
            return Response(status, headers, payload)

    original = urllib.request.build_opener
    opener = Opener()
    urllib.request.build_opener = lambda *_handlers: opener
    try:
        yield "http://127.0.0.1:8787", captured
    finally:
        urllib.request.build_opener = original


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
    assert got_catalog["profiles"][0]["authority_label"] == "Broad GitHub authority"
    assert got_record["id"] == REQUEST_ID
    assert got_list[0]["state"] == "pending"


def test_duplicate_response_fields_fail_closed():
    headers = {"Content-Type": "application/json"}
    body = b'{"version":"airlock.catalog/v2","version":"airlock.catalog/v1"}'
    with (
        server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).capabilities()
    assert failure.value.code == "invalid_response"


def test_legacy_catalog_fails_closed_for_command_creation_client():
    value = catalog()
    value["version"] = "airlock.catalog/v1"
    value.pop("profiles")
    value["capabilities"] = []
    headers, body = encoded(value)
    with (
        server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).capabilities()
    assert failure.value.code == "invalid_response"


def test_state_filter_paginates_until_it_finds_matching_records():
    approved = legacy_record("approved", [receipt()])
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
    with (
        server(routes) as (url, captured),
        pytest.raises(AirlockError, match="invalid page cursor"),
    ):
        AirlockClient(url).list_requests(state="approved", limit=1)

    assert len(captured) == 2


def test_state_filter_rejects_a_malformed_page_cursor():
    headers, body = encoded({"requests": [record()], "next_cursor": REQUEST_ID})
    with (
        server({("GET", "/api/v1/requests?limit=50"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError, match="invalid page cursor"),
    ):
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
    headers, body = encoded(legacy_record("approved", [receipt()]))
    with server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
        url,
        _captured,
    ):
        got = AirlockClient(url).request_status(REQUEST_ID)
    assert got["receipts"][0]["decision"] == "approved_for_manual_execution"
    assert "must-not-leak" not in json.dumps(got)


def test_expiry_is_derived_from_rfc3339_for_requests_and_receipts(monkeypatch):
    value = legacy_record("approved", [receipt()])
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
    malformed_receipt = legacy_record("approved", [receipt()])
    malformed_receipt["receipts"][0][field] = "not-a-timestamp"
    for value in (malformed_request, malformed_receipt):
        headers, body = encoded(value)
        with (
            server(
                {("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}
            ) as (
                url,
                _captured,
            ),
            pytest.raises(AirlockError) as failure,
        ):
            AirlockClient(url).request_status(REQUEST_ID)
        assert failure.value.code == "invalid_response"


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_non_rfc3339_catalog_timestamps_are_rejected(field):
    value = catalog()
    value[field] = "2026-08-15 00:00:00Z"
    headers, body = encoded(value)
    with (
        server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).capabilities()
    assert failure.value.code == "invalid_response"


@pytest.mark.parametrize(
    "payload,path",
    [
        (
            {
                **catalog(),
                "issued_at": "2026-08-15T01:00:00Z",
                "expires_at": "2026-08-15T00:00:00Z",
            },
            "/api/v1/catalog",
        ),
        (
            {
                **catalog(),
                "issued_at": "2026-08-15T03:00:00Z",
                "expires_at": "2026-08-15T04:00:00Z",
            },
            "/api/v1/catalog",
        ),
        (record(), f"/api/v1/requests/{REQUEST_ID}"),
        (legacy_record("approved", [receipt()]), f"/api/v1/requests/{REQUEST_ID}"),
    ],
)
def test_reversed_or_future_time_windows_are_rejected(monkeypatch, payload, path):
    monkeypatch.setattr(
        client_module, "_utcnow", lambda: datetime(2026, 8, 15, 0, 30, tzinfo=UTC)
    )
    if path != "/api/v1/catalog":
        target = (
            payload["request"]
            if payload["receipts"] is None
            else payload["receipts"][0]
        )
        if payload["receipts"] is None:
            target["created_at"] = "2026-08-15T01:00:00Z"
            target["expires_at"] = "2026-08-15T00:00:00Z"
        else:
            target["created_at"] = "2026-08-15T03:00:00Z"
            target["expires_at"] = "2026-08-15T04:00:00Z"
    headers, body = encoded(payload)
    with (
        server({("GET", path): (200, headers, body)}) as (url, _captured),
        pytest.raises(AirlockError) as failure,
    ):
        client = AirlockClient(url)
        if path == "/api/v1/catalog":
            client.capabilities()
        else:
            client.request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


def test_unsupported_receipt_is_rejected():
    headers, body = encoded(legacy_record("approved", [receipt("execute_shell")]))
    with (
        server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


def test_create_request_posts_only_typed_fields():
    headers, body = encoded(record())
    with server({("POST", "/api/v1/requests"): (201, headers, body)}) as (
        url,
        captured,
    ):
        result = AirlockClient(url).create_request(
            profile_id="github.command",
            profile_version="v1",
            argv=["api", ";", "$(id)"],
            reason="allow contribution",
            ttl_seconds=600,
        )
    sent = json.loads(captured[0][2])
    assert result["state"] == "pending"
    assert sent == {
        "profile_id": "github.command",
        "profile_version": "v1",
        "argv": ["api", ";", "$(id)"],
        "reason": "allow contribution",
        "ttl_seconds": 600,
    }
    assert "executable" not in sent and "env" not in sent and "cwd" not in sent


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
    with (
        server(
            {
                ("GET", "/api/v1/catalog"): (
                    302,
                    {"Location": "/api/v1/requests"},
                    b"",
                )
            }
        ) as (url, _captured),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).capabilities()
    assert failure.value.code == "redirect_refused"


@pytest.mark.parametrize("control", ["\x1b[31m", "\x7f", "\x9b31m"])
def test_requester_error_messages_never_expose_terminal_controls(control):
    headers, body = encoded({"error": f"unsafe {control} requester message"})
    with (
        server({("GET", "/api/v1/catalog"): (400, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).capabilities()
    assert failure.value.code == "request_rejected"
    assert failure.value.message == "Airlock requester rejected the request"
    assert all(
        not (ord(character) < 32 or 127 <= ord(character) <= 159)
        for character in failure.value.message
    )


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
        lambda value: value["profiles"][0].update(id="shell.run"),
        lambda value: value["profiles"][0]["limits"].update(max_argv_count=65),
        lambda value: value["profiles"][0].update(display_name="bad\ninstruction"),
    ],
)
def test_unsupported_catalog_fields_are_rejected(mutate):
    value = catalog()
    mutate(value)
    headers, body = encoded(value)
    with (
        server({("GET", "/api/v1/catalog"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).capabilities()
    assert failure.value.code == "invalid_response"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["request"].update(argv=[]),
        lambda value: value["request"].update(profile_id="shell.run"),
        lambda value: value["request"].update(digest="not-a-digest"),
    ],
)
def test_unsupported_request_record_fields_are_rejected(mutate):
    value = record()
    mutate(value)
    headers, body = encoded(value)
    with (
        server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile_id", "shell.run"),
        ("profile_version", "v2"),
        ("argv", []),
        ("argv", ["api", "bad\nvalue"]),
        ("argv", ["api", "bad\x00value"]),
        ("argv", ["api", "\x1b[31mbad"]),
        ("argv", ["api", "safe\u202ebad"]),
        ("argv", ["api", "safe\u200bbad"]),
        ("argv", ["api", "safe\u200cbad"]),
        ("argv", ["api", "safe\u200dbad"]),
        ("argv", ["api", "safe\ufeffbad"]),
        ("argv", ["api", "safe\ufdd0bad"]),
        ("argv", ["api", "ghp_" + "a" * 24]),
        ("argv", ["api", "Authorization: Bearer " + "a" * 20]),
        ("argv", ["api", "https://operator:password@example.invalid"]),
        ("argv", ["api", "password=" + "a" * 12]),
        ("argv", ["api", "\ud800"]),
        ("argv", ["api", "x" * 4097]),
        ("argv", ["x" * 4096] * 9),
        ("reason", "bad\nreason"),
        ("reason", " \t "),
        ("reason", "Authorization: Bearer " + "a" * 20),
        ("reason", "review\u200bexact argv"),
    ],
)
def test_invalid_create_inputs_never_reach_network(field, value):
    params = {
        "profile_id": "github.command",
        "profile_version": "v1",
        "argv": ["api", "repos/example/demo"],
        "reason": "allow contribution",
        "ttl_seconds": 600,
    }
    params[field] = value
    with server({}) as (url, captured), pytest.raises(AirlockError) as failure:
        AirlockClient(url).create_request(**params)
    assert failure.value.code == "invalid_input"
    assert captured == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("argv", ["api", "Authorization: Bearer " + "a" * 20]),
        ("argv", ["api", "safe\u200bvalue"]),
        ("reason", "review\u200bexact argv"),
    ],
)
def test_invalid_current_requester_record_never_reaches_hermes_output(field, value):
    value_from_requester = record()
    value_from_requester["request"][field] = value
    headers, body = encoded(value_from_requester)
    with (
        server({("GET", f"/api/v1/requests/{REQUEST_ID}"): (200, headers, body)}) as (
            url,
            _captured,
        ),
        pytest.raises(AirlockError) as failure,
    ):
        AirlockClient(url).request_status(REQUEST_ID)
    assert failure.value.code == "invalid_response"


def test_historical_record_with_invisible_reason_remains_readable():
    historical = legacy_record()
    historical["request"]["reason"] = "historical\u200b record"
    assert client_module._sanitize_record(historical)["reason"] == "historical\u200b record"
