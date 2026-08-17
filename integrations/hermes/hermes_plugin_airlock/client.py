"""Bounded loopback HTTP client for the Airlock requester API."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

_MAX_RESPONSE_BYTES = 1 << 20
_MAX_REQUEST_BYTES = 64 << 10
_MAX_ERROR_CHARS = 300
_MAX_LIST_PAGES = 100
_MAX_PAGE_LIMIT = 50
_CAPABILITY_RE = re.compile(r"^[a-z0-9][a-z0-9:._-]{0,127}$")
_REQUEST_ID_RE = re.compile(r"^req_[A-Za-z0-9_-]{20,80}$")
_PAGE_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_RECEIPT_ID_RE = re.compile(r"^rec_[A-Za-z0-9_-]{20,80}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_GITHUB_USER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
_ALLOWED_STATES = {"pending", "approved", "denied", "manually_executed"}
_ALLOWED_DECISIONS = {"approved_for_manual_execution", "denied", "manually_executed"}
_ALLOWED_ACTION = "github.repo.add_collaborator"
_ADAPTER_VERSION = "github.repo.add_collaborator/v1"


@dataclass
class AirlockError(Exception):
    code: str
    message: str
    status: int | None = None

    def __str__(self) -> str:
        return self.message

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.status is not None:
            result["http_status"] = self.status
        return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AirlockError("redirect_refused", "Airlock requester redirects are refused", code)


class AirlockClient:
    def __init__(self, base_url: Any, timeout_seconds: Any = 5.0) -> None:
        self.base_url = _validate_base_url(base_url)
        if isinstance(timeout_seconds, bool):
            raise AirlockError("invalid_config", "timeout_seconds must be numeric")
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise AirlockError("invalid_config", "timeout_seconds must be numeric") from exc
        if not math.isfinite(timeout):
            raise AirlockError("invalid_config", "timeout_seconds must be finite")
        self.timeout_seconds = min(30.0, max(0.25, timeout))
        # Never let HTTP_PROXY/HTTPS_PROXY route loopback authority requests elsewhere.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def capabilities(self) -> dict[str, Any]:
        raw = self._request("/api/v1/catalog")
        capabilities = raw.get("capabilities")
        if raw.get("version") != "airlock.catalog/v1" or not isinstance(capabilities, list):
            raise AirlockError("invalid_response", "Requester returned an unsupported catalog")
        if not 1 <= len(capabilities) <= 64:
            raise AirlockError("invalid_response", "Requester returned an invalid capability count")
        issued_at = _response_string(raw.get("issued_at"), "issued_at", 40)
        expires_at = _response_string(raw.get("expires_at"), "expires_at", 40)
        return {
            "version": raw.get("version"),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "expired": _expired_window(issued_at, expires_at, "issued_at", "expires_at"),
            "capabilities": [_sanitize_capability(item) for item in capabilities],
        }

    def create_request(
        self,
        *,
        capability_id: Any,
        action: Any,
        repository: Any,
        permission: Any,
        reason: Any,
        ttl_seconds: Any,
    ) -> dict[str, Any]:
        capability_id = _validated_string(capability_id, "capability_id", 128)
        if not _CAPABILITY_RE.fullmatch(capability_id):
            raise AirlockError("invalid_input", "capability_id has an invalid format")
        action = _validated_string(action, "action", 128)
        if action != _ALLOWED_ACTION:
            raise AirlockError("invalid_input", "action is not supported by this plugin version")
        repository = _validated_string(repository, "repository", 100)
        if (
            not _REPOSITORY_RE.fullmatch(repository)
            or repository in {".", ".."}
            or ".." in repository
        ):
            raise AirlockError("invalid_input", "repository must be one conservative GitHub name")
        permission = _validated_string(permission, "permission", 8)
        if permission not in {"pull", "push"}:
            raise AirlockError("invalid_input", "permission must be pull or push")
        reason = _validated_string(reason, "reason", 512)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
            raise AirlockError("invalid_input", "ttl_seconds must be an integer")
        if not 60 <= ttl_seconds <= 3600:
            raise AirlockError("invalid_input", "ttl_seconds must be between 60 and 3600")
        raw = self._request(
            "/api/v1/requests",
            method="POST",
            payload={
                "capability_id": capability_id,
                "action": action,
                "arguments": {"repository": repository, "permission": permission},
                "reason": reason,
                "ttl_seconds": ttl_seconds,
            },
        )
        return _sanitize_record(raw)

    def request_status(self, request_id: Any) -> dict[str, Any]:
        request_id = _validated_string(request_id, "request_id", 84)
        if not _REQUEST_ID_RE.fullmatch(request_id):
            raise AirlockError("invalid_input", "request_id has an invalid format")
        quoted = urllib.parse.quote(request_id, safe="")
        return _sanitize_record(self._request(f"/api/v1/requests/{quoted}"))

    def list_requests(self, *, state: Any = None, limit: Any = 10) -> list[dict[str, Any]]:
        if state is not None:
            state = _validated_string(state, "state", 32)
            if state not in _ALLOWED_STATES:
                raise AirlockError("invalid_input", "state filter is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_PAGE_LIMIT:
            raise AirlockError(
                "invalid_input", f"limit must be an integer between 1 and {_MAX_PAGE_LIMIT}"
            )
        result: list[dict[str, Any]] = []
        cursor = ""
        seen_cursors: set[str] = set()
        # A state filter is applied client-side, so each page may yield nothing
        # matching; ask for full pages rather than just the caller's limit.
        page_limit = limit if state is None else _MAX_PAGE_LIMIT
        # The page cap is the one bound on a requester that keeps handing out
        # cursors, looping or otherwise.
        for _ in range(_MAX_LIST_PAGES):
            raw = self._request("/api/v1/requests", limit=page_limit, cursor=cursor)
            records = raw.get("requests")
            if not isinstance(records, list) or len(records) > page_limit:
                raise AirlockError("invalid_response", "Requester returned an invalid request list")
            for item in records:
                sanitized = _sanitize_record(item)
                if state is None or sanitized["state"] == state:
                    result.append(sanitized)
                if len(result) == limit:
                    return result
            next_cursor = raw.get("next_cursor", "")
            if next_cursor == "":
                return result
            if (
                not isinstance(next_cursor, str)
                or not _valid_page_cursor(next_cursor)
                or next_cursor in seen_cursors
            ):
                raise AirlockError("invalid_response", "Requester returned an invalid page cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise AirlockError("invalid_response", "Requester pagination exceeded the safety limit")

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        limit: int | None = None,
        cursor: str = "",
    ) -> dict[str, Any]:
        if not path.startswith("/api/v1/") or "?" in path or "#" in path:
            raise AirlockError("invalid_client_path", "Airlock client path is invalid")
        query_string = ""
        if limit is not None:
            query = {"limit": str(limit)}
            if cursor:
                query["cursor"] = cursor
            query_string = "?" + urllib.parse.urlencode(query)
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if len(body) > _MAX_REQUEST_BYTES:
                raise AirlockError("invalid_input", "Airlock request payload is too large")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path + query_string,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                data = _read_json(response)
        except AirlockError:
            raise
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise AirlockError(
                    "redirect_refused", "Airlock requester redirects are refused", exc.code
                ) from exc
            error_body = _read_error_body(exc)
            raise AirlockError("request_rejected", error_body, exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AirlockError(
                "service_unavailable",
                "Local Airlock requester is unavailable or timed out",
            ) from exc
        if not isinstance(data, dict):
            raise AirlockError("invalid_response", "Requester JSON response must be an object")
        return data


def _validate_base_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise AirlockError("invalid_config", "requester_url must be a non-empty string")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise AirlockError("invalid_config", "requester_url is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or port is None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AirlockError(
            "invalid_config",
            "requester_url must be an absolute loopback HTTP URL with an explicit port and no path",
        )
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise AirlockError(
            "invalid_config", "requester_url must use a loopback IP literal, not a hostname"
        ) from exc
    if not address.is_loopback:
        raise AirlockError("invalid_config", "requester_url must remain on loopback")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{host}:{port}"


def _valid_page_cursor(value: str) -> bool:
    if not _PAGE_CURSOR_RE.fullmatch(value):
        return False
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
        request_id = raw[12:].decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    if len(raw) <= 12 or int.from_bytes(raw[8:12], "big") >= 1_000_000_000:
        return False
    return _REQUEST_ID_RE.fullmatch(request_id) is not None


def _read_json(response: Any) -> Any:
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise AirlockError("invalid_response", "Requester response exceeded the size limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AirlockError("invalid_response", "Requester returned invalid JSON") from exc


def _read_error_body(response: Any) -> str:
    try:
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            return "Airlock requester rejected the request"
        data = json.loads(raw)
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            return _bounded_message(data["error"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return "Airlock requester rejected the request"
    return "Airlock requester rejected the request"


def _bounded_message(value: str) -> str:
    if _has_terminal_controls(value):
        return "Airlock requester rejected the request"
    clean = " ".join(value.split())
    return clean[:_MAX_ERROR_CHARS] or "Airlock requester rejected the request"


def _validated_string(value: Any, name: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > max_bytes:
        raise AirlockError("invalid_input", f"{name} has an invalid length")
    if _has_terminal_controls(value):
        raise AirlockError("invalid_input", f"{name} contains control characters")
    return value


def _string_list(value: Any, field: str, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise AirlockError("invalid_response", f"Requester response has invalid {field}")
    return [_response_string(item, field, 128) for item in value]


def _response_string(value: Any, field: str, max_bytes: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > max_bytes
        or _has_terminal_controls(value)
    ):
        raise AirlockError("invalid_response", f"Requester response has invalid {field}")
    return value


def _has_terminal_controls(value: str) -> bool:
    """Reject C0, DEL, and C1 terminal controls, including ANSI introducers."""

    return any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _rfc3339_timestamp(value: Any, field: str) -> datetime:
    timestamp = _response_string(value, field, 40)
    match = _RFC3339_RE.fullmatch(timestamp)
    if match is None:
        raise AirlockError("invalid_response", f"Requester response has invalid {field}")
    fraction = (match.group("fraction") or "")[:7]
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    try:
        return datetime.fromisoformat(f"{match.group('date')}{fraction}{zone}").astimezone(UTC)
    except ValueError as exc:
        raise AirlockError("invalid_response", f"Requester response has invalid {field}") from exc


def _expired_window(created_raw: str, expires_raw: str, created_field: str, expires_field: str) -> bool:
    created = _rfc3339_timestamp(created_raw, created_field)
    expires = _rfc3339_timestamp(expires_raw, expires_field)
    now = _utcnow()
    if expires <= created or created > now + timedelta(minutes=2):
        raise AirlockError("invalid_response", "Requester response has an invalid time window")
    return expires <= now


def _sanitize_capability(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AirlockError("invalid_response", "Requester returned an invalid capability")
    constraints = value.get("constraints")
    if not isinstance(constraints, dict):
        raise AirlockError("invalid_response", "Requester returned invalid capability constraints")
    capability_id = _response_string(value.get("id"), "capability id", 128)
    actions = _string_list(value.get("actions"), "actions")
    owner = _response_string(constraints.get("owner"), "owner", 39)
    collaborator = _response_string(constraints.get("collaborator"), "collaborator", 39)
    permissions = _string_list(constraints.get("permissions"), "permissions", 2)
    if (
        not _CAPABILITY_RE.fullmatch(capability_id)
        or actions != [_ALLOWED_ACTION]
        or not _GITHUB_USER_RE.fullmatch(owner)
        or not _GITHUB_USER_RE.fullmatch(collaborator)
        or not permissions
        or any(permission not in {"pull", "push"} for permission in permissions)
        or permissions != sorted(set(permissions))
    ):
        raise AirlockError("invalid_response", "Requester returned an unsupported capability")
    return {
        "id": capability_id,
        "display_name": _response_string(value.get("display_name"), "display name", 100),
        "actions": actions,
        "constraints": {
            "owner": owner,
            "collaborator": collaborator,
            "permissions": permissions,
        },
    }


def _sanitize_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AirlockError("invalid_response", "Requester returned an invalid request record")
    request = value.get("request")
    receipts = value.get("receipts")
    state = value.get("state")
    if receipts is None:
        receipts = []
    if not isinstance(request, dict) or not isinstance(receipts, list) or state not in _ALLOWED_STATES:
        raise AirlockError("invalid_response", "Requester returned a malformed request record")
    arguments = request.get("arguments")
    if not isinstance(arguments, dict) or set(arguments) != {"repository", "permission"}:
        raise AirlockError("invalid_response", "Requester returned invalid request arguments")
    request_id = _response_string(request.get("id"), "request id", 84)
    digest = _response_string(request.get("digest"), "request digest", 64)
    capability_id = _response_string(request.get("capability_id"), "capability id", 128)
    action = _response_string(request.get("action"), "action", 128)
    repository = _response_string(arguments.get("repository"), "repository", 100)
    permission = _response_string(arguments.get("permission"), "permission", 8)
    if (
        request.get("version") != "airlock.request/v1"
        or not _REQUEST_ID_RE.fullmatch(request_id)
        or not _DIGEST_RE.fullmatch(digest)
        or not _CAPABILITY_RE.fullmatch(capability_id)
        or action != _ALLOWED_ACTION
        or not _REPOSITORY_RE.fullmatch(repository)
        or repository in {".", ".."}
        or ".." in repository
        or permission not in {"pull", "push"}
    ):
        raise AirlockError("invalid_response", "Requester returned an unsupported request record")
    created_at = _response_string(request.get("created_at"), "created_at", 40)
    expires_at = _response_string(request.get("expires_at"), "expires_at", 40)
    expired = _expired_window(created_at, expires_at, "created_at", "expires_at")
    return {
        "id": request_id,
        "state": state,
        "digest": digest,
        "capability_id": capability_id,
        "action": action,
        "arguments": {"repository": repository, "permission": permission},
        "reason": _response_string(request.get("reason"), "reason", 512),
        "created_at": created_at,
        "expires_at": expires_at,
        "expired": expired,
        "receipts": [_sanitize_receipt(item) for item in receipts],
    }


def _sanitize_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AirlockError("invalid_response", "Requester returned an invalid receipt")
    receipt_id = _response_string(value.get("id"), "receipt id", 84)
    decision = _response_string(value.get("decision"), "receipt decision", 64)
    adapter_version = _response_string(value.get("adapter_version"), "adapter version", 128)
    if (
        value.get("version") != "airlock.receipt/v1"
        or not _RECEIPT_ID_RE.fullmatch(receipt_id)
        or decision not in _ALLOWED_DECISIONS
        or adapter_version != _ADAPTER_VERSION
    ):
        raise AirlockError("invalid_response", "Requester returned an unsupported receipt")
    created_at = _response_string(value.get("created_at"), "receipt created_at", 40)
    expires_at = _response_string(value.get("expires_at"), "receipt expires_at", 40)
    expired = _expired_window(
        created_at, expires_at, "receipt created_at", "receipt expires_at"
    )
    return {
        "id": receipt_id,
        "decision": decision,
        "reviewer": _response_string(value.get("reviewer"), "reviewer", 254),
        "adapter_version": adapter_version,
        "created_at": created_at,
        "expires_at": expires_at,
        "expired": expired,
    }
