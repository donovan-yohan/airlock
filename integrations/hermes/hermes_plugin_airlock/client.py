"""Bounded loopback HTTP client for the Airlock requester API."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
import unicodedata
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
_REQUEST_ID_RE = re.compile(r"^req_[A-Za-z0-9_-]{20,80}$")
_PAGE_CURSOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_RECEIPT_ID_RE = re.compile(r"^rec_[A-Za-z0-9_-]{20,80}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
_ALLOWED_STATES = {
    "pending",
    "approved",
    "approved_for_execution",
    "denied",
    "manually_executed",
    "executed",
}
_RECEIPT_DECISIONS = {
    "airlock.receipt/v1": frozenset(
        {"approved_for_manual_execution", "denied", "manually_executed"}
    ),
    "airlock.receipt/v2": frozenset({"approved_for_execution", "denied", "executed"}),
    "airlock.receipt/v3": frozenset({"approved_for_execution", "denied", "executed"}),
}
_PROFILE_ID = "github.command"
_PROFILE_VERSION = "v1"
_ADAPTER_VERSION = "github.repo.add_collaborator/v1"
_LIKELY_CREDENTIAL_PATTERNS = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[A-Z0-9+/=\r\n-]*-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|token|basic)\s+[A-Za-z0-9._~+/=-]{8,}\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s@]+@", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*\S{8,}",
        re.IGNORECASE,
    ),
    re.compile(r"\b[A-Za-z0-9_-]{80,}\b"),
)


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
        raise AirlockError(
            "redirect_refused", "Airlock requester redirects are refused", code
        )


class AirlockClient:
    def __init__(self, base_url: Any, timeout_seconds: Any = 5.0) -> None:
        self.base_url = _validate_base_url(base_url)
        if isinstance(timeout_seconds, bool):
            raise AirlockError("invalid_config", "timeout_seconds must be numeric")
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise AirlockError(
                "invalid_config", "timeout_seconds must be numeric"
            ) from exc
        if not math.isfinite(timeout):
            raise AirlockError("invalid_config", "timeout_seconds must be finite")
        self.timeout_seconds = min(30.0, max(0.25, timeout))
        # Never let HTTP_PROXY/HTTPS_PROXY route loopback authority requests elsewhere.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def capabilities(self) -> dict[str, Any]:
        raw = self._request("/api/v1/catalog")
        profiles = raw.get("profiles")
        if raw.get("version") != "airlock.catalog/v2" or not isinstance(profiles, list):
            raise AirlockError(
                "invalid_response", "Requester returned an unsupported catalog"
            )
        if not 1 <= len(profiles) <= 16:
            raise AirlockError(
                "invalid_response", "Requester returned an invalid profile count"
            )
        issued_at = _response_string(raw.get("issued_at"), "issued_at", 40)
        expires_at = _response_string(raw.get("expires_at"), "expires_at", 40)
        return {
            "version": raw.get("version"),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "expired": _expired_window(
                issued_at, expires_at, "issued_at", "expires_at"
            ),
            "profiles": [_sanitize_profile(item) for item in profiles],
        }

    def create_request(
        self,
        *,
        profile_id: Any,
        profile_version: Any,
        argv: Any,
        reason: Any,
        ttl_seconds: Any,
    ) -> dict[str, Any]:
        profile_id = _validated_string(profile_id, "profile_id", 64)
        profile_version = _validated_string(profile_version, "profile_version", 8)
        if profile_id != _PROFILE_ID or profile_version != _PROFILE_VERSION:
            raise AirlockError(
                "invalid_input", "profile is not supported by this plugin version"
            )
        if not isinstance(argv, list) or not 1 <= len(argv) <= 64:
            raise AirlockError(
                "invalid_input", "argv must contain between 1 and 64 elements"
            )
        argv = [
            _validated_command_string(item, f"argv[{index}]", 4096)
            for index, item in enumerate(argv)
        ]
        if sum(_utf8_length(item) for item in argv) > 32768:
            raise AirlockError("invalid_input", "argv aggregate bytes exceed 32768")
        reason = _validated_command_string(reason, "reason", 512)
        if not reason.strip():
            raise AirlockError("invalid_input", "reason must not be blank")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
            raise AirlockError("invalid_input", "ttl_seconds must be an integer")
        if not 60 <= ttl_seconds <= 3600:
            raise AirlockError(
                "invalid_input", "ttl_seconds must be between 60 and 3600"
            )
        raw = self._request(
            "/api/v1/requests",
            method="POST",
            payload={
                "profile_id": profile_id,
                "profile_version": profile_version,
                "argv": argv,
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

    def list_requests(
        self, *, state: Any = None, limit: Any = 10
    ) -> list[dict[str, Any]]:
        if state is not None:
            state = _validated_string(state, "state", 32)
            if state not in _ALLOWED_STATES:
                raise AirlockError("invalid_input", "state filter is invalid")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_PAGE_LIMIT
        ):
            raise AirlockError(
                "invalid_input",
                f"limit must be an integer between 1 and {_MAX_PAGE_LIMIT}",
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
                raise AirlockError(
                    "invalid_response", "Requester returned an invalid request list"
                )
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
                raise AirlockError(
                    "invalid_response", "Requester returned an invalid page cursor"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise AirlockError(
            "invalid_response", "Requester pagination exceeded the safety limit"
        )

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
            body = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            if len(body) > _MAX_REQUEST_BYTES:
                raise AirlockError(
                    "invalid_input", "Airlock request payload is too large"
                )
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
                    "redirect_refused",
                    "Airlock requester redirects are refused",
                    exc.code,
                ) from exc
            error_body = _read_error_body(exc)
            raise AirlockError("request_rejected", error_body, exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AirlockError(
                "service_unavailable",
                "Local Airlock requester is unavailable or timed out",
            ) from exc
        if not isinstance(data, dict):
            raise AirlockError(
                "invalid_response", "Requester JSON response must be an object"
            )
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
            "invalid_config",
            "requester_url must use a loopback IP literal, not a hostname",
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
        raise AirlockError(
            "invalid_response", "Requester response exceeded the size limit"
        )
    try:
        return _strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AirlockError(
            "invalid_response", "Requester returned invalid JSON"
        ) from exc


def _read_error_body(response: Any) -> str:
    try:
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            return "Airlock requester rejected the request"
        data = _strict_json_loads(raw)
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            return _bounded_message(data["error"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return "Airlock requester rejected the request"
    return "Airlock requester rejected the request"


def _bounded_message(value: str) -> str:
    if _has_terminal_controls(value):
        return "Airlock requester rejected the request"
    clean = " ".join(value.split())
    return clean[:_MAX_ERROR_CHARS] or "Airlock requester rejected the request"


def _strict_json_loads(raw: bytes) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=reject_duplicate_keys)


def _validated_string(value: Any, name: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value or _utf8_length(value) > max_bytes:
        raise AirlockError("invalid_input", f"{name} has an invalid length")
    if _has_terminal_controls(value):
        raise AirlockError("invalid_input", f"{name} contains control characters")
    return value


def _response_string(value: Any, field: str, max_bytes: int) -> str:
    try:
        length = len(value.encode("utf-8")) if isinstance(value, str) else -1
    except UnicodeEncodeError:
        length = -1
    if (
        not isinstance(value, str)
        or not value
        or length < 0
        or length > max_bytes
        or _has_terminal_controls(value)
    ):
        raise AirlockError(
            "invalid_response", f"Requester response has invalid {field}"
        )
    return value


def _validated_command_string(value: Any, name: str, max_bytes: int) -> str:
    value = _validated_string(value, name, max_bytes)
    if _has_invisible_format_or_noncharacter(value):
        raise AirlockError(
            "invalid_input", f"{name} contains invisible format characters"
        )
    if _contains_likely_credential(value):
        raise AirlockError(
            "invalid_input", f"{name} appears to contain credential material"
        )
    return value


def _response_command_string(value: Any, field: str, max_bytes: int) -> str:
    value = _response_string(value, field, max_bytes)
    if _has_invisible_format_or_noncharacter(value) or _contains_likely_credential(
        value
    ):
        raise AirlockError(
            "invalid_response", f"Requester response has invalid {field}"
        )
    return value


def _has_terminal_controls(value: str) -> bool:
    """Reject C0, DEL, and C1 terminal controls, including ANSI introducers."""

    bidi = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
    return any(
        ord(character) < 32 or 127 <= ord(character) <= 159 or ord(character) in bidi
        for character in value
    )


def _has_invisible_format_or_noncharacter(value: str) -> bool:
    return any(
        (0xFDD0 <= ord(character) <= 0xFDEF)
        or (ord(character) <= 0x10FFFF and ord(character) & 0xFFFE == 0xFFFE)
        or unicodedata.category(character) == "Cf"
        for character in value
    )


def _contains_likely_credential(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in _LIKELY_CREDENTIAL_PATTERNS)


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise AirlockError("invalid_input", "text contains invalid Unicode") from exc


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _rfc3339_timestamp(value: Any, field: str) -> datetime:
    timestamp = _response_string(value, field, 40)
    match = _RFC3339_RE.fullmatch(timestamp)
    if match is None:
        raise AirlockError(
            "invalid_response", f"Requester response has invalid {field}"
        )
    fraction = (match.group("fraction") or "")[:7]
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    try:
        return datetime.fromisoformat(
            f"{match.group('date')}{fraction}{zone}"
        ).astimezone(UTC)
    except ValueError as exc:
        raise AirlockError(
            "invalid_response", f"Requester response has invalid {field}"
        ) from exc


def _expired_window(
    created_raw: str, expires_raw: str, created_field: str, expires_field: str
) -> bool:
    created = _rfc3339_timestamp(created_raw, created_field)
    expires = _rfc3339_timestamp(expires_raw, expires_field)
    now = _utcnow()
    if expires <= created or created > now + timedelta(minutes=2):
        raise AirlockError(
            "invalid_response", "Requester response has an invalid time window"
        )
    return expires <= now


def _sanitize_profile(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AirlockError("invalid_response", "Requester returned an invalid profile")
    if set(value) != {
        "id",
        "version",
        "display_name",
        "authority_label",
        "sandbox_label",
        "network_label",
        "cwd_label",
        "output_label",
        "limits",
    }:
        raise AirlockError(
            "invalid_response", "Requester returned ambiguous profile fields"
        )
    limits = value.get("limits")
    if not isinstance(limits, dict) or limits != {
        "max_argv_count": 64,
        "max_argument_bytes": 4096,
        "max_aggregate_bytes": 32768,
    }:
        raise AirlockError(
            "invalid_response", "Requester returned invalid profile limits"
        )
    profile_id = _response_string(value.get("id"), "profile id", 64)
    profile_version = _response_string(value.get("version"), "profile version", 8)
    if (profile_id, profile_version) != (
        _PROFILE_ID,
        _PROFILE_VERSION,
    ):
        raise AirlockError(
            "invalid_response", "Requester returned an unsupported profile"
        )
    return {
        "id": profile_id,
        "version": profile_version,
        "display_name": _response_string(
            value.get("display_name"), "display name", 100
        ),
        "authority_label": _response_string(
            value.get("authority_label"), "authority label", 200
        ),
        "sandbox_label": _response_string(
            value.get("sandbox_label"), "sandbox label", 200
        ),
        "network_label": _response_string(
            value.get("network_label"), "network label", 200
        ),
        "cwd_label": _response_string(value.get("cwd_label"), "cwd label", 200),
        "output_label": _response_string(
            value.get("output_label"), "output label", 200
        ),
        "limits": limits,
    }


def _sanitize_record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AirlockError(
            "invalid_response", "Requester returned an invalid request record"
        )
    request = value.get("request")
    receipts = value.get("receipts")
    state = value.get("state")
    if receipts is None:
        receipts = []
    if (
        not isinstance(request, dict)
        or not isinstance(receipts, list)
        or state not in _ALLOWED_STATES
    ):
        raise AirlockError(
            "invalid_response", "Requester returned a malformed request record"
        )
    request_id = _response_string(request.get("id"), "request id", 84)
    digest = _response_string(request.get("digest"), "request digest", 64)
    if not _REQUEST_ID_RE.fullmatch(request_id) or not _DIGEST_RE.fullmatch(digest):
        raise AirlockError(
            "invalid_response", "Requester returned an unsupported request record"
        )
    created_at = _response_string(request.get("created_at"), "created_at", 40)
    expires_at = _response_string(request.get("expires_at"), "expires_at", 40)
    expired = _expired_window(created_at, expires_at, "created_at", "expires_at")
    request_version = request.get("version")
    sanitized_receipts = [
        _sanitize_receipt(item, request_id=request_id, request_digest=digest)
        for item in receipts
    ]
    if request_version == "airlock.request/v2" and any(
        item.get("version") != "airlock.receipt/v3" for item in receipts
    ):
        raise AirlockError(
            "invalid_response", "Requester returned mixed command protocol versions"
        )
    if request_version == "airlock.request/v1" and any(
        item.get("version") == "airlock.receipt/v3" for item in receipts
    ):
        raise AirlockError(
            "invalid_response", "Requester returned mixed historical protocol versions"
        )
    _validate_receipt_history(
        sanitized_receipts,
        state=state,
        request_created_at=created_at,
        request_expires_at=expires_at,
    )
    if request_version == "airlock.request/v2":
        reason = _response_command_string(request.get("reason"), "reason", 512)
    else:
        reason = _response_string(request.get("reason"), "reason", 512)
    result = {
        "id": request_id,
        "state": state,
        "digest": digest,
        "reason": reason,
        "created_at": created_at,
        "expires_at": expires_at,
        "expired": expired,
        "receipts": sanitized_receipts,
    }
    if request_version == "airlock.request/v2":
        if any(field in request for field in ("capability_id", "action", "arguments")):
            raise AirlockError(
                "invalid_response", "Requester returned mixed command request fields"
            )
        profile_id = _response_string(request.get("profile_id"), "profile id", 64)
        profile_version = _response_string(
            request.get("profile_version"), "profile version", 8
        )
        argv = request.get("argv")
        if (
            (profile_id, profile_version) != (_PROFILE_ID, _PROFILE_VERSION)
            or not isinstance(argv, list)
            or not 1 <= len(argv) <= 64
        ):
            raise AirlockError(
                "invalid_response", "Requester returned unsupported command argv"
            )
        argv = [_response_command_string(item, f"argv[{index}]", 4096) for index, item in enumerate(argv)]
        if sum(_utf8_length(item) for item in argv) > 32768:
            raise AirlockError(
                "invalid_response", "Requester returned oversized command argv"
            )
        result.update(
            {"profile_id": profile_id, "profile_version": profile_version, "argv": argv}
        )
    elif request_version == "airlock.request/v1":
        if any(field in request for field in ("profile_id", "profile_version", "argv")):
            raise AirlockError(
                "invalid_response", "Requester returned mixed historical request fields"
            )
        arguments = request.get("arguments")
        if not isinstance(arguments, dict) or set(arguments) != {
            "repository",
            "permission",
        }:
            raise AirlockError(
                "invalid_response", "Requester returned invalid historical arguments"
            )
        result.update(
            {
                "historical_capability_id": _response_string(
                    request.get("capability_id"), "capability id", 128
                ),
                "historical_action": _response_string(
                    request.get("action"), "action", 128
                ),
                "historical_arguments": {
                    "repository": _response_string(
                        arguments.get("repository"), "repository", 100
                    ),
                    "permission": _response_string(
                        arguments.get("permission"), "permission", 8
                    ),
                },
            }
        )
    else:
        raise AirlockError(
            "invalid_response", "Requester returned an unsupported request version"
        )
    return result


def _sanitize_receipt(
    value: Any, *, request_id: str | None = None, request_digest: str | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AirlockError("invalid_response", "Requester returned an invalid receipt")
    receipt_id = _response_string(value.get("id"), "receipt id", 84)
    decision = _response_string(value.get("decision"), "receipt decision", 64)
    version = value.get("version")
    allowed_decisions = (
        _RECEIPT_DECISIONS.get(version) if isinstance(version, str) else None
    )
    if (
        allowed_decisions is None
        or not _RECEIPT_ID_RE.fullmatch(receipt_id)
        or decision not in allowed_decisions
    ):
        raise AirlockError(
            "invalid_response", "Requester returned an unsupported receipt"
        )
    if request_id is not None:
        bound_id = _response_string(value.get("request_id"), "receipt request id", 84)
        bound_digest = _response_string(
            value.get("request_digest"), "receipt request digest", 64
        )
        if bound_id != request_id or bound_digest != request_digest:
            raise AirlockError(
                "invalid_response", "Requester returned a misbound receipt"
            )
    created_at = _response_string(value.get("created_at"), "receipt created_at", 40)
    expires_at = _response_string(value.get("expires_at"), "receipt expires_at", 40)
    expired = _expired_window(
        created_at, expires_at, "receipt created_at", "receipt expires_at"
    )
    result = {
        "id": receipt_id,
        "decision": decision,
        "reviewer": _response_string(value.get("reviewer"), "reviewer", 254),
        "created_at": created_at,
        "expires_at": expires_at,
        "expired": expired,
    }
    if version == "airlock.receipt/v3":
        if "adapter_version" in value:
            raise AirlockError(
                "invalid_response", "Requester returned mixed command receipt fields"
            )
        if (
            value.get("profile_id") != _PROFILE_ID
            or value.get("profile_version") != _PROFILE_VERSION
        ):
            raise AirlockError(
                "invalid_response", "Requester returned an unsupported command receipt"
            )
        plan_digest = _response_string(value.get("plan_digest"), "plan digest", 64)
        if not _DIGEST_RE.fullmatch(plan_digest):
            raise AirlockError(
                "invalid_response", "Requester returned an invalid plan digest"
            )
        result.update(
            {
                "profile_id": _PROFILE_ID,
                "profile_version": _PROFILE_VERSION,
                "plan_digest": plan_digest,
            }
        )
    else:
        if any(
            field in value for field in ("profile_id", "profile_version", "plan_digest")
        ):
            raise AirlockError(
                "invalid_response", "Requester returned mixed legacy receipt fields"
            )
        adapter_version = _response_string(
            value.get("adapter_version"), "adapter version", 128
        )
        if adapter_version != _ADAPTER_VERSION:
            raise AirlockError(
                "invalid_response", "Requester returned an unsupported legacy receipt"
            )
        result["adapter_version"] = adapter_version
    return result


def _validate_receipt_history(
    receipts: list[dict[str, Any]],
    *,
    state: str,
    request_created_at: str,
    request_expires_at: str,
) -> None:
    derived_state = "pending"
    request_created = _rfc3339_timestamp(request_created_at, "created_at")
    request_expires = _rfc3339_timestamp(request_expires_at, "expires_at")
    previous_created: datetime | None = None
    seen_ids: set[str] = set()
    for index, receipt in enumerate(receipts):
        created = _rfc3339_timestamp(receipt["created_at"], "receipt created_at")
        if (
            receipt["id"] in seen_ids
            or created < request_created
            or created >= request_expires
            or (previous_created is not None and created < previous_created)
        ):
            raise AirlockError(
                "invalid_response", "Requester returned invalid receipt history"
            )
        seen_ids.add(receipt["id"])
        previous_created = created
        decision = receipt["decision"]
        transition = {
            ("pending", "approved_for_manual_execution"): "approved",
            ("pending", "approved_for_execution"): "approved_for_execution",
            ("pending", "denied"): "denied",
            ("approved", "manually_executed"): "manually_executed",
            (
                "approved_for_execution",
                "approved_for_execution",
            ): "approved_for_execution",
            ("approved_for_execution", "executed"): "executed",
        }.get((derived_state, decision))
        if transition is None:
            raise AirlockError(
                "invalid_response", "Requester returned invalid receipt transition"
            )
        if (
            "plan_digest" in receipt
            and decision == "executed"
            and (
                index == 0
                or any(
                    receipts[index - 1].get(field) != receipt.get(field)
                    for field in ("profile_id", "profile_version", "plan_digest")
                )
            )
        ):
            raise AirlockError(
                "invalid_response", "Requester returned execution plan drift"
            )
        derived_state = transition
    if derived_state != state:
        raise AirlockError("invalid_response", "Requester returned receipt/state drift")
