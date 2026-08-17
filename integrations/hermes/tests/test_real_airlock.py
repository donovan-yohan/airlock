from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.request
from contextlib import ExitStack
from pathlib import Path

import pytest

from hermes_plugin_airlock.client import AirlockClient, AirlockError

AIRLOCK_BINARY = os.environ.get("AIRLOCK_BINARY")
pytestmark = pytest.mark.skipif(not AIRLOCK_BINARY, reason="AIRLOCK_BINARY is not set")


def _wait_for_address(log_path: Path) -> str:
    pattern = re.compile(r"listening on (127\.0\.0\.1:\d+)")
    for _ in range(100):
        if log_path.exists():
            match = pattern.search(log_path.read_text(errors="replace"))
            if match:
                return match.group(1)
        time.sleep(0.05)
    raise AssertionError(f"service address did not appear in {log_path}")


def _wait_for_health(url: str) -> None:
    for _ in range(100):
        try:
            with urllib.request.urlopen(url, timeout=0.25) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"service never became healthy: {url}")


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def test_plugin_uses_real_airlock_requester(tmp_path: Path):
    binary = Path(AIRLOCK_BINARY).resolve()
    assert binary.is_file()
    keys = tmp_path / "keys"
    requester_state = tmp_path / "requester-state"
    trusted_state = tmp_path / "trusted-state"
    for directory in (keys, requester_state, trusted_state):
        directory.mkdir(mode=0o700)

    private_key = keys / "trusted.key"
    public_key = keys / "trusted.pub"
    subprocess.run(
        [str(binary), "keygen", "--private", str(private_key), "--public", str(public_key)],
        check=True,
        capture_output=True,
        text=True,
    )
    requester_config = tmp_path / "requester.json"
    requester_config.write_text(
        json.dumps(
            {
                "listen": "127.0.0.1:0",
                "state_dir": str(requester_state),
                "trusted_public_key_file": str(public_key),
                "request_max_ttl": "15m",
                "catalog_max_ttl": "1h",
                "receipt_max_ttl": "1h",
            }
        )
    )
    requester_log = tmp_path / "requester.log"
    trusted_log = tmp_path / "trusted.log"

    with ExitStack() as stack:
        requester_stream = stack.enter_context(requester_log.open("w"))
        requester = subprocess.Popen(
            [str(binary), "requester", "serve", "--config", str(requester_config)],
            stdout=requester_stream,
            stderr=subprocess.STDOUT,
            text=True,
        )
        stack.callback(_terminate, requester)
        requester_address = _wait_for_address(requester_log)
        _wait_for_health(f"http://{requester_address}/healthz")

        trusted_config = tmp_path / "trusted.json"
        trusted_config.write_text(
            json.dumps(
                {
                    "listen": "127.0.0.1:0",
                    "state_dir": str(trusted_state),
                    "private_key_file": str(private_key),
                    "requester_url": f"http://{requester_address}",
                    "poll_interval": "100ms",
                    "request_max_ttl": "15m",
                    "catalog_ttl": "1h",
                    "receipt_ttl": "1h",
                    "allowed_logins": ["reviewer@example.invalid"],
                    "capabilities": [
                        {
                            "id": "github:example-owner",
                            "display_name": "Example GitHub authority",
                            "adapter": "github.repo.add_collaborator/v1",
                            "owner": "example-owner",
                            "collaborator": "example-agent",
                            "permissions": ["pull", "push"],
                        }
                    ],
                }
            )
        )
        trusted_stream = stack.enter_context(trusted_log.open("w"))
        trusted = subprocess.Popen(
            [str(binary), "trusted", "serve", "--dev", "--config", str(trusted_config)],
            stdout=trusted_stream,
            stderr=subprocess.STDOUT,
            text=True,
        )
        stack.callback(_terminate, trusted)
        trusted_address = _wait_for_address(trusted_log)
        _wait_for_health(f"http://{trusted_address}/healthz")

        client = AirlockClient(f"http://{requester_address}")
        for _ in range(100):
            try:
                discovered = client.capabilities()
                break
            except AirlockError:
                time.sleep(0.05)
        else:
            raise AssertionError("trusted catalog did not reach requester")

        assert discovered["capabilities"][0]["id"] == "github:example-owner"
        record = client.create_request(
            capability_id="github:example-owner",
            action="github.repo.add_collaborator",
            repository="plugin-smoke",
            permission="push",
            reason="Live Hermes plugin integration smoke",
            ttl_seconds=600,
        )
        assert record["state"] == "pending"
        assert client.request_status(record["id"])["digest"] == record["digest"]
        assert client.list_requests(limit=1)[0]["id"] == record["id"]

    private_canary = private_key.read_text().strip()
    artifacts = requester_log.read_text() + trusted_log.read_text()
    artifacts += (requester_state / "requester-state.json").read_text()
    assert private_canary not in artifacts
