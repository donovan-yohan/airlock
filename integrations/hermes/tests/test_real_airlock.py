from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from contextlib import ExitStack
from pathlib import Path

import pytest

from hermes_plugin_airlock.client import AirlockClient, AirlockError

AIRLOCK_BINARY = os.environ.get("AIRLOCK_BINARY")
pytestmark = pytest.mark.skipif(not AIRLOCK_BINARY, reason="AIRLOCK_BINARY is not set")
REPO = Path(__file__).resolve().parents[3]


def _required_host_dependency(name: str) -> str:
    path = shutil.which(name)
    if path:
        return str(Path(path).resolve())
    message = f"real Airlock integration requires {name}"
    if os.environ.get("CI"):
        pytest.fail(message)
    pytest.skip(message + " (local host dependency unavailable)")


def _build_static_fake_gh(tmp_path: Path) -> Path:
    go = _required_host_dependency("go")
    output = tmp_path / "fake-gh"
    environment = os.environ.copy()
    environment["CGO_ENABLED"] = "0"
    subprocess.run(
        [
            go,
            "build",
            "-buildvcs=false",
            "-trimpath",
            "-o",
            str(output),
            "./internal/trusted/testdata/fakegh",
        ],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return output


def _wait_for_address(log_path: Path) -> str:
    pattern = re.compile(r"listening on (127\.0\.0\.1:\d+)")
    for _ in range(100):
        if log_path.exists():
            match = pattern.search(log_path.read_text(errors="replace"))
            if match:
                return match.group(1)
        time.sleep(0.05)
    diagnostic = log_path.read_text(errors="replace")[-1_000:]
    raise AssertionError(f"service address did not appear in {log_path}: {diagnostic!r}")


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
    github_cli = _build_static_fake_gh(tmp_path)
    sandbox_cli = _required_host_dependency("bwrap")
    keys = tmp_path / "keys"
    requester_state = tmp_path / "requester-state"
    trusted_state = tmp_path / "trusted-state"
    github_config = tmp_path / "github-config"
    for directory in (keys, requester_state, trusted_state, github_config):
        directory.mkdir(mode=0o700)
    hosts = github_config / "hosts.yml"
    hosts.write_text("github.example.invalid:\n  user: hermes-test\n")
    hosts.chmod(0o600)

    private_key = keys / "trusted.key"
    public_key = keys / "trusted.pub"
    subprocess.run(
        [
            str(binary),
            "keygen",
            "--private",
            str(private_key),
            "--public",
            str(public_key),
        ],
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
                    "control_socket": str(trusted_state / "control.sock"),
                    "private_key_file": str(private_key),
                    "requester_url": f"http://{requester_address}",
                    "github_cli_path": str(github_cli),
                    "github_config_dir": str(github_config),
                    "sandbox_cli_path": sandbox_cli,
                    "execution_timeout": "10s",
                    "profile_config_version": "test-v1",
                    "credential_authority_label": "Test-only fake GitHub authority",
                    "execution_identity_label": "Test process identity",
                    "sandbox_label": "Ephemeral GitHub auth snapshot",
                    "network_label": "Shared network is not used by this pending-only test",
                    "cwd_label": "Fresh ephemeral working directory",
                    "output_label": "Bounded sanitized trusted-local output preview",
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

        assert discovered["profiles"][0]["id"] == "github.command"
        record = client.create_request(
            profile_id="github.command",
            profile_version="v1",
            argv=["api", "repos/example-owner/plugin-smoke"],
            reason="Live Hermes plugin integration smoke",
            ttl_seconds=600,
        )
        assert record["state"] == "pending"
        assert client.request_status(record["id"])["digest"] == record["digest"]
        assert client.list_requests(limit=1)[0]["id"] == record["id"]
        trusted_state_file = trusted_state / "trusted-state.json"
        for _ in range(100):
            if trusted_state_file.exists():
                persisted = json.loads(trusted_state_file.read_text())
                trusted_record = persisted.get("requests", {}).get(record["id"])
                if trusted_record is not None:
                    break
            time.sleep(0.05)
        else:
            raise AssertionError("pending request did not reach trusted durable state")
        assert trusted_record["state"] == "pending"
        assert trusted_record.get("attempts", []) == []
        assert "AIRLOCK_SNAPSHOT:" not in trusted_log.read_text(errors="replace")

    private_canary = private_key.read_text().strip()
    artifacts = requester_log.read_text() + trusted_log.read_text()
    artifacts += (requester_state / "requester-state.json").read_text()
    artifacts += (trusted_state / "trusted-state.json").read_text()
    assert private_canary not in artifacts
