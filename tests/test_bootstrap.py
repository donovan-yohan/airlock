"""Temp-home regression tests for the stdlib Airlock bootstrapper."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "tools/airlock_bootstrap.py"

FAKE_CLI = r"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
home = Path(os.environ["HOME"])
state_file = home / ".fake-cli-state.json"
harness = "claude" if name == "claude" else "codex"
state = json.loads(state_file.read_text()) if state_file.exists() else {"mcp": {"claude": {}, "codex": {}}, "plugins": {"claude": {}, "codex": {}}, "marketplaces": {"claude": {}, "codex": {}}, "hermes": {"instructions_enabled": False}}
state.setdefault("hermes", {"instructions_enabled": False})
args = sys.argv[1:]
if os.environ.get("FAKE_FAIL") and os.environ["FAKE_FAIL"] in " ".join([name, *args]):
    print("forced fixture failure", file=sys.stderr); raise SystemExit(9)
def save():
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state))
def touch():
    if name == "hermes":
        path = Path(os.environ["HERMES_HOME"]) / "config.yaml"
    else:
        path = home / (".claude/.claude.json" if name == "claude" else ".codex/config.toml")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle: handle.write("# fake mutation\n")
def binary_after_dash():
    return args[args.index("--") + 1:]
if args[:2] == ["plugins", "show"]:
    if os.environ.get("FAKE_HERMES_PLUGIN_MISSING"): raise SystemExit(1)
    print("airlock v0.3.0\nStatus: enabled"); raise SystemExit(0)
if args[:2] == ["config", "get"]:
    if os.environ.get("FAKE_HERMES_GET_FAIL"):
        print("forced Hermes config read failure", file=sys.stderr); raise SystemExit(9)
    if os.environ.get("FAKE_HERMES_CONFIG_MISSING"):
        print("Config key not set: plugins.entries.airlock.settings.instructions_enabled", file=sys.stderr); raise SystemExit(1)
    print(json.dumps(state["hermes"]["instructions_enabled"])); raise SystemExit(0)
if args[:2] == ["config", "set"]:
    state["hermes"]["instructions_enabled"] = args[-1].lower() == "true"; touch(); save(); raise SystemExit(0)
if args[:2] == ["mcp", "get"]:
    if os.environ.get("FAKE_QUERY_MUTATES"): touch()
    entry = state["mcp"][harness].get("airlock")
    if entry is None: raise SystemExit(1)
    print("command: " + " ".join(entry)); raise SystemExit(0)
if args[:2] == ["mcp", "add"]:
    entry = binary_after_dash(); state["mcp"][harness]["airlock"] = entry; touch(); save(); raise SystemExit(0)
if args[:2] == ["mcp", "remove"]:
    state["mcp"][harness].pop("airlock", None); touch(); save(); raise SystemExit(0)
if args[:2] == ["plugin", "list"]:
    print(json.dumps({"plugins": [{"id": item} for item in state["plugins"][harness]]})); raise SystemExit(0)
if args[:3] == ["plugin", "marketplace", "list"]:
    source = state["marketplaces"][harness].get("airlock")
    if source: print("airlock Source: " + source)
    raise SystemExit(0)
if args[:3] == ["plugin", "marketplace", "add"]:
    state["marketplaces"][harness]["airlock"] = args[-2] if args[-1] == "--json" else args[-1]; touch(); save(); raise SystemExit(0)
if args[:3] == ["plugin", "marketplace", "remove"]:
    state["marketplaces"][harness].pop("airlock", None); touch(); save(); raise SystemExit(0)
if args[:2] in (["plugin", "install"], ["plugin", "add"]):
    state["plugins"][harness]["airlock@airlock"] = True; touch(); save(); raise SystemExit(0)
if args[:2] in (["plugin", "uninstall"], ["plugin", "remove"]):
    selector = next((item for item in args if item.startswith("airlock")), "airlock@airlock")
    state["plugins"][harness].pop(selector, None); touch(); save(); raise SystemExit(0)
print("unsupported fake cli call: " + " ".join(args), file=sys.stderr)
raise SystemExit(1)
"""

FAKE_AIRLOCK = r"""#!/usr/bin/env python3
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        print(json.dumps({"jsonrpc":"2.0", "id":request["id"], "result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"fake-airlock","version":"0"}}}), flush=True)
    elif request.get("method") == "tools/list":
        tools = [{"name": name, "description": "fake", "inputSchema": {"type":"object"}} for name in ("airlock_capabilities", "airlock_create_request", "airlock_requests")]
        print(json.dumps({"jsonrpc":"2.0", "id":request["id"], "result":{"tools":tools}}), flush=True)
"""


class BootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir()
        self.fixture = Path(self.temp.name) / "fixture"
        self.fixture.mkdir()
        self.cli = self.fixture / "fake-cli"
        self.binary = self.fixture / "airlock"
        self.cli.write_text(FAKE_CLI)
        self.binary.write_text(FAKE_AIRLOCK)
        self.cli.chmod(self.cli.stat().st_mode | stat.S_IXUSR)
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        for name in ("hermes", "claude", "codex"):
            (self.fixture / name).symlink_to(self.cli)
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "HERMES_HOME": str(self.home / ".hermes"),
                "CODEX_HOME": str(self.home / ".codex"),
                "CLAUDE_CONFIG_DIR": str(self.home / ".claude"),
            }
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def bootstrap(
        self, *args: str, check: bool = True, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = self.env.copy()
        if extra_env:
            environment.update(extra_env)
        result = subprocess.run(
            [
                sys.executable,
                str(BOOTSTRAP),
                "--repo",
                str(ROOT),
                "--home",
                str(self.home),
                "--hermes",
                str(self.fixture / "hermes"),
                "--claude",
                str(self.fixture / "claude"),
                "--codex",
                str(self.fixture / "codex"),
                *args,
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        if check and result.returncode:
            self.fail(
                f"{result.args}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def state(self) -> dict[str, Any]:
        return json.loads((self.home / ".fake-cli-state.json").read_text())

    def test_package_validation(self) -> None:
        result = self.bootstrap("validate")
        self.assertIn("OK package manifests", result.stdout)

    def test_package_contract_has_no_hooks_or_shipped_instruction_files(self) -> None:
        claude = json.loads(
            (ROOT / "plugins/airlock/.claude-plugin/plugin.json").read_text()
        )
        codex = json.loads(
            (ROOT / "plugins/airlock/.codex-plugin/plugin.json").read_text()
        )
        skill = (ROOT / "plugins/airlock/skills/airlock/SKILL.md").read_text()
        self.assertNotIn("hooks", claude)
        self.assertNotIn("hooks", codex)
        self.assertNotIn("allowed-tools:", skill)
        self.assertLessEqual(len(skill.encode()), 4096)
        self.assertLessEqual(len(skill.splitlines()), 80)
        self.assertEqual(claude["name"], codex["name"])
        self.assertEqual(claude["version"], codex["version"])
        pyproject = tomllib.loads(
            (ROOT / "integrations/hermes/pyproject.toml").read_text()
        )
        self.assertEqual(claude["version"], pyproject["project"]["version"])
        self.assertEqual(claude["skills"], codex["skills"])
        plugin_root = ROOT / "plugins/airlock"
        self.assertFalse(any(plugin_root.rglob("AGENTS.md")))
        self.assertFalse(any(plugin_root.rglob("CLAUDE.md")))
        claude_market = json.loads(
            (ROOT / ".claude-plugin/marketplace.json").read_text()
        )
        codex_market = json.loads(
            (ROOT / ".agents/plugins/marketplace.json").read_text()
        )
        self.assertEqual(claude_market["name"], codex_market["name"])
        self.assertEqual(
            claude_market["plugins"][0]["name"], codex_market["plugins"][0]["name"]
        )
        self.assertEqual(
            claude_market["plugins"][0]["source"],
            codex_market["plugins"][0]["source"]["path"],
        )

    def test_dry_run_lists_absolute_binary_and_no_mutation(self) -> None:
        result = self.bootstrap("install", "--binary", str(self.binary), "--dry-run")
        self.assertIn("COMMAND", result.stdout)
        self.assertIn("mcp --requester-url http://127.0.0.1:8787", result.stdout)
        self.assertNotIn("Airlock authority requests", result.stdout)
        self.assertFalse((self.home / ".fake-cli-state.json").exists())
        self.assertFalse((self.home / ".local/share/airlock").exists())

    def test_instruction_dry_run_prints_managed_changes_without_mutation(self) -> None:
        result = self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
            "--dry-run",
        )
        self.assertIn(
            "plugins.entries.airlock.settings.instructions_enabled true", result.stdout
        )
        self.assertIn(".claude/CLAUDE.md", result.stdout)
        self.assertIn(".codex/AGENTS.md", result.stdout)
        self.assertIn("Airlock authority requests", result.stdout)
        self.assertFalse((self.home / ".fake-cli-state.json").exists())
        self.assertFalse((self.home / ".claude/CLAUDE.md").exists())
        self.assertFalse((self.home / ".codex/AGENTS.md").exists())

    def test_instruction_install_requires_enabled_native_hermes_plugin(self) -> None:
        result = self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
            check=False,
            extra_env={"FAKE_HERMES_PLUGIN_MISSING": "1"},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("installed and enabled", result.stderr)
        self.assertFalse((self.home / ".fake-cli-state.json").exists())
        self.assertFalse((self.home / ".local/share/airlock").exists())

    def test_requester_url_requires_exact_loopback_ip_and_port(self) -> None:
        invalid = (
            "http://127.0.0.1",
            "http://localhost:8787",
            "http://127.0.0.2:8787",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://user@127.0.0.1:8787",
            "http://127.0.0.1:8787/path",
        )
        for requester_url in invalid:
            with self.subTest(requester_url=requester_url):
                result = self.bootstrap(
                    "--requester-url",
                    requester_url,
                    "install",
                    "--binary",
                    str(self.binary),
                    "--dry-run",
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("explicit port", result.stderr)

    def test_install_idempotent_doctor_and_uninstall(self) -> None:
        (self.home / ".claude").mkdir()
        (self.home / ".claude/.claude.json").write_text('{"preexisting":true}\n')
        (self.home / ".codex").mkdir()
        (self.home / ".codex/config.toml").write_text("model = 'test'\n")
        self.bootstrap("install", "--binary", str(self.binary))
        first = self.state()
        self.bootstrap("install", "--binary", str(self.binary))
        self.assertEqual(first, self.state())
        state_path = self.home / ".local/share/airlock/install-state.json"
        self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
        backups = list((self.home / ".local/share/airlock/backups").rglob("*"))
        backup_files = [item for item in backups if item.is_file()]
        self.assertTrue(backup_files)
        self.assertTrue(
            all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in backup_files)
        )
        installed = json.loads(state_path.read_text())
        binary = Path(installed["installs"]["claude"]["binary"])
        self.assertTrue(binary.is_file())
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o500)
        self.bootstrap("doctor")
        invalid_timeout = self.bootstrap("doctor", "--timeout", "nan", check=False)
        self.assertEqual(invalid_timeout.returncode, 2)
        self.assertIn("positive finite", invalid_timeout.stderr)
        self.bootstrap("uninstall")
        self.assertEqual(self.state()["mcp"], {"claude": {}, "codex": {}})
        self.assertFalse(binary.exists())

    def test_uninstall_dry_run_previews_exact_installer_owned_plugin(self) -> None:
        self.bootstrap("install", "--binary", str(self.binary), "--harness", "claude")
        before = (self.home / ".fake-cli-state.json").read_bytes()

        result = self.bootstrap("uninstall", "--harness", "claude", "--dry-run")

        self.assertIn(
            "plugin uninstall --scope user airlock@airlock --yes", result.stdout
        )
        self.assertEqual((self.home / ".fake-cli-state.json").read_bytes(), before)

    def test_default_install_does_not_edit_global_instructions(self) -> None:
        claude = self.home / ".claude/CLAUDE.md"
        codex = self.home / ".codex/AGENTS.md"
        claude.parent.mkdir()
        codex.parent.mkdir()
        claude.write_text("claude-owned\n")
        codex.write_text("codex-owned\n")

        self.bootstrap("install", "--binary", str(self.binary))

        self.assertEqual(claude.read_text(), "claude-owned\n")
        self.assertEqual(codex.read_text(), "codex-owned\n")
        self.assertFalse(self.state()["hermes"]["instructions_enabled"])
        self.assertFalse((self.home / ".hermes").exists())
        backups = self.home / ".local/share/airlock/backups"
        self.assertFalse(any(backups.rglob("CLAUDE.md")))
        self.assertFalse(any(backups.rglob("AGENTS.md")))
        installer = json.loads(
            (self.home / ".local/share/airlock/install-state.json").read_text()
        )
        self.assertEqual(installer["instructions"], {})

    def test_explicit_instructions_are_managed_idempotently_and_uninstalled(
        self,
    ) -> None:
        claude = self.home / ".claude/CLAUDE.md"
        codex = self.home / ".codex/AGENTS.md"
        claude.parent.mkdir()
        codex.parent.mkdir()
        claude.write_text("claude-owned\n")
        codex.write_text("codex-owned\n")

        command = (
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        self.bootstrap(*command)
        first_claude = claude.read_text()
        first_codex = codex.read_text()
        self.bootstrap(*command)

        for text, prefix in (
            (claude.read_text(), "claude-owned\n"),
            (codex.read_text(), "codex-owned\n"),
        ):
            self.assertTrue(text.startswith(prefix))
            self.assertEqual(text.count("airlock:instructions:start"), 1)
            self.assertEqual(text.count("airlock:instructions:end"), 1)
            self.assertIn("airlock_capabilities", text)
            self.assertIn("independently verify", text)
        self.assertEqual(claude.read_text(), first_claude)
        self.assertEqual(codex.read_text(), first_codex)
        installer = json.loads(
            (self.home / ".local/share/airlock/install-state.json").read_text()
        )
        self.assertEqual(installer["schema"], 3)
        for harness in ("claude", "codex"):
            self.assertRegex(
                installer["instructions"][harness]["content_sha256"],
                r"^[0-9a-f]{64}$",
            )
        self.assertTrue(self.state()["hermes"]["instructions_enabled"])

        self.bootstrap("doctor")
        self.bootstrap("uninstall")

        self.assertEqual(claude.read_text(), "claude-owned\n")
        self.assertEqual(codex.read_text(), "codex-owned\n")
        self.assertFalse(self.state()["hermes"]["instructions_enabled"])

    def test_instruction_files_preserve_bytes_permissions_and_newline_style(
        self,
    ) -> None:
        claude = self.home / ".claude/CLAUDE.md"
        codex = self.home / ".codex/AGENTS.md"
        claude.parent.mkdir()
        codex.parent.mkdir()
        originals = {
            claude: b"claude-owned\r\n\r\n",
            codex: b"codex-owned-without-final-newline",
        }
        for path, content in originals.items():
            path.write_bytes(content)
            path.chmod(0o640)

        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )

        claude_installed = claude.read_bytes()
        self.assertNotIn(b"\n", claude_installed.replace(b"\r\n", b""))
        self.assertTrue(codex.read_bytes().startswith(originals[codex]))
        self.assertTrue(
            all(stat.S_IMODE(path.stat().st_mode) == 0o640 for path in originals)
        )

        self.bootstrap("uninstall")

        for path, content in originals.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_malformed_instruction_markers_fail_before_any_mutation(self) -> None:
        claude = self.home / ".claude/CLAUDE.md"
        claude.parent.mkdir()
        original = b"owned\n<!-- airlock:instructions:start -->\n"
        claude.write_bytes(original)

        result = self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("incomplete or duplicated", result.stderr)
        self.assertEqual(claude.read_bytes(), original)
        self.assertFalse((self.home / ".fake-cli-state.json").exists())
        self.assertFalse((self.home / ".local/share/airlock").exists())

    def test_existing_markers_without_state_are_not_adopted(self) -> None:
        claude = self.home / ".claude/CLAUDE.md"
        claude.parent.mkdir()
        original = (
            "user text\n<!-- airlock:instructions:start -->\n"
            "manually managed\n<!-- airlock:instructions:end -->"
        )
        claude.write_text(original)

        result = self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--harness",
            "claude",
            "--instructions",
            "install",
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("without installer ownership state", result.stderr)
        self.assertEqual(claude.read_text(), original)
        self.assertFalse((self.home / ".fake-cli-state.json").exists())

    def test_tampered_instruction_block_blocks_uninstall_before_mutation(self) -> None:
        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        claude = self.home / ".claude/CLAUDE.md"
        claude.write_text(claude.read_text().replace("untrusted data", "trusted data"))
        state_path = self.home / ".local/share/airlock/install-state.json"
        installer_before = state_path.read_bytes()
        cli_before = (self.home / ".fake-cli-state.json").read_bytes()

        result = self.bootstrap("uninstall", check=False)

        self.assertEqual(result.returncode, 2)
        self.assertIn("was modified", result.stderr)
        self.assertEqual(state_path.read_bytes(), installer_before)
        self.assertEqual((self.home / ".fake-cli-state.json").read_bytes(), cli_before)
        self.assertIn("trusted data", claude.read_text())

    def test_failed_hermes_config_read_blocks_uninstall_before_mutation(self) -> None:
        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        state_path = self.home / ".local/share/airlock/install-state.json"
        installer_before = state_path.read_bytes()
        cli_before = (self.home / ".fake-cli-state.json").read_bytes()

        result = self.bootstrap(
            "uninstall",
            check=False,
            extra_env={"FAKE_HERMES_GET_FAIL": "1"},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Hermes instruction config read failed", result.stderr)
        self.assertEqual(state_path.read_bytes(), installer_before)
        self.assertEqual((self.home / ".fake-cli-state.json").read_bytes(), cli_before)
        self.assertTrue((self.home / ".claude/CLAUDE.md").exists())
        self.assertTrue((self.home / ".codex/AGENTS.md").exists())

    def test_uninstall_restores_config_mutated_by_failed_preflight_query(self) -> None:
        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        claude_config = self.home / ".claude/.claude.json"
        config_before = claude_config.read_bytes()
        state_path = self.home / ".local/share/airlock/install-state.json"
        installer_before = state_path.read_bytes()

        result = self.bootstrap(
            "uninstall",
            check=False,
            extra_env={
                "FAKE_QUERY_MUTATES": "1",
                "FAKE_HERMES_GET_FAIL": "1",
            },
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Hermes instruction config read failed", result.stderr)
        self.assertEqual(claude_config.read_bytes(), config_before)
        self.assertEqual(state_path.read_bytes(), installer_before)

    def test_missing_hermes_instruction_key_is_treated_as_disabled(self) -> None:
        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--harness",
            "claude",
            "--instructions",
            "install",
            extra_env={"FAKE_HERMES_CONFIG_MISSING": "1"},
        )

        self.assertTrue(self.state()["hermes"]["instructions_enabled"])

    def test_schema_two_instruction_state_migrates_only_when_block_is_canonical(
        self,
    ) -> None:
        command = (
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        self.bootstrap(*command)
        state_path = self.home / ".local/share/airlock/install-state.json"
        installer = json.loads(state_path.read_text())
        installer["schema"] = 2
        for harness in ("claude", "codex"):
            installer["instructions"][harness].pop("content_sha256")
        state_path.write_text(json.dumps(installer))

        self.bootstrap(*command)

        migrated = json.loads(state_path.read_text())
        self.assertEqual(migrated["schema"], 3)
        for harness in ("claude", "codex"):
            self.assertRegex(
                migrated["instructions"][harness]["content_sha256"],
                r"^[0-9a-f]{64}$",
            )

    def test_nonempty_codex_override_blocks_ineffective_instruction_install(
        self,
    ) -> None:
        override = self.home / ".codex/AGENTS.override.md"
        override.parent.mkdir()
        override.write_text("override instructions\n")

        result = self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("global instructions are overridden", result.stderr)
        self.assertFalse((self.home / ".fake-cli-state.json").exists())

    def test_doctor_reports_tampered_managed_instructions(self) -> None:
        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        claude = self.home / ".claude/CLAUDE.md"
        claude.write_text(claude.read_text().replace("untrusted data", "trusted data"))

        result = self.bootstrap("doctor", check=False)

        self.assertEqual(result.returncode, 1)
        self.assertIn("was modified", result.stderr)

    def test_external_ambient_hermes_home_requires_explicit_selection_with_home(
        self,
    ) -> None:
        external = self.fixture / "external-hermes"

        result = self.bootstrap(
            "validate",
            check=False,
            extra_env={"HERMES_HOME": str(external)},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("outside explicit --home", result.stderr)
        self.assertFalse(external.exists())

    def test_explicit_external_hermes_home_is_honored(self) -> None:
        external = self.fixture / "external-hermes"
        self.bootstrap(
            "--hermes-home",
            str(external),
            "install",
            "--binary",
            str(self.binary),
            "--harness",
            "claude",
            "--instructions",
            "install",
            extra_env={"HERMES_HOME": str(self.fixture / "wrong-hermes")},
        )

        self.assertTrue((external / "config.yaml").exists())
        self.assertFalse((self.fixture / "wrong-hermes").exists())

    def test_default_home_honors_external_ambient_hermes_profile(self) -> None:
        external = self.fixture / "ambient-hermes"
        environment = self.env.copy()
        environment["HERMES_HOME"] = str(external)
        result = subprocess.run(
            [
                sys.executable,
                str(BOOTSTRAP),
                "--repo",
                str(ROOT),
                "--hermes",
                str(self.fixture / "hermes"),
                "--claude",
                str(self.fixture / "claude"),
                "--codex",
                str(self.fixture / "codex"),
                "install",
                "--binary",
                str(self.binary),
                "--harness",
                "claude",
                "--instructions",
                "install",
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((external / "config.yaml").exists())

    def test_partial_uninstall_keeps_shared_binary_and_hermes_instructions(
        self,
    ) -> None:
        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--instructions",
            "install",
        )
        state_path = self.home / ".local/share/airlock/install-state.json"
        installed = json.loads(state_path.read_text())
        binary = Path(installed["installs"]["claude"]["binary"])
        claude_instructions = self.home / ".claude/CLAUDE.md"
        codex_instructions = self.home / ".codex/AGENTS.md"
        self.assertEqual(stat.S_IMODE(claude_instructions.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(codex_instructions.stat().st_mode), 0o600)

        self.bootstrap("uninstall", "--harness", "claude")

        remaining = json.loads(state_path.read_text())
        self.assertEqual(set(remaining["installs"]), {"codex"})
        self.assertEqual(set(remaining["instructions"]), {"hermes", "codex"})
        self.assertTrue(binary.exists())
        self.assertFalse(claude_instructions.exists())
        self.assertTrue(codex_instructions.exists())
        self.assertTrue(self.state()["hermes"]["instructions_enabled"])

        self.bootstrap("uninstall", "--harness", "codex")
        self.assertFalse(binary.exists())
        self.assertFalse(codex_instructions.exists())
        self.assertFalse(self.state()["hermes"]["instructions_enabled"])

    def test_update_replaces_only_prior_owned_binary(self) -> None:
        self.bootstrap("install", "--binary", str(self.binary))
        second = self.fixture / "airlock-v2"
        second.write_text(FAKE_AIRLOCK + "\n# v2\n")
        second.chmod(second.stat().st_mode | stat.S_IXUSR)
        self.bootstrap("update", "--binary", str(second))
        mcp = self.state()["mcp"]["claude"]["airlock"]
        self.assertIn("airlock", mcp[0])
        self.assertIn("versions", mcp[0])

    def test_collision_refuses_without_replace(self) -> None:
        state = {
            "mcp": {
                "claude": {
                    "airlock": [
                        "/elsewhere/airlock",
                        "mcp",
                        "--requester-url",
                        "http://127.0.0.1:8787",
                    ]
                },
                "codex": {},
            },
            "plugins": {"claude": {"airlock@other": True}, "codex": {}},
            "marketplaces": {"claude": {}, "codex": {}},
        }
        (self.home / ".fake-cli-state.json").write_text(json.dumps(state))
        result = self.bootstrap("install", "--binary", str(self.binary), check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("pointing elsewhere", result.stderr)
        self.bootstrap("install", "--binary", str(self.binary), "--replace")
        self.assertEqual(
            self.state()["plugins"]["claude"], {"airlock@airlock": True}
        )

    def test_unrelated_airlock_plugin_is_never_treated_as_installer_owned(self) -> None:
        state = {
            "mcp": {"claude": {}, "codex": {}},
            "plugins": {"claude": {"airlock@other": True}, "codex": {}},
            "marketplaces": {
                "claude": {"airlock": str(ROOT)},
                "codex": {},
            },
        }
        (self.home / ".fake-cli-state.json").write_text(json.dumps(state))

        collision = self.bootstrap(
            "install", "--binary", str(self.binary), "--harness", "claude", check=False
        )

        self.assertEqual(collision.returncode, 2)
        self.assertIn("plugin pointing elsewhere", collision.stderr)
        self.assertEqual(self.state()["plugins"]["claude"], {"airlock@other": True})

        self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            "--harness",
            "claude",
            "--replace",
        )
        changed = self.state()
        changed["plugins"]["claude"] = {"airlock@other": True}
        (self.home / ".fake-cli-state.json").write_text(json.dumps(changed))

        removal = self.bootstrap("uninstall", "--harness", "claude", check=False)

        self.assertEqual(removal.returncode, 2)
        self.assertIn("no longer installer-owned", removal.stderr)
        self.assertEqual(self.state()["plugins"]["claude"], {"airlock@other": True})

    def test_failure_rolls_back_config_and_binary(self) -> None:
        original = "model = 'unchanged'\n"
        (self.home / ".codex").mkdir()
        config = self.home / ".codex/config.toml"
        config.write_text(original)
        config.chmod(0o640)
        result = self.bootstrap(
            "install",
            "--binary",
            str(self.binary),
            check=False,
            extra_env={"FAKE_FAIL": "codex plugin add"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(config.read_text(), original)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
        self.assertFalse((self.home / ".local/share/airlock/versions").exists())
        state = self.state()
        self.assertEqual(state["mcp"], {"claude": {}, "codex": {}})
        self.assertEqual(state["plugins"], {"claude": {}, "codex": {}})
        self.assertEqual(state["marketplaces"], {"claude": {}, "codex": {}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
