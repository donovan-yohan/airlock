from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
SMOKE = REPO / "scripts" / "smoke-local.sh"
REQUESTER_UNIT = REPO / "deploy" / "systemd" / "airlock-requester.service"
TRUSTED_UNIT = REPO / "deploy" / "systemd" / "airlock-trusted.service"


class CITests(unittest.TestCase):
    def test_third_party_actions_are_pinned_to_commits(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        actions = re.findall(
            r"^\s*- uses:\s+([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE
        )
        self.assertGreater(len(actions), 0)
        for action, revision in actions:
            self.assertRegex(
                revision, r"^[0-9a-f]{40}$", f"{action} is not commit-pinned"
            )

    def test_hermes_dependencies_use_the_lockfile(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("uv run --with", workflow)
        self.assertIn("uv lock --check", workflow)
        self.assertIn("uv run --locked pytest", workflow)
        self.assertIn("uv run --locked ruff", workflow)
        self.assertRegex(workflow, r"(?m)^\s+ref: [0-9a-f]{40}(?:\s+#.*)?$")
        self.assertEqual(workflow.count("timeout-minutes: 20"), 2)

    def test_real_sandbox_and_release_artifact_gates_are_required(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(workflow.count("sudo apt-get install -y --no-install-recommends bubblewrap"), 2)
        self.assertEqual(workflow.count("Bubblewrap unprivileged-userns preflight"), 2)
        self.assertIn("bwrap --version", workflow)
        self.assertIn("bwrap --unshare-user --unshare-pid", workflow)
        self.assertIn("git diff --check HEAD^ HEAD", workflow)
        self.assertIn(
            "systemd-analyze --user verify deploy/systemd/airlock-requester.service",
            workflow,
        )
        self.assertIn(
            "systemd-analyze --user verify deploy/systemd/airlock-trusted.service",
            workflow,
        )
        self.assertIn("./docs/diagrams/render.sh", workflow)
        self.assertIn("git diff --exit-code -- docs/assets/diagrams", workflow)
        self.assertIn("ruff check hermes_plugin_airlock tests ../../tests", workflow)

    def test_checkout_never_persists_credentials(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        checkouts = re.findall(
            r"uses: actions/checkout@[0-9a-f]{40}(.*?)(?=^\s*- uses:|^\s*- name:|\Z)",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertGreaterEqual(len(checkouts), 3)
        for checkout in checkouts:
            self.assertIn("persist-credentials: false", checkout)

    def test_smoke_asserts_fake_sandbox_snapshots_before_claiming_count(self) -> None:
        smoke = SMOKE.read_text(encoding="utf-8")
        snapshot_pattern = r'r"(?m)^AIRLOCK_SNAPSHOT:(\{.*\})$"'
        self.assertIn(snapshot_pattern, smoke)
        self.assertIn("requester-state/requester-state.json", smoke)
        self.assertIn('observed["reviewed_environment_policy"]', smoke)
        self.assertIn("set(reviewed_policy) != expected_policy", smoke)
        self.assertIn("export GH_TOKEN=smoke-forbidden-gh-token", smoke)
        self.assertIn("export ALL_PROXY=socks5://127.0.0.1:9", smoke)
        self.assertIn("command curl --noproxy '*'", smoke)
        self.assertLess(
            smoke.index("export GH_TOKEN=smoke-forbidden-gh-token"),
            smoke.index('"$smoke_root/airlock" trusted serve'),
        )
        self.assertLess(
            smoke.index("if len(snapshots) != 2:"),
            smoke.index("sandbox_invocations=2"),
        )

    def test_user_units_avoid_capability_operations_that_fail_before_exec(self) -> None:
        # These directives fail before ExecStart with 218/CAPABILITIES under
        # an unprivileged user manager. Bubblewrap supplies the child device
        # namespace; the dedicated account cannot gain capabilities.
        for unit in (REQUESTER_UNIT, TRUSTED_UNIT):
            directives = {
                line.strip()
                for line in unit.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith(("#", "["))
            }
            keys = {line.partition("=")[0] for line in directives}
            self.assertNotIn("PrivateDevices", keys, unit.name)
            self.assertNotIn("CapabilityBoundingSet", keys, unit.name)
            self.assertIn("NoNewPrivileges=yes", directives, unit.name)
        requester = REQUESTER_UNIT.read_text(encoding="utf-8")
        trusted = TRUSTED_UNIT.read_text(encoding="utf-8")
        self.assertIn("RestrictNamespaces=yes", requester)
        self.assertIn("SystemCallFilter=@system-service", requester)
        self.assertIn("RestrictNamespaces=cgroup ipc mnt pid user uts", trusted)
        self.assertIn("SystemCallFilter=@system-service @mount @process", trusted)


if __name__ == "__main__":
    unittest.main()
