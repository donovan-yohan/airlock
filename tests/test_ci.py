from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"


class CITests(unittest.TestCase):
    def test_third_party_actions_are_pinned_to_commits(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        actions = re.findall(r"^\s*- uses:\s+([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE)
        self.assertGreater(len(actions), 0)
        for action, revision in actions:
            self.assertRegex(revision, r"^[0-9a-f]{40}$", f"{action} is not commit-pinned")

    def test_hermes_dependencies_use_the_lockfile(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("uv run --with", workflow)
        self.assertIn("uv lock --check", workflow)
        self.assertIn("uv run --locked pytest", workflow)
        self.assertIn("uv run --locked ruff", workflow)
        self.assertRegex(workflow, r"(?m)^\s+ref: [0-9a-f]{40}(?:\s+#.*)?$")
        self.assertEqual(workflow.count("timeout-minutes: 20"), 2)


if __name__ == "__main__":
    unittest.main()
