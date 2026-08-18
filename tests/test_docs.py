from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
import unittest
from collections.abc import Iterable
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

REPO = Path(__file__).resolve().parents[1]
DOCS = REPO / "docs"
HTML_PAGES = (
    "index.html",
    "getting-started.html",
    "architecture.html",
    "approval-timing.html",
    "security.html",
)
MERMAID_PAIRS = {
    "architecture.md": (
        "trust-boundary.mmd",
        "installation-topology.mmd",
        "instruction-lifecycle.mmd",
    ),
    "approval-timing.md": ("approval-timing.mmd",),
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.ids: list[str] = []
        self.images_without_alt: list[str] = []
        self._title_depth = 0
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"] or "")
        if tag == "a" and values.get("href"):
            self.references.append(values["href"] or "")
        if tag in {"img", "script"} and values.get("src"):
            self.references.append(values["src"] or "")
        if tag == "link" and values.get("href"):
            self.references.append(values["href"] or "")
        if tag == "img" and not (values.get("alt") or "").strip():
            self.images_without_alt.append(values.get("src") or "<unknown>")
        if tag == "title":
            self._title_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._title_depth:
            self._title_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._title_depth:
            self.title += data


def tracked_markdown() -> list[Path]:
    """Walk the repository for Markdown, pruning dot-directories during descent
    so .git and virtualenvs are never stat-ed."""

    found: list[Path] = []
    for parent, directories, files in os.walk(REPO):
        directories[:] = [name for name in directories if not name.startswith(".")]
        found.extend(Path(parent) / name for name in files if name.endswith(".md"))
    return found


def mermaid_blocks(markdown: str) -> list[str]:
    return [
        block.strip()
        for block in re.findall(r"```mermaid\s*\n(.*?)\n```", markdown, re.DOTALL)
    ]


class DocsTests(unittest.TestCase):
    def test_mermaid_markdown_matches_raw_sources(self) -> None:
        for markdown_name, source_names in MERMAID_PAIRS.items():
            markdown = (DOCS / markdown_name).read_text(encoding="utf-8")
            blocks = mermaid_blocks(markdown)
            self.assertEqual(
                len(blocks),
                len(source_names),
                f"{markdown_name} must contain one fenced block per raw source",
            )
            expected = [
                (DOCS / "diagrams" / name).read_text(encoding="utf-8").strip()
                for name in source_names
            ]
            self.assertEqual(
                blocks, expected, f"{markdown_name} drifted from docs/diagrams"
            )

    def test_rendered_diagrams_exist_and_are_svg(self) -> None:
        source_stems = {path.stem for path in (DOCS / "diagrams").glob("*.mmd")}
        rendered = {
            path.stem: path for path in (DOCS / "assets" / "diagrams").glob("*.svg")
        }
        self.assertEqual(set(rendered), source_stems)
        for name, path in rendered.items():
            payload = path.read_text(encoding="utf-8")
            source = DOCS / "diagrams" / f"{name}.mmd"
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertTrue(
                payload.startswith(f"<!-- source-sha256:{digest} -->\n"),
                f"{name}.svg is stale; run docs/diagrams/render.sh",
            )
            self.assertIn("<svg", payload, name)
            self.assertGreater(len(payload), 500, name)
            if name == "approval-timing":
                self.assertIn(
                    "Bubblewrap runs pinned gh with fixed environment",
                    payload,
                )
                self.assertIn(
                    "Atomically persist executed receipt + succeeded attempt",
                    payload,
                )
                self.assertNotIn(
                    "Manually execute the locally reconstructed action",
                    payload,
                )
                self.assertNotIn("Airlock exposes no provider-execution API", payload)

    def test_static_site_local_references_resolve(self) -> None:
        for page_name in HTML_PAGES:
            page = DOCS / page_name
            parser = PageParser()
            parser.feed(page.read_text(encoding="utf-8"))
            self.assertTrue(parser.title.strip(), page_name)
            self.assertEqual(parser.images_without_alt, [], page_name)
            self.assertEqual(
                len(parser.ids), len(set(parser.ids)), f"duplicate id in {page_name}"
            )
            self.assert_local_references(page, parser.references)

    def test_markdown_local_references_resolve(self) -> None:
        for markdown in tracked_markdown():
            content = markdown.read_text(encoding="utf-8")
            self.assert_local_references(
                markdown, re.findall(r"!?\[[^]]*\]\(([^)]+)\)", content)
            )

    def assert_local_references(self, source: Path, references: Iterable[str]) -> None:
        """Every non-remote reference must stay inside the repository and exist."""

        for reference in references:
            reference = reference.strip()
            split = urlsplit(reference)
            if split.scheme or split.netloc or reference.startswith(("#", "mailto:")):
                continue
            target = (source.parent / unquote(split.path)).resolve()
            label = source.relative_to(REPO)
            self.assertTrue(
                target.is_relative_to(REPO),
                f"{label}: link escapes repository: {reference}",
            )
            self.assertTrue(
                target.exists(), f"{label}: missing local reference {reference}"
            )

    def test_pages_are_script_free_and_github_pages_ready(self) -> None:
        self.assertTrue((DOCS / ".nojekyll").exists())
        for page_name in HTML_PAGES:
            page = (DOCS / page_name).read_text(encoding="utf-8").lower()
            self.assertNotIn("<script", page, page_name)
            self.assertNotIn("javascript:", page, page_name)
            self.assertIn('name="viewport"', page, page_name)

    def test_timing_docs_use_protocol_states(self) -> None:
        expected = ("pending", "approved_for_execution", "denied", "executed")
        for relative in (
            "approval-timing.md",
            "approval-timing.html",
            "diagrams/approval-timing.mmd",
        ):
            content = (DOCS / relative).read_text(encoding="utf-8")
            for state in expected:
                self.assertIn(
                    state, content, f"{relative} omits protocol state {state}"
                )
            self.assertNotIn("execution_failed", content, relative)
            self.assertNotIn("rejected receipt", content, relative)

    def test_marketing_page_states_trusted_execution_path(self) -> None:
        page = (DOCS / "index.html").read_text(encoding="utf-8")
        for claim in (
            "Agent requests",
            "Trusted node validates",
            "Human reviews",
            "Trusted node executes",
            "Verifier observes",
            "Credentials never cross the boundary",
        ):
            self.assertIn(claim, page)

    def test_command_broker_contract_and_versions_are_consistent(self) -> None:
        contract_files = (
            REPO / "README.md",
            DOCS / "adr" / "0001-two-node-authority-boundary.md",
            DOCS / "mcp-conformance.md",
            DOCS / "security.html",
            REPO / "integrations" / "hermes" / "README.md",
            REPO / "plugins" / "airlock" / "skills" / "airlock" / "SKILL.md",
        )
        for path in contract_files:
            content = path.read_text(encoding="utf-8")
            for claim in ("github.command/v1", "reviewer-approved RCE", "shell.run/v1"):
                self.assertIn(claim, content, f"{path.relative_to(REPO)} omits {claim}")

        protocol = (DOCS / "mcp-conformance.md").read_text(encoding="utf-8")
        for version in (
            "airlock.catalog/v2",
            "airlock.request/v2",
            "airlock.receipt/v3",
        ):
            self.assertIn(version, protocol)

        claude = json.loads(
            (REPO / "plugins" / "airlock" / ".claude-plugin" / "plugin.json").read_text()
        )
        codex = json.loads(
            (REPO / "plugins" / "airlock" / ".codex-plugin" / "plugin.json").read_text()
        )
        pyproject = tomllib.loads(
            (REPO / "integrations" / "hermes" / "pyproject.toml").read_text()
        )
        hermes_manifest = (
            REPO / "integrations" / "hermes" / "plugin.yaml"
        ).read_text(encoding="utf-8")
        versions = {claude["version"], codex["version"], pyproject["project"]["version"]}
        self.assertEqual(versions, {"0.4.0"})
        self.assertRegex(hermes_manifest, r"(?m)^version: 0\.4\.0$")
        self.assertIn("Package 0.4.0", (DOCS / "index.html").read_text())

    def test_network_and_execution_disclaimers_are_not_marketing_copy(self) -> None:
        public_surfaces = [REPO / "README.md"]
        for root in (DOCS, REPO / "integrations", REPO / "plugins"):
            public_surfaces.extend(
                path
                for path in root.rglob("*")
                if path.is_file() and path.suffix in {".html", ".md", ".mmd", ".yaml", ".json"}
            )
        for path in public_surfaces:
            self.assertNotIn(
                "airgapped", path.read_text(encoding="utf-8").lower(), path.relative_to(REPO)
            )

        two_node_docs = (
            REPO / "README.md",
            DOCS / "adr" / "0001-two-node-authority-boundary.md",
            DOCS / "architecture.md",
            DOCS / "index.html",
        )
        for path in two_node_docs:
            content = path.read_text(encoding="utf-8").lower()
            self.assertIn("two-node", content, path.relative_to(REPO))

        network_docs = (
            REPO / "README.md",
            DOCS / "adr" / "0001-two-node-authority-boundary.md",
            DOCS / "architecture.md",
            DOCS / "architecture.html",
            DOCS / "approval-timing.md",
            DOCS / "approval-timing.html",
            DOCS / "security.html",
        )
        for path in network_docs:
            self.assertRegex(
                path.read_text(encoding="utf-8").lower(),
                r"not an egress\s+firewall",
                path.relative_to(REPO),
            )

        execution_docs = (
            REPO / "README.md",
            DOCS / "adr" / "0001-two-node-authority-boundary.md",
            DOCS / "architecture.md",
            DOCS / "approval-timing.md",
            DOCS / "security.html",
            REPO / "integrations" / "hermes" / "skills" / "airlock" / "SKILL.md",
            REPO / "plugins" / "airlock" / "skills" / "airlock" / "SKILL.md",
        )
        for path in execution_docs:
            content = path.read_text(encoding="utf-8").lower()
            self.assertTrue(
                "does not prove provider state" in content
                or "not independent provider proof" in content,
                path.relative_to(REPO),
            )


if __name__ == "__main__":
    unittest.main()
