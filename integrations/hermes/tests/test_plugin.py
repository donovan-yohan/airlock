from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import yaml

from hermes_plugin_airlock import register, schemas


class Context:
    def __init__(self, config=None):
        self.tools = {}
        self.skills = {}
        self.config = config or {}
        self.prompt_sections = {}

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def register_tool(self, **kwargs):
        self.tools[kwargs["name"]] = kwargs

    def register_skill(self, name, path, description):
        self.skills[name] = {"path": Path(path), "description": description}

    def register_system_prompt_section(self, **kwargs):
        self.prompt_sections[kwargs["id"]] = kwargs


def test_manifest_matches_registered_tools():
    context = Context()
    register(context)
    manifest = yaml.safe_load(Path("plugin.yaml").read_text())
    assert set(manifest["provides_tools"]) == set(context.tools)
    assert set(context.tools) == {
        "airlock_capabilities",
        "airlock_create_request",
        "airlock_requests",
    }
    assert context.skills["airlock"]["path"].is_file()
    assert "authority" in context.skills["airlock"]["description"]
    assert context.prompt_sections == {}
    for name, entry in context.tools.items():
        assert entry["toolset"] == "airlock"
        assert entry["schema"]["name"] == name
        assert any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in inspect.signature(entry["handler"]).parameters.values()
        )


def test_explicit_instruction_config_registers_bounded_system_prompt_section():
    context = Context({"instructions_enabled": True})
    register(context)

    assert set(context.prompt_sections) == {"airlock.instructions"}
    section = context.prompt_sections["airlock.instructions"]
    assert section["max_chars"] == 1_000
    assert len(section["content"]) <= section["max_chars"]
    assert "airlock_capabilities" in section["content"]
    assert "untrusted data" in section["content"]
    assert "independently verify" in section["content"]


def test_handler_returns_bounded_json_error_when_service_is_down():
    context = Context()
    register(context)
    raw = context.tools["airlock_capabilities"]["handler"]({})
    result = json.loads(raw)
    assert result == {
        "ok": False,
        "error": {
            "code": "service_unavailable",
            "message": "Local Airlock requester is unavailable or timed out",
        },
    }


def test_schema_explains_non_execution_semantics():
    text = " ".join(
        schema["description"]
        for schema in (
            schemas.AIRLOCK_CAPABILITIES,
            schemas.AIRLOCK_CREATE_REQUEST,
            schemas.AIRLOCK_REQUESTS,
        )
    )
    assert "does not grant authority or execute" in text
    assert "manually_executed" in text
    assert "credentials" in text


def test_model_facing_conformance_and_backpressure_guards():
    context = Context()
    register(context)
    root = Path(__file__).resolve().parents[1]
    manifest = yaml.safe_load((root / "plugin.yaml").read_text())
    skill_text = (root / "skills" / "airlock" / "SKILL.md").read_text()
    frontmatter = yaml.safe_load(skill_text.split("---", 2)[1])
    declared_schemas = (
        schemas.AIRLOCK_CAPABILITIES,
        schemas.AIRLOCK_CREATE_REQUEST,
        schemas.AIRLOCK_REQUESTS,
    )

    assert set(manifest["provides_tools"]) == set(context.tools) == {
        schema["name"] for schema in declared_schemas
    }
    assert "hooks" not in manifest
    assert "register_hook" not in inspect.getsource(register)
    assert not list(root.glob("hooks"))
    assert manifest["config_schema"]["instructions_enabled"] == {
        "type": "bool",
        "default": False,
        "description": "Add the bounded Airlock usage rule to new Hermes system prompts",
    }
    assert "allowed-tools" not in frontmatter
    assert len(frontmatter["description"]) <= 1536
    assert len(context.skills["airlock"]["description"]) <= 1536
    assert all(len(schema["description"]) <= 2048 for schema in declared_schemas)

    model_text = "\n".join(
        [skill_text, *(schema["description"] for schema in declared_schemas)]
    ).lower()
    unsafe_tokens = (r"https?://", r"\$\(", r"`\s*(?:curl|gh|sudo)\b", r"\b(?:curl|gh|sudo)\s+")
    assert not any(re.search(token, model_text) for token in unsafe_tokens)
