#!/usr/bin/env python3
"""Validate the TS STUDIO R0 control-plane baseline and executable policies."""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import tempfile
from contextlib import closing
from html.parser import HTMLParser
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from studio_core.integrity import (  # noqa: E402
    IntegrityError,
    canonical_bytes,
    classify,
    content_hash,
    hash_file,
    verify_file,
)

EXPECTED_AGENT_IDS = {
    "A-00",
    "A-01",
    "A-02",
    "A-03",
    "A-10",
    "A-20",
    "A-30",
    "A-40",
    "A-50",
}


class BaselineValidationError(ValueError):
    """Raised when a baseline file violates a repository contract."""


def load_json(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise BaselineValidationError(f"{relative_path}: root must be an object")
    return value


def load_yaml(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise BaselineValidationError(f"{relative_path}: root must be a mapping")
    return value


def content_sha256(path: Path) -> str:
    """Hash repository content in a way that does not depend on the checkout's line endings.

    Artifact and knowledge hashes are recorded against the committed form of a file, which
    stores text with LF. A Windows checkout with ``core.autocrlf=true`` materializes exactly
    the same commit as CRLF, so hashing raw working-tree bytes makes one commit validate on a
    Linux runner and fail on a Windows workstation. Text is therefore normalized to LF before
    hashing; content holding a NUL byte is treated as binary and hashed verbatim.

    The canonical form lives in ``studio_core.integrity`` so the validator, the R2 integrity
    check, and the CI pipeline all agree on one definition; this stays as the named entry
    point that the baseline suite and the CI documentation refer to.
    """

    return hash_file(path, label=str(path))


def _resolve_ref(root_schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise BaselineValidationError(f"external schema reference is not allowed: {reference}")
    value: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            raise BaselineValidationError(f"unresolved schema reference: {reference}")
        value = value[part]
    if not isinstance(value, dict):
        raise BaselineValidationError(f"schema reference is not an object: {reference}")
    return value


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise BaselineValidationError(f"unsupported schema type: {expected}")


def validate_instance(
    value: Any,
    schema: dict[str, Any],
    *,
    root_schema: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    """Validate the JSON Schema subset used by this baseline."""

    root_schema = root_schema or schema

    if "$ref" in schema:
        validate_instance(value, _resolve_ref(root_schema, schema["$ref"]), root_schema=root_schema, path=path)
        return

    if "oneOf" in schema:
        matches = 0
        for candidate in schema["oneOf"]:
            try:
                validate_instance(value, candidate, root_schema=root_schema, path=path)
            except BaselineValidationError:
                continue
            matches += 1
        if matches != 1:
            raise BaselineValidationError(f"{path}: expected exactly one oneOf match, found {matches}")
        return

    if "const" in schema and value != schema["const"]:
        raise BaselineValidationError(f"{path}: expected constant {schema['const']!r}, found {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        raise BaselineValidationError(f"{path}: {value!r} is not in {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_matches_type(value, item) for item in allowed_types):
            raise BaselineValidationError(f"{path}: expected type {allowed_types!r}, found {type(value).__name__}")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise BaselineValidationError(f"{path}: string is shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise BaselineValidationError(f"{path}: string is longer than maxLength")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise BaselineValidationError(f"{path}: {value!r} does not match {schema['pattern']!r}")
        if schema.get("format") == "date-time" and value is not None:
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise BaselineValidationError(f"{path}: invalid date-time {value!r}") from exc

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise BaselineValidationError(f"{path}: value is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise BaselineValidationError(f"{path}: value is above maximum")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise BaselineValidationError(f"{path}: array is shorter than minItems")
        if schema.get("uniqueItems"):
            normalized = [json.dumps(item, ensure_ascii=False, sort_keys=True) for item in value]
            if len(normalized) != len(set(normalized)):
                raise BaselineValidationError(f"{path}: array items are not unique")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_instance(item, schema["items"], root_schema=root_schema, path=f"{path}[{index}]")

    if isinstance(value, dict):
        if len(value) < schema.get("minProperties", 0):
            raise BaselineValidationError(f"{path}: object has fewer than minProperties")
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise BaselineValidationError(f"{path}: missing required properties {missing!r}")
        properties = schema.get("properties", {})
        for key, child in value.items():
            if key in properties:
                validate_instance(child, properties[key], root_schema=root_schema, path=f"{path}.{key}")
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                raise BaselineValidationError(f"{path}: unexpected property {key!r}")
            if isinstance(additional, dict):
                validate_instance(child, additional, root_schema=root_schema, path=f"{path}.{key}")


def validate_schema_structure(schema: dict[str, Any], relative_path: str) -> None:
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise BaselineValidationError(f"{relative_path}: Draft 2020-12 declaration is required")
    if schema.get("type") != "object":
        raise BaselineValidationError(f"{relative_path}: top-level type must be object")

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "$ref" in node:
                _resolve_ref(schema, node["$ref"])
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(schema)


def validate_required_files() -> None:
    required = [
        "AGENTS.md",
        "CLAUDE.md",
        ".gitattributes",
        ".claude/settings.json",
        ".claude/agents/client-engineer.md",
        ".claude/agents/game-server-engineer.md",
        ".claude/agents/backend-platform-engineer.md",
        ".claude/agents/code-reviewer.md",
        "docs/constitution/studio-constitution-v1.md",
        "docs/decisions/ADR-0001-r0-baseline.md",
        "docs/approvals/R0-checklist.md",
        "docs/approvals/R0-validation-report.md",
        "agents/agent.schema.json",
        "agents/registry.yaml",
        "contracts/task.schema.json",
        "contracts/handoff.schema.json",
        "contracts/artifact.schema.json",
        "examples/task.example.json",
        "examples/handoff.example.json",
        "examples/artifact.example.json",
        "operations/rooms.yaml",
        "operations/workflow.yaml",
        "operations/permissions.yaml",
        "knowledge/knowledge-item.schema.json",
        "knowledge/lifecycle.yaml",
        "knowledge/retrieval-policy.yaml",
        "knowledge/examples/roulette-policy.example.json",
        "providers/request.schema.json",
        "providers/response.schema.json",
        "providers/registry.yaml",
        "providers/routing-policy.yaml",
        "providers/errors.yaml",
        "providers/examples/request.example.json",
        "providers/examples/response.example.json",
        "evals/eval-case.schema.json",
        "evals/gates.yaml",
        "games/roulette/rules-reference.yaml",
        "games/roulette/test-spec.yaml",
        "games/roulette/fixtures/test-vectors.json",
        "games/roulette/game-brief.yaml",
        "games/roulette/r1-rules-extension.yaml",
        "games/roulette/round-state.yaml",
        "games/roulette/round.schema.json",
        "games/roulette/ledger-transaction.schema.json",
        "games/roulette/fixtures/round.example.json",
        "games/roulette/fixtures/ledger-transaction.example.json",
        "games/roulette/rng-contract.yaml",
        "games/roulette/economy-model.yaml",
        "games/roulette/r1-acceptance.yaml",
        "audit/audit-event.schema.json",
        "policies/security.yaml",
        "policies/cost.yaml",
        "policies/audit.yaml",
        "policies/risk.yaml",
        "approvals/r0-approval.schema.json",
        "approvals/SYS-010-R0-approval.yaml",
        "docs/approvals/SYS-010-R0-approval.md",
        "docs/status/MOBILE-STATUS.md",
        "docs/status/R1-MOBILE-STATUS.md",
        "docs/decisions/ADR-0003-claude-only-programming.md",
        "docs/providers/CLAUDE-CODE-SETUP.md",
        "docs/approvals/R1-checklist.md",
        "docs/approvals/R1-validation-report.md",
        "operations/collaboration.yaml",
        "studio_core/collaboration.py",
        "studio_core/rng.py",
        "studio_core/rng_stats.py",
        "games/roulette/rng-draw-record.schema.json",
        "games/roulette/fixtures/rng-draw-record.example.json",
        "audit/events/R2-RNG-0001-events.json",
        "tasks/R2-RNG-0001.json",
        "artifacts/R2-RNG-0001-artifact.json",
        "handoffs/R2-RNG-0001-handoff.json",
        "docs/games/R2-rng-csprng.md",
        "docs/operations/R2-RNG-0001-recovery.md",
        "docs/approvals/R1-evidence-closure.md",
        "docs/approvals/R2-RNG-0001-validation-report.md",
        "tests/test_rng.py",
        "studio_core/integrity.py",
        "tests/test_integrity.py",
        "providers/connection-proof.schema.json",
        "providers/evidence/SYS-CLD-0011-claude-connection-proof.yaml",
        "tasks/SYS-CLD-0011.json",
        "artifacts/SYS-CLD-0011-artifact.json",
        "handoffs/SYS-CLD-0011-handoff.json",
        "docs/operations/SYS-CLD-0011-codex-claude-collaboration.md",
        "tests/test_collaboration.py",
        # SYS-CI-0012 continuous validation. The workflow itself runs on GitHub; these files
        # are what make the pipeline reproducible from a local checkout.
        ".github/workflows/ci.yml",
        "studio_core/secret_scan.py",
        "scripts/scan_secrets.py",
        "tests/test_secret_scan.py",
        "tests/fixtures/secret_scan/allowlisted-sample.txt",
        "docs/operations/SYS-CI-0012-ci-validation.md",
        "tasks/SYS-CI-0012.json",
        "artifacts/SYS-CI-0012-artifact.json",
        "handoffs/SYS-CI-0012-handoff.json",
        # R2-DBC-0002 durable state boundary. The SQLite databases this unit creates live in
        # temporary directories only and are deliberately absent from the repository surface.
        "studio_core/durable_state.py",
        "games/roulette/durable-state-contract.yaml",
        "games/roulette/durable-state-schema.sql",
        "tests/test_durable_state.py",
        "audit/events/R2-DBC-0002-events.json",
        "tasks/R2-DBC-0002.json",
        "artifacts/R2-DBC-0002-artifact.json",
        "handoffs/R2-DBC-0002-handoff.json",
        "docs/games/R2-durable-state.md",
        "docs/approvals/R2-DBC-0002-validation-report.md",
        "docs/status/R2-STATUS.md",
        "docs/operations/R2-followup-units.md",
        # R4-UI-0006 internal playable slice. The authoritative SQLite database this app
        # creates lives outside the repository by design, so no runtime state file appears
        # here -- ``validate_r4_playable_slice`` asserts the absence rather than the presence.
        "apps/__init__.py",
        "apps/roulette_web/__init__.py",
        "apps/roulette_web/table.py",
        "apps/roulette_web/server.py",
        "apps/roulette_web/static/index.html",
        "apps/roulette_web/static/styles.css",
        "apps/roulette_web/static/app.js",
        "apps/roulette_web/README.md",
        "games/roulette/playable-slice-contract.yaml",
        "tests/test_roulette_web_server.py",
        "tests/test_roulette_web_ui.py",
        "audit/events/R4-UI-0006-events.json",
        "tasks/R4-UI-0006.json",
        "artifacts/R4-UI-0006-artifact.json",
        "handoffs/R4-UI-0006-handoff.json",
        "docs/games/R4-roulette-playable-slice.md",
        "docs/approvals/R4-UI-0006-validation-report.md",
        # SYS-AST-0014 binary asset integrity gate. No asset directory appears here on
        # purpose: the gate replaces a "zero binaries" assertion with an invariant, and an
        # empty tree is a valid, passing input to it.
        "policies/binary-assets.yaml",
        "contracts/asset-manifest.schema.json",
        "studio_core/binary_assets.py",
        "tests/test_binary_assets.py",
        "docs/operations/SYS-AST-0014-binary-asset-integrity-gate.md",
        "audit/events/SYS-AST-0014-events.json",
        # R2-NET-0003 reconnect continuity. There is no new runtime module here on purpose:
        # the unit adds a contract, tests, a validator stage and documentation, and reuses
        # the endpoints that already existed. ``validate_r2_reconnect`` asserts that absence.
        "games/roulette/reconnect-contract.yaml",
        "tests/test_reconnect_continuity.py",
        "audit/events/R2-NET-0003-events.json",
        "tasks/R2-NET-0003.json",
        "artifacts/R2-NET-0003-artifact.json",
        "handoffs/R2-NET-0003-handoff.json",
        "docs/games/R2-reconnect-continuity.md",
        "docs/approvals/R2-NET-0003-validation-report.md",
    ]
    missing = [path for path in required if not (ROOT / path).is_file()]
    if missing:
        raise BaselineValidationError(f"missing required files: {missing!r}")

    constitution = (ROOT / "docs/constitution/studio-constitution-v1.md").read_text(encoding="utf-8")
    for phrase in ("R5", "사용자", "최소 권한", "결정론", "환전·현금 인출"):
        if phrase not in constitution:
            raise BaselineValidationError(f"Constitution is missing required policy phrase: {phrase}")


def validate_agent_registry() -> dict[str, dict[str, Any]]:
    registry = load_yaml("agents/registry.yaml")
    agent_schema = load_json("agents/agent.schema.json")
    validate_schema_structure(agent_schema, "agents/agent.schema.json")

    entries = registry.get("agents")
    if not isinstance(entries, list):
        raise BaselineValidationError("agents/registry.yaml: agents must be a list")
    if registry.get("permanent_agent_count") != 9 or len(entries) != 9:
        raise BaselineValidationError("Agent Registry must contain exactly 9 permanent agents")
    if registry.get("production_schedule_policy") != "prohibited_before_r5":
        raise BaselineValidationError("R5 production schedule prohibition is missing")
    if registry.get("status") != "R0_APPROVED":
        raise BaselineValidationError("Agent Registry must be marked R0_APPROVED after SYS-010")
    if registry.get("approval_record") != "approvals/SYS-010-R0-approval.yaml":
        raise BaselineValidationError("Agent Registry approval_record is missing or incorrect")

    ids = [entry.get("agent_id") for entry in entries]
    slugs = [entry.get("slug") for entry in entries]
    if set(ids) != EXPECTED_AGENT_IDS or len(ids) != len(set(ids)):
        raise BaselineValidationError(f"unexpected or duplicate permanent agent IDs: {ids!r}")
    if len(slugs) != len(set(slugs)):
        raise BaselineValidationError("Agent Registry contains duplicate slugs")

    definitions: dict[str, dict[str, Any]] = {}
    for entry in entries:
        definition_path = entry.get("definition")
        if not isinstance(definition_path, str) or not (ROOT / definition_path).is_file():
            raise BaselineValidationError(f"missing definition for {entry.get('agent_id')}: {definition_path!r}")
        definition = load_yaml(definition_path)
        validate_instance(definition, agent_schema)
        for field in ("agent_id", "slug", "role", "department"):
            if definition[field] != entry[field]:
                raise BaselineValidationError(
                    f"{definition_path}: {field} does not match registry ({definition[field]!r} != {entry[field]!r})"
                )
        definitions[definition["agent_id"]] = definition

    for agent_id, definition in definitions.items():
        unknown_handoffs = set(definition["handoff_to"]) - EXPECTED_AGENT_IDS
        if unknown_handoffs:
            raise BaselineValidationError(f"{agent_id}: unknown handoff agents {sorted(unknown_handoffs)!r}")
        reviewer = definition["evaluation_profile"]["independent_reviewer"]
        if reviewer not in EXPECTED_AGENT_IDS:
            raise BaselineValidationError(f"{agent_id}: unknown independent reviewer {reviewer}")
        if definition["permissions"]["production"] != "no_direct_access":
            raise BaselineValidationError(f"{agent_id}: direct production access is prohibited")

    return definitions


def validate_contracts(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    pairs = {
        "task": ("contracts/task.schema.json", "examples/task.example.json"),
        "handoff": ("contracts/handoff.schema.json", "examples/handoff.example.json"),
        "artifact": ("contracts/artifact.schema.json", "examples/artifact.example.json"),
    }
    instances: dict[str, dict[str, Any]] = {}
    for name, (schema_path, example_path) in pairs.items():
        schema = load_json(schema_path)
        validate_schema_structure(schema, schema_path)
        instance = load_json(example_path)
        validate_instance(instance, schema)
        instances[name] = instance

    task = instances["task"]
    artifact = instances["artifact"]
    handoff = instances["handoff"]
    valid_agents = set(agent_definitions)

    agent_references = {
        task["owner_agent_id"],
        *[item for item in task["approvers"] if item.startswith("A-")],
        artifact["source"]["created_by"],
        *artifact["reviewers"],
        handoff["from_agent_id"],
        handoff["to_agent_id"],
        *[risk["owner_agent_id"] for risk in handoff["known_risks"]],
    }
    unknown_agents = {item for item in agent_references if item.startswith("A-")} - valid_agents
    if unknown_agents:
        raise BaselineValidationError(f"examples reference unknown agents: {sorted(unknown_agents)!r}")
    if task["task_id"] != artifact["task_id"] or task["task_id"] != handoff["task_id"]:
        raise BaselineValidationError("task_id does not match across examples")
    if task["project_id"] != artifact["project_id"]:
        raise BaselineValidationError("project_id does not match between task and artifact")
    if artifact["artifact_id"] not in handoff["artifact_refs"]:
        raise BaselineValidationError("handoff does not reference the submitted artifact")
    if handoff["from_agent_id"] != task["owner_agent_id"]:
        raise BaselineValidationError("handoff sender must be the example task owner")

    return instances


def validate_operations(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rooms = load_yaml("operations/rooms.yaml")
    workflow = load_yaml("operations/workflow.yaml")
    permissions = load_yaml("operations/permissions.yaml")

    room_entries = rooms.get("rooms")
    if not isinstance(room_entries, list) or len(room_entries) != 9:
        raise BaselineValidationError("operations/rooms.yaml must define exactly 9 department hubs")
    hub_names = [item["hub"] for item in room_entries]
    if len(hub_names) != len(set(hub_names)):
        raise BaselineValidationError("operations/rooms.yaml contains duplicate hubs")
    owner_by_hub = {item["hub"]: item["owner"] for item in room_entries}
    for agent_id, definition in agent_definitions.items():
        hub = definition["default_room"]
        if hub not in owner_by_hub or owner_by_hub[hub] != agent_id:
            raise BaselineValidationError(f"{agent_id}: default room is not owned by the agent")
    for room in room_entries:
        if len(room["subrooms"]) != len(set(room["subrooms"])) or not room["subrooms"]:
            raise BaselineValidationError(f"{room['hub']}: subrooms must be non-empty and unique")
        unknown_members = set(room["members"]) - EXPECTED_AGENT_IDS
        if unknown_members:
            raise BaselineValidationError(f"{room['hub']}: unknown members {sorted(unknown_members)!r}")

    task_states = set(load_json("contracts/task.schema.json")["properties"]["status"]["enum"])
    if set(workflow.get("states", [])) != task_states:
        raise BaselineValidationError("workflow states must exactly match Task Contract states")
    transition_pairs: set[tuple[str, str]] = set()
    for transition in workflow.get("transitions", []):
        pair = (transition["from"], transition["to"])
        if pair in transition_pairs or not set(pair) <= task_states:
            raise BaselineValidationError(f"invalid or duplicate workflow transition: {pair!r}")
        transition_pairs.add(pair)
    if any((source, "DONE") in transition_pairs for source in task_states - {"QA"}):
        raise BaselineValidationError("DONE must only be reachable from QA")
    if ("QA", "DONE") not in transition_pairs:
        raise BaselineValidationError("workflow is missing QA -> DONE")
    if set(workflow.get("done_gate", {})) != {"LOW", "MEDIUM", "HIGH"}:
        raise BaselineValidationError("workflow must define all risk-class DONE gates")
    if not {"A-50", "A-02", "A-00"} <= set(workflow["done_gate"]["HIGH"]):
        raise BaselineValidationError("HIGH DONE gate is missing mandatory reviewers")

    if permissions.get("mode") != "deny_by_default" or permissions.get("production_direct_access") != "denied":
        raise BaselineValidationError("permissions must be default-deny with no direct production access")
    if set(permissions.get("roles", {})) != EXPECTED_AGENT_IDS:
        raise BaselineValidationError("permissions must define exactly the 9 permanent agents")
    required_human = {"budget.final_approve", "legal.final_approve", "release.final_approve", "r0.final_approve"}
    if not required_human <= set(permissions.get("human_only", [])):
        raise BaselineValidationError("human-only approval capabilities are incomplete")
    return {"rooms": rooms, "workflow": workflow, "permissions": permissions}


def validate_knowledge(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    schema_path = "knowledge/knowledge-item.schema.json"
    schema = load_json(schema_path)
    validate_schema_structure(schema, schema_path)
    item = load_json("knowledge/examples/roulette-policy.example.json")
    validate_instance(item, schema)
    lifecycle = load_yaml("knowledge/lifecycle.yaml")
    retrieval = load_yaml("knowledge/retrieval-policy.yaml")
    if lifecycle.get("retrievable_state") != "APPROVED" or retrieval.get("required_status") != "APPROVED":
        raise BaselineValidationError("only APPROVED knowledge may be retrievable")
    if lifecycle.get("guards", {}).get("automatic_conversation_ingest") != "denied":
        raise BaselineValidationError("automatic conversation knowledge ingestion must be denied")
    if item["provenance"]["captured_by"] == item["quality"]["reviewer"]:
        raise BaselineValidationError("knowledge creator and reviewer must be separated")
    allowed = set(item["retrieval"]["allowed_agents"])
    if "*" not in allowed and not allowed <= set(agent_definitions):
        raise BaselineValidationError("knowledge item references unknown allowed agents")
    if item["status"] == "APPROVED" and item.get("approved_at") is None:
        raise BaselineValidationError("approved knowledge requires approved_at")
    if item["content_ref"].startswith("repo://"):
        referenced_path = item["content_ref"].removeprefix("repo://")
        content_path = ROOT / referenced_path
        if not content_path.is_file():
            raise BaselineValidationError(f"knowledge content_ref does not exist: {referenced_path}")
        decision = verify_file(content_path, item["provenance"]["content_hash"], label=referenced_path)
        if not decision.matches:
            raise BaselineValidationError(f"knowledge provenance hash does not match content_ref: {decision.message}")
    return item


def validate_providers(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    pairs = {
        "request": ("providers/request.schema.json", "providers/examples/request.example.json"),
        "response": ("providers/response.schema.json", "providers/examples/response.example.json"),
    }
    values: dict[str, dict[str, Any]] = {}
    for name, (schema_path, example_path) in pairs.items():
        schema = load_json(schema_path)
        validate_schema_structure(schema, schema_path)
        value = load_json(example_path)
        validate_instance(value, schema)
        values[name] = value
    request, response = values["request"], values["response"]
    if request["request_id"] != response["request_id"] or request["task_id"] != response["task_id"]:
        raise BaselineValidationError("provider request and response references do not match")
    if request["requesting_agent_id"] not in agent_definitions:
        raise BaselineValidationError("provider request references an unknown agent")

    registry = load_yaml("providers/registry.yaml")
    routing = load_yaml("providers/routing-policy.yaml")
    providers = registry.get("providers", [])
    provider_ids = [item["provider_id"] for item in providers]
    if len(provider_ids) != len(set(provider_ids)) or not providers:
        raise BaselineValidationError("provider registry must contain unique providers")
    for provider in providers:
        if not provider["credential_ref"].startswith("secret-ref://"):
            raise BaselineValidationError(f"{provider['provider_id']}: credentials must be references")
        if provider["status"] not in {"ENABLED", "DISABLED_UNTIL_CONFIGURED", "DISABLED"}:
            raise BaselineValidationError(f"{provider['provider_id']}: unsupported status")
    provider_map = {item["provider_id"]: item for item in providers}
    if response["provider_id"] not in provider_map:
        raise BaselineValidationError("provider response references an unknown provider")
    for capability, route in routing.get("routes", {}).items():
        candidates = [route["preferred"], *route.get("fallbacks", [])]
        if not candidates or any(item not in provider_map for item in candidates):
            raise BaselineValidationError(f"{capability}: route references an unknown provider")
        if any(capability not in provider_map[item]["capabilities"] for item in candidates):
            raise BaselineValidationError(f"{capability}: route provider lacks capability")
    if routing.get("production_write") != "denied" or not routing.get("human_review_required"):
        raise BaselineValidationError("provider routing must deny production writes and require review")
    if provider_map.get("codex_primary", {}).get("status") != "DISABLED":
        raise BaselineValidationError("Codex programming provider must remain disabled by ADR-0003")
    claude_status = provider_map.get("claude_agent", {}).get("status")
    if claude_status == "ENABLED":
        decision = evaluate_claude_activation(claude_status)
        if not decision.allowed:
            raise BaselineValidationError(f"Claude activation is not backed by connection proof: {decision.message}")
    elif claude_status != "DISABLED_UNTIL_CONFIGURED":
        raise BaselineValidationError("Claude must remain disabled until a real connection health check passes")
    code_route = routing.get("routes", {}).get("code", {})
    if code_route.get("preferred") != "claude_agent" or code_route.get("fallbacks") != []:
        raise BaselineValidationError("programming must route only to Claude with no model fallback")
    routed_providers = {
        provider_id
        for route in routing.get("routes", {}).values()
        for provider_id in [route["preferred"], *route.get("fallbacks", [])]
    }
    if "codex_primary" in routed_providers:
        raise BaselineValidationError("Codex must not appear in an active provider route")
    no_fallback = routing.get("no_fallback_policy", {})
    if no_fallback.get("programming_provider") != "claude_agent" or no_fallback.get("on_unavailable") != "BLOCKED" or no_fallback.get("codex_substitution") != "denied":
        raise BaselineValidationError("Claude-only unavailable and substitution behavior is incomplete")
    return {"request": request, "response": response, "registry": registry, "routing": routing}


def load_connection_proof(provider_id: str) -> dict[str, Any] | None:
    """Return the single connection proof recorded for a provider, if one exists."""

    evidence_dir = ROOT / "providers" / "evidence"
    if not evidence_dir.is_dir():
        return None
    matches = []
    for path in sorted(evidence_dir.glob("*.yaml")):
        proof = load_yaml(str(path.relative_to(ROOT)).replace("\\", "/"))
        if proof.get("provider_id") == provider_id:
            matches.append(proof)
    if len(matches) > 1:
        raise BaselineValidationError(f"{provider_id}: multiple connection proofs are ambiguous")
    return matches[0] if matches else None


def evaluate_claude_activation(target_status: str) -> Any:
    """Gate claude_agent promotion on a schema-valid, fully passing connection proof."""

    from studio_core.collaboration import evaluate_provider_activation

    protocol = load_yaml("operations/collaboration.yaml")
    proof = load_connection_proof("claude_agent")
    if proof is not None:
        validate_instance(proof, load_json("providers/connection-proof.schema.json"))
    return evaluate_provider_activation("claude_agent", target_status, proof, protocol=protocol)


def _iter_text_files(relative_path: str) -> list[Path]:
    target = ROOT / relative_path
    if target.is_file():
        return [target]
    if not target.is_dir():
        return []
    return sorted(path for path in target.rglob("*") if path.is_file() and path.suffix in {".json", ".yaml", ".md"})


#: Directory names that are not part of the hashed repository surface: caches, build output,
#: virtual environments, and the scratch worktrees an internal reviewer materialises.
NON_REPOSITORY_DIRS = frozenset(
    {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "build", "dist", "worktrees"}
)


def repository_files(base: Path | None = None) -> list[Path]:
    """Return every committed-surface file under ``base``, skipping caches and scratch copies."""

    root = ROOT if base is None else Path(base)
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if NON_REPOSITORY_DIRS.intersection(path.relative_to(root).parts[:-1]):
            continue
        found.append(path)
    return found


def hashed_content_references() -> list[tuple[str, str, str]]:
    """Collect every ``(declaring file, uri, expected hash)`` binding in the control plane."""

    references: list[tuple[str, str, str]] = []
    for path in sorted((ROOT / "tasks").glob("*.json")):
        contract = load_json(f"tasks/{path.name}")
        for item in contract.get("inputs", []):
            references.append((f"tasks/{path.name}", item["uri"], item["content_hash"]))
    for path in sorted((ROOT / "artifacts").glob("*.json")):
        artifact = load_json(f"artifacts/{path.name}")
        references.append((f"artifacts/{path.name}", artifact["uri"], artifact["content_hash"]))
    knowledge_path = "knowledge/examples/roulette-policy.example.json"
    knowledge = load_json(knowledge_path)
    references.append((knowledge_path, knowledge["content_ref"], knowledge["provenance"]["content_hash"]))
    return references


def validate_content_integrity() -> dict[str, Any]:
    """Verify that every declared ``content_hash`` matches its file's canonical representation.

    The canonical form is defined in ``studio_core.integrity``: LF-normalised UTF-8 for text,
    raw bytes for binaries. Hashing the bytes as they sit on disk instead would make a
    Windows CRLF checkout report tampering against artifacts that are byte-identical in Git,
    and would make the check pass or fail on the reviewer's platform rather than on content.
    """

    attributes_path = ROOT / ".gitattributes"
    if not attributes_path.is_file():
        raise BaselineValidationError(
            ".gitattributes is required so Git stores the LF text form the artifact hashes assume"
        )
    directives = [
        line.split("#", 1)[0].split()
        for line in attributes_path.read_text(encoding="utf-8").splitlines()
    ]
    if not any(fields and fields[0] == "*" and "text=auto" in fields[1:] for fields in directives):
        raise BaselineValidationError(".gitattributes must pin '* text=auto' for every text blob")

    # Prove the canonical property on real repository content rather than asserting it in
    # prose: the same text must hash identically from either line ending, a genuine edit must
    # not, and binary bytes must survive untouched.
    sample = (ROOT / "operations/collaboration.yaml").read_bytes()
    as_lf = sample.replace(b"\r\n", b"\n")
    as_crlf = as_lf.replace(b"\n", b"\r\n")
    if content_hash(as_lf) != content_hash(as_crlf):
        raise BaselineValidationError("canonical text hashing is not line-ending independent")
    if content_hash(as_lf) == content_hash(as_lf + b"# tampered\n"):
        raise BaselineValidationError("canonical text hashing does not detect appended content")
    binary_sample = b"\x00head\r\ntail"
    if canonical_bytes(binary_sample) != binary_sample:
        raise BaselineValidationError("binary content must be hashed as raw bytes")

    kinds: dict[str, int] = {"text": 0, "binary": 0}
    binaries: list[str] = []
    for path in repository_files():
        relative = path.relative_to(ROOT).as_posix()
        try:
            kind = classify(path.read_bytes(), label=relative)
        except IntegrityError as exc:
            raise BaselineValidationError(str(exc)) from exc
        kinds[kind] += 1
        if kind == "binary":
            binaries.append(relative)

    verified: list[str] = []
    external: list[str] = []
    for source, uri, expected in hashed_content_references():
        if not uri.startswith("repo://"):
            external.append(f"{source} -> {uri}")
            continue
        relative = uri.removeprefix("repo://")
        if not (ROOT / relative).is_file():
            raise BaselineValidationError(f"{source}: hashed reference does not exist: {relative}")
        decision = verify_file(ROOT / relative, expected, label=relative)
        if not decision.matches:
            raise BaselineValidationError(f"{source}: {decision.message}")
        verified.append(f"{source} -> {relative}")

    # SYS-AST-0014: the classification above used to end at a count, and the R2 suite asserted
    # that count was zero. A count is not an integrity property -- it rejects the first
    # legitimate, fully traced PNG and would admit anything at all once relaxed. Every binary
    # the walk found is put through the default-deny gate instead, and the verified paths are
    # published alongside the existing text counts, reference resolutions and hash checks
    # rather than in place of them.
    from studio_core.binary_assets import format_rejections, validate_binary_assets  # noqa: PLC0415

    gate = validate_binary_assets(ROOT, binaries, manifest_validator=validate_instance)
    if not gate.ok:
        raise BaselineValidationError(f"binary asset gate rejected {len(gate.rejections)} item(s): {format_rejections(gate.rejections)}")

    return {"verified": verified, "external": external, "files": kinds, "binary_assets": gate.to_dict()}


def validate_binary_asset_policy(root: Path | None = None) -> dict[str, Any]:
    """Validate the SYS-AST-0014 binary asset policy, its manifest schema and its Git pinning.

    Structural only, and deliberately separate from the per-file gate in
    ``validate_content_integrity``: the policy has to be well formed and default-deny even when
    the repository holds no binary at all, which is exactly the state it is introduced in.

    ``root`` defaults to the repository. Pointing it at a copy lets the negative tests prove a
    weakened policy or an unpinned extension is actually rejected without writing to tracked
    files.
    """

    from studio_core.binary_assets import (  # noqa: PLC0415
        BinaryAssetError,
        load_policy,
        unpinned_extensions,
    )

    base = ROOT if root is None else Path(root)

    try:
        policy = load_policy(base)
    except BinaryAssetError as exc:
        raise BaselineValidationError(f"policies/binary-assets.yaml: [{exc.code}] {exc.message}") from exc

    schema_relative = policy.manifest_schema
    schema_path = base / schema_relative
    if not schema_path.is_file():
        raise BaselineValidationError(f"the binary asset policy names a missing manifest schema: {schema_relative}")
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, dict):
        raise BaselineValidationError(f"{schema_relative}: root must be an object")
    validate_schema_structure(schema, schema_relative)
    entry_schema = schema.get("$defs", {}).get("assetEntry", {})
    for field in ("path", "content_hash", "byte_size"):
        if field not in entry_schema.get("required", []):
            raise BaselineValidationError(f"{schema_relative}: an asset entry must require {field}")

    attributes_path = base / ".gitattributes"
    if not attributes_path.is_file():
        raise BaselineValidationError(".gitattributes is required to pin allowed binary extensions")
    unpinned = unpinned_extensions(policy, attributes_path.read_text(encoding="utf-8"))
    if unpinned:
        raise BaselineValidationError(
            f".gitattributes does not pin these policy-allowed extensions as binary: {list(unpinned)!r}"
        )

    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "allowed_roots": list(policy.allowed_roots),
        "allowed_extensions": list(policy.allowed_extensions),
    }


#: Files ``validate_r2_reconnect`` reads. Exposed so the negative tests can materialise an
#: isolated copy and prove each declared fact is actually checked, without ever writing to a
#: tracked file.
R2_NET_INPUT_FILES: tuple[str, ...] = (
    "games/roulette/reconnect-contract.yaml",
    "games/roulette/round-state.yaml",
    "games/roulette/playable-slice-contract.yaml",
    # The whole package directory, because the check is that no *fourth* module appeared.
    "apps/roulette_web/__init__.py",
    "apps/roulette_web/server.py",
    "apps/roulette_web/table.py",
    "apps/roulette_web/static/app.js",
    "apps/roulette_web/static/index.html",
    "apps/roulette_web/static/styles.css",
    "tests/test_roulette_web_server.py",
    "tests/test_roulette_web_ui.py",
    "docs/status/R2-STATUS.md",
    "tasks/R2-NET-0003.json",
    "tasks/R4-ART-0007.json",
    # The re-pin scope check walks every contract under ``tasks/``, so the three that pin the
    # validator have to be present or an isolated copy would report an empty scope.
    "tasks/SYS-AST-0014.json",
    "tasks/SYS-CI-0012.json",
    "tasks/SYS-QA-0015.json",
    "artifacts/R2-NET-0003-artifact.json",
    "audit/audit-event.schema.json",
    "audit/events/R2-NET-0003-events.json",
    "docs/games/R2-reconnect-continuity.md",
    "docs/approvals/R2-NET-0003-validation-report.md",
    "docs/operations/R2-followup-units.md",
)

#: Audit actions the R2-NET-0003 record must carry. The interrupted first attempt is one of
#: them on purpose: it modified a file the contract had not declared, and a later reader must
#: be able to see that it happened and was withdrawn rather than infer it from a diff.
R2_NET_REQUIRED_AUDIT_ACTIONS = frozenset(
    {
        "TASK_CONTRACT_ISSUED_READY",
        "PRE_IMPLEMENTATION_ARTIFACT_REGISTERED",
        "IMPLEMENTATION_ATTEMPT_INTERRUPTED_AND_DISCARDED",
        "TASK_CONTRACT_AMENDED_SMALLER_SCOPE",
        "RECONNECT_IMPLEMENTATION_COMPLETED",
        "VALIDATION_COMMANDS_REPLAYED",
    }
)

#: Markers that must be present in the client for the reconnect behaviour to exist at all,
#: and tokens whose presence would mean the client had started deciding things or had grown
#: the route this unit was explicitly told not to add.
R2_NET_CLIENT_REQUIRED = (
    "function rehydrate(",
    "function recoverLostSpin(",
    "function showSettledSpin(",
    "/api/state",
    "/api/spin",
    "accepts_bets",
)
R2_NET_CLIENT_PROHIBITED = ("/api/resume", "reconnect.py")


def validate_r2_reconnect(root: Path | None = None) -> dict[str, Any]:
    """Validate the R2-NET-0003 reconnect contract against the code that already exists.

    ``root`` defaults to the repository. Pointing it at a copy lets the negative tests prove
    a declaration that disagrees with the implementation is actually rejected without writing
    to tracked files.

    The interesting property of this unit is what it did *not* do, so most of what follows
    measures absence: no new route, no new runtime module, no drift in the files that other
    contracts pin. Those are checked against the live constants and the real directory rather
    than against prose, because "we did not add an endpoint" is only worth writing down if
    something fails when it stops being true.
    """

    base = ROOT if root is None else Path(root)

    def _json(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be an object")
        return value

    def _yaml(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be a mapping")
        return value

    def _text(relative_path: str) -> str:
        return (base / relative_path).read_text(encoding="utf-8")

    from apps.roulette_web.server import ROUTES, SECURITY_HEADERS
    from apps.roulette_web.table import BETS_ACCEPTED_IN, CLIENT_AUTHORITY_FIELDS

    contract_path = "games/roulette/reconnect-contract.yaml"
    contract = _yaml(contract_path)

    # -- the shape of the change: nothing was added ----------------------------------------
    design = contract.get("design", {})
    for key in ("new_http_routes", "new_runtime_modules"):
        if design.get(key) != 0:
            raise BaselineValidationError(f"{contract_path}: design.{key} must be declared 0")
    for key in ("server_api_changed", "server_constructor_changed"):
        if design.get(key) is not False:
            raise BaselineValidationError(f"{contract_path}: design.{key} must be declared false")
    if design.get("rehydration_endpoint") != "/api/state" or design.get("rehydration_method") != "GET":
        raise BaselineValidationError(f"{contract_path}: rehydration must be the existing GET /api/state")
    if (
        design.get("response_loss_recovery_endpoint") != "/api/spin"
        or design.get("response_loss_recovery_key") != "request_id"
    ):
        raise BaselineValidationError(
            f"{contract_path}: response-loss recovery must be the existing POST /api/spin retry"
        )
    for endpoint in (design.get("rehydration_endpoint"), design.get("response_loss_recovery_endpoint")):
        if endpoint not in ROUTES:
            raise BaselineValidationError(f"{contract_path}: {endpoint!r} is not a served route")

    declared_modules = list(design.get("runtime_modules", []))
    actual_modules = sorted(path.name for path in (base / "apps/roulette_web").glob("*.py"))
    if declared_modules != actual_modules:
        raise BaselineValidationError(
            f"{contract_path}: declared runtime modules {declared_modules!r} are not the "
            f"modules present {actual_modules!r}"
        )

    preserved = contract.get("preserved_boundaries", {})
    if preserved.get("route_count") != len(ROUTES):
        raise BaselineValidationError(
            f"{contract_path}: preserved_boundaries.route_count is {preserved.get('route_count')!r}, "
            f"the server serves {len(ROUTES)}"
        )
    if preserved.get("security_header_count") != len(SECURITY_HEADERS):
        raise BaselineValidationError(
            f"{contract_path}: preserved_boundaries.security_header_count does not match the server"
        )
    for key in (
        "rules_changed",
        "payout_schedule_changed",
        "rng_algorithm_changed",
        "ledger_semantics_changed",
        "asset_or_image_paths_changed",
    ):
        if preserved.get(key) is not False:
            raise BaselineValidationError(f"{contract_path}: preserved_boundaries.{key} must be false")

    # -- the authority and continuity rules must be the implemented ones --------------------
    authority = contract.get("authority", {})
    if authority.get("client_authority") != "denied":
        raise BaselineValidationError(f"{contract_path}: the client authority boundary is not closed")
    for key in (
        "client_supplied_state_merged_on_reconnect",
        "client_computes_result",
        "client_computes_payout",
        "client_computes_balance",
    ):
        if authority.get(key) is not False:
            raise BaselineValidationError(f"{contract_path}: authority.{key} must be declared false")
    if authority.get("rejected_client_field_refusal_code") != "CLIENT_AUTHORITY_DENIED":
        raise BaselineValidationError(f"{contract_path}: the client-authority refusal code has drifted")

    betting = contract.get("betting_continuity", {})
    if betting.get("accept_bets_only_in") != BETS_ACCEPTED_IN.value:
        raise BaselineValidationError(
            f"{contract_path}: betting_continuity.accept_bets_only_in is "
            f"{betting.get('accept_bets_only_in')!r}, the table accepts bets in "
            f"{BETS_ACCEPTED_IN.value!r}"
        )
    guards = _yaml("games/roulette/round-state.yaml")["guards"]
    if betting.get("accept_bets_only_in") != guards["accept_bets_only_in"]:
        raise BaselineValidationError(
            f"{contract_path}: accept_bets_only_in disagrees with games/roulette/round-state.yaml"
        )
    for key in ("uncommitted_bets_durable", "bets_restored_on_reconnect"):
        if betting.get(key) is not False:
            raise BaselineValidationError(f"{contract_path}: betting_continuity.{key} must be false")
    if betting.get("client_drops_drafts_when_not_accepting_bets") is not True:
        raise BaselineValidationError(
            f"{contract_path}: the client must drop drafts once the round stops accepting bets"
        )

    recovery = contract.get("settlement_recovery", {})
    if recovery.get("retry_uses_same_request_id") is not True:
        raise BaselineValidationError(f"{contract_path}: recovery must retry the same request_id")
    for key in (
        "second_draw",
        "second_entropy_consumption",
        "second_ledger_settlement",
        "balance_moves_on_retry",
    ):
        if recovery.get(key) != "prohibited":
            raise BaselineValidationError(
                f"{contract_path}: settlement_recovery.{key} must be 'prohibited', found "
                f"{recovery.get(key)!r}"
            )
    restart_codes = list(recovery.get("after_restart_refusal_codes", []))
    # After a restart the journal is empty and a fresh round is open, so which refusal comes
    # back depends on that round's state. Both of these are reachable and both fail closed;
    # a declaration naming only one would be a half-truth the client could not act on.
    if not {"NO_BETS", "DRAW_DENIED"} <= set(restart_codes):
        raise BaselineValidationError(
            f"{contract_path}: after_restart_refusal_codes must cover both the empty new round "
            f"(NO_BETS) and the request-fingerprint conflict (DRAW_DENIED), found {restart_codes!r}"
        )
    # The store-replay code exists in the table but is not reachable on this path, because a
    # restarted table mints round identifiers under a new instance token. Declaring it as an
    # after-restart refusal would be untrue, so it is recorded separately and pinned as
    # unreachable; if that ever changes, this check is what says so.
    if recovery.get("store_replay_refusal_code") != "REQUEST_ID_ALREADY_USED":
        raise BaselineValidationError(f"{contract_path}: the store-replay refusal code has drifted")
    if recovery.get("store_replay_reachable_after_restart") is not False:
        raise BaselineValidationError(
            f"{contract_path}: store_replay_reachable_after_restart must be declared false"
        )
    if "REQUEST_ID_ALREADY_USED" in restart_codes:
        raise BaselineValidationError(
            f"{contract_path}: REQUEST_ID_ALREADY_USED is not reachable after a restart and must "
            "not be listed as an after-restart refusal"
        )
    if recovery.get("client_treats_refusal_as_recovery_signal") is not True:
        raise BaselineValidationError(
            f"{contract_path}: the client must read an after-restart refusal as a recovery signal"
        )
    slice_contract = _yaml("games/roulette/playable-slice-contract.yaml")
    declared_codes = set(slice_contract["error_codes"]["authority"]) | set(
        slice_contract["error_codes"]["transport"]
    )
    for code in (
        *restart_codes,
        recovery.get("store_replay_refusal_code"),
        betting.get("post_open_bet_submission_refusal_code"),
        authority.get("rejected_client_field_refusal_code"),
    ):
        # This unit introduces no new refusal code; every one it names must already be part
        # of the slice's published vocabulary.
        if code not in declared_codes:
            raise BaselineValidationError(
                f"{contract_path}: {code!r} is not declared by the playable slice contract"
            )

    # -- the client must actually reconnect, and must still decide nothing -------------------
    script = _text("apps/roulette_web/static/app.js")
    missing = [marker for marker in R2_NET_CLIENT_REQUIRED if marker not in script]
    if missing:
        raise BaselineValidationError(f"app.js does not carry the reconnect behaviour: {missing!r}")
    present = [needle for needle in R2_NET_CLIENT_PROHIBITED if needle in script]
    if present:
        raise BaselineValidationError(f"app.js names a surface this unit must not add: {present!r}")

    # -- the integrity cascade must stop where the contract says it does ---------------------
    task = _json("tasks/R2-NET-0003.json")
    if task["status"] not in {"READY", "IN_PROGRESS", "REVIEW", "QA"} or task["risk_class"] != "HIGH":
        raise BaselineValidationError("R2-NET-0003 must remain a HIGH risk task under an open gate")
    if not {"A-50", "A-02", "A-00"} <= set(task["approvers"]):
        raise BaselineValidationError("a HIGH risk reconnect task requires the mandatory reviewers")
    pinned = {item["uri"].removeprefix("repo://"): item["content_hash"] for item in task["inputs"]}

    frozen = contract.get("frozen_paths", {}).get("paths", [])
    expected_frozen = {
        "apps/roulette_web/server.py",
        "apps/roulette_web/table.py",
        "games/roulette/playable-slice-contract.yaml",
        "docs/status/R2-STATUS.md",
        "tasks/R4-ART-0007.json",
    }
    if not expected_frozen <= set(frozen):
        raise BaselineValidationError(
            f"{contract_path}: frozen_paths omits {sorted(expected_frozen - set(frozen))!r}; these "
            "cascade into R4-ART-0007 when modified"
        )
    for relative in frozen:
        expected = pinned.get(relative)
        if expected is None:
            raise BaselineValidationError(
                f"tasks/R2-NET-0003.json must pin the frozen path {relative} as an input"
            )
        decision = verify_file(base / relative, expected, label=relative)
        if not decision.matches:
            raise BaselineValidationError(f"a frozen path was modified by this unit: {decision.message}")

    repin = contract.get("repin_scope", {})
    if repin.get("target") != "scripts/validate_baseline.py" or repin.get("reaches_r4_art_0007") is not False:
        raise BaselineValidationError(f"{contract_path}: the re-pin scope declaration is not the bounded one")
    declared_repins = set(repin.get("contracts", []))
    actual_repins = set()
    for path in sorted((base / "tasks").glob("*.json")):
        candidate = _json(f"tasks/{path.name}")
        for item in candidate.get("inputs", []):
            if item["uri"] == "repo://scripts/validate_baseline.py":
                actual_repins.add(f"tasks/{path.name}")
    if declared_repins != actual_repins:
        raise BaselineValidationError(
            f"{contract_path}: repin_scope declares {sorted(declared_repins)!r} but the validator is "
            f"pinned by {sorted(actual_repins)!r}"
        )

    # -- the interrupted first attempt must stay on the record -------------------------------
    from studio_core.rng import verify_audit_chain  # noqa: PLC0415

    audit_schema = _json("audit/audit-event.schema.json")
    events_document = _json("audit/events/R2-NET-0003-events.json")
    unit_events = events_document["events"]
    for event in unit_events:
        validate_instance(event, audit_schema)
        if event["task_id"] != "R2-NET-0003":
            raise BaselineValidationError("a reconnect audit event is attached to the wrong task")
    chain_problems = verify_audit_chain(unit_events)
    if chain_problems:
        raise BaselineValidationError(f"the R2-NET-0003 audit chain is broken: {chain_problems!r}")
    actions = {item.get("action") for item in unit_events}
    missing_actions = R2_NET_REQUIRED_AUDIT_ACTIONS - actions
    if missing_actions:
        raise BaselineValidationError(
            f"audit/events/R2-NET-0003-events.json is missing actions {sorted(missing_actions)!r}"
        )
    artifact = _json("artifacts/R2-NET-0003-artifact.json")
    specification = artifact.get("specification", {})
    if specification.get("first_implementation_attempt") != "INTERRUPTED_AND_DISCARDED":
        raise BaselineValidationError(
            "the R2-NET-0003 artifact must keep recording the interrupted first attempt"
        )
    if specification.get("r4_art_0007_touched") is not False:
        raise BaselineValidationError("the R2-NET-0003 artifact must declare R4-ART-0007 untouched")

    return {
        "new_http_routes": design["new_http_routes"],
        "new_runtime_modules": design["new_runtime_modules"],
        "routes": sorted(ROUTES),
        "runtime_modules": actual_modules,
        "frozen_paths_verified": len(frozen),
        "repin_contracts": sorted(actual_repins),
        "client_authority_fields": len(CLIENT_AUTHORITY_FIELDS),
    }


def validate_collaboration(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Validate the SYS-CLD-0011 Codex/Claude collaboration protocol and its task artifacts."""

    from studio_core.collaboration import (
        evaluate_delegation,
        evaluate_independent_verification,
        evaluate_role_action,
        missing_evidence_commands,
        scan_for_plaintext_secrets,
    )

    protocol = load_yaml("operations/collaboration.yaml")
    proof_schema_path = "providers/connection-proof.schema.json"
    proof_schema = load_json(proof_schema_path)
    validate_schema_structure(proof_schema, proof_schema_path)

    roles = protocol["roles"]
    if set(roles) != {"issuer", "implementer", "independent_verifier"}:
        raise BaselineValidationError("collaboration protocol must define issuer, implementer, and verifier roles")
    if roles["implementer"]["console"] == roles["independent_verifier"]["console"]:
        raise BaselineValidationError("implementation and independent verification must use different consoles")
    if roles["implementer"]["provider_id"] != "claude_agent":
        raise BaselineValidationError("Claude must remain the sole implementation provider")
    for role in ("issuer", "independent_verifier"):
        if evaluate_role_action(role, "code_generation", protocol=protocol).allowed:
            raise BaselineValidationError(f"{role} must never be allowed to generate code")
    if evaluate_role_action("implementer", "final_qa_approval", protocol=protocol).allowed:
        raise BaselineValidationError("the implementer must never issue the final QA gate")
    for role, definition in roles.items():
        unknown = set(definition["acts_for"]) - EXPECTED_AGENT_IDS
        if unknown:
            raise BaselineValidationError(f"{role}: unknown agents {sorted(unknown)!r}")

    duties = protocol["separation_of_duties"]
    for key in ("generator_is_reviewer", "generator_is_final_approver", "self_approval"):
        if duties[key] != "denied":
            raise BaselineValidationError(f"collaboration protocol must deny {key}")
    if not {"A-50", "USER"} <= set(duties["final_gate"]):
        raise BaselineValidationError("final QA gate must stay with A-50 and the user")

    credentials = protocol["credentials"]
    if credentials["storage"] not in credentials["allowed_storage"]:
        raise BaselineValidationError("declared credential storage is not in the allowed list")
    if any(credentials[target] != "prohibited" for target in ("repository_values", "prompt_values", "log_values")):
        raise BaselineValidationError("credential values must be prohibited in repository, prompts, and logs")
    if credentials["reference_prefix"] != "secret-ref://":
        raise BaselineValidationError("credential references must use the secret-ref:// scheme")

    boundary = protocol["adr_0003_boundary"]
    if not boundary["claude_is_sole_programming_provider"]:
        raise BaselineValidationError("ADR-0003 sole-provider boundary must be preserved")
    if boundary["codex_substitution_on_claude_unavailable"] != "denied":
        raise BaselineValidationError("Codex substitution must stay denied when Claude is unavailable")
    if protocol["provider_activation"]["codex_code_provider"] != "denied":
        raise BaselineValidationError("Codex must never be activated as a code provider")
    for guard in ("commit_without_user_approval", "push_without_user_approval", "production_direct_access"):
        if protocol["guards"][guard] != "denied":
            raise BaselineValidationError(f"collaboration guard {guard} must be denied")

    instructions = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    required_checks = protocol["completion_gate"]["required_checks"]
    for command in required_checks:
        if command not in instructions:
            raise BaselineValidationError(f"completion gate command is not declared in CLAUDE.md: {command}")

    activation = protocol["provider_activation"]
    proof = load_connection_proof(activation["provider_id"])
    if proof is None:
        raise BaselineValidationError("a connection proof record is required for the gated provider")
    validate_instance(proof, proof_schema)
    if proof["recorded_by"] == proof["verified_by"]:
        raise BaselineValidationError("connection proof recorder and verifier must be different actors")
    for actor in (proof["recorded_by"], proof["verified_by"]):
        if actor != "USER" and actor not in agent_definitions:
            raise BaselineValidationError(f"connection proof references an unknown actor: {actor}")

    registry = load_yaml("providers/registry.yaml")
    provider_map = {item["provider_id"]: item for item in registry["providers"]}
    claude_status = provider_map[activation["provider_id"]]["status"]
    # Always ask whether a promotion would be allowed, so the recorded status and the evidence
    # cannot drift apart in either direction.
    promotion = evaluate_claude_activation(activation["proven_status"])
    if claude_status == activation["proven_status"] and not promotion.allowed:
        raise BaselineValidationError(f"claude_agent is ENABLED without proof: {promotion.message}")
    if claude_status == activation["unproven_status"] and promotion.allowed:
        raise BaselineValidationError("connection proof passes but claude_agent was not promoted")
    if claude_status not in {activation["proven_status"], activation["unproven_status"]}:
        raise BaselineValidationError(f"claude_agent has an unexpected status: {claude_status}")

    task_schema = load_json("contracts/task.schema.json")
    artifact_schema = load_json("contracts/artifact.schema.json")
    handoff_schema = load_json("contracts/handoff.schema.json")
    directories = protocol["directories"]

    tasks: dict[str, Any] = {}
    for path in sorted((ROOT / directories["task_contracts"]).glob("*.json")):
        task = load_json(f"{directories['task_contracts']}/{path.name}")
        validate_instance(task, task_schema)
        if path.stem != task["task_id"]:
            raise BaselineValidationError(f"{path.name}: filename must match task_id {task['task_id']}")
        if task["owner_agent_id"] not in agent_definitions:
            raise BaselineValidationError(f"{task['task_id']}: unknown owner agent")

        delegation = evaluate_delegation(
            task,
            console=roles["implementer"]["console"],
            actor_agent_id=task["owner_agent_id"],
            protocol=protocol,
        )
        if task["status"] in protocol["delegation_gate"]["allowed_task_status"] and not delegation.allowed:
            raise BaselineValidationError(f"{task['task_id']}: delegation gate rejects the contract: {delegation.message}")

        artifact_path = f"{directories['artifact_contracts']}/{task['task_id']}-artifact.json"
        handoff_path = f"{directories['handoff_packets']}/{task['task_id']}-handoff.json"
        if not (ROOT / artifact_path).is_file() or not (ROOT / handoff_path).is_file():
            raise BaselineValidationError(f"{task['task_id']}: an Artifact Contract and Handoff Packet are required")

        artifact = load_json(artifact_path)
        handoff = load_json(handoff_path)
        validate_instance(artifact, artifact_schema)
        validate_instance(handoff, handoff_schema)

        if artifact["task_id"] != task["task_id"] or handoff["task_id"] != task["task_id"]:
            raise BaselineValidationError(f"{task['task_id']}: artifact or handoff task_id does not match")
        if artifact["project_id"] != task["project_id"]:
            raise BaselineValidationError(f"{task['task_id']}: artifact project_id does not match the task")
        if artifact["artifact_id"] not in handoff["artifact_refs"]:
            raise BaselineValidationError(f"{task['task_id']}: handoff does not reference the artifact")
        if artifact["source"]["created_by"] in artifact["reviewers"]:
            raise BaselineValidationError(f"{task['task_id']}: artifact creator may not review its own artifact")
        if handoff["from_agent_id"] == handoff["to_agent_id"]:
            raise BaselineValidationError(f"{task['task_id']}: handoff sender and receiver must differ")

        verification = evaluate_independent_verification(
            handoff,
            console=roles["independent_verifier"]["console"],
            verifier_agent_id=handoff["to_agent_id"],
            protocol=protocol,
        )
        if not verification.allowed:
            raise BaselineValidationError(f"{task['task_id']}: handoff is not independently verifiable: {verification.message}")
        missing = missing_evidence_commands(handoff, required_checks)
        if missing:
            raise BaselineValidationError(f"{task['task_id']}: missing command evidence {missing!r}")

        content_path = artifact["uri"].removeprefix("repo://")
        if artifact["uri"].startswith("repo://"):
            if not (ROOT / content_path).is_file():
                raise BaselineValidationError(f"{task['task_id']}: artifact uri does not exist: {content_path}")
            decision = verify_file(ROOT / content_path, artifact["content_hash"], label=content_path)
            if not decision.matches:
                raise BaselineValidationError(f"{task['task_id']}: artifact {decision.message}")

        tasks[task["task_id"]] = {"task": task, "artifact": artifact, "handoff": handoff}

    if not tasks:
        raise BaselineValidationError("at least one Task Contract is required under tasks/")

    scanned = [
        "operations/collaboration.yaml",
        protocol["guide"],
        directories["provider_evidence"],
        directories["task_contracts"],
        directories["artifact_contracts"],
        directories["handoff_packets"],
    ]
    for entry in scanned:
        for path in _iter_text_files(entry):
            matches = scan_for_plaintext_secrets(path.read_text(encoding="utf-8"))
            if matches:
                relative = path.relative_to(ROOT).as_posix()
                raise BaselineValidationError(f"{relative}: plaintext credential material detected ({len(matches)} rules)")

    return {"protocol": protocol, "proof": proof, "tasks": tasks}


def validate_claude_workspace() -> dict[str, Any]:
    instructions = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    if len(instructions.splitlines()) > 200:
        raise BaselineValidationError("CLAUDE.md must remain concise at 200 lines or fewer")
    for phrase in (
        "sole programming provider",
        "python scripts/validate_baseline.py",
        "python -m unittest discover -s tests -v",
        "Never write secrets",
        "Never use destructive Git",
    ):
        if phrase not in instructions:
            raise BaselineValidationError(f"CLAUDE.md is missing required rule: {phrase}")

    settings = load_json(".claude/settings.json")
    permissions = settings.get("permissions", {})
    if permissions.get("defaultMode") != "default" or permissions.get("disableBypassPermissionsMode") != "disable":
        raise BaselineValidationError("Claude permissions must use default mode with bypass disabled")
    # Edit rules also govern Write and NotebookEdit, so secret paths are denied with the
    # Edit prefix instead of a separate Write rule.
    required_denies = {
        "Bash(rm -rf *)", "Bash(git reset --hard *)", "Bash(git clean *)",
        "Bash(git push *)", "Read(./.env)", "Edit(./.env)",
        "Read(./secrets/**)", "Edit(./secrets/**)",
    }
    if not required_denies <= set(permissions.get("deny", [])):
        raise BaselineValidationError("Claude destructive or secret-path deny rules are incomplete")

    expected = {
        "client-engineer": ".claude/agents/client-engineer.md",
        "game-server-engineer": ".claude/agents/game-server-engineer.md",
        "backend-platform-engineer": ".claude/agents/backend-platform-engineer.md",
        "code-reviewer": ".claude/agents/code-reviewer.md",
    }
    definitions: dict[str, dict[str, Any]] = {}
    for expected_name, path in expected.items():
        text = (ROOT / path).read_text(encoding="utf-8")
        parts = text.split("---", 2)
        if len(parts) != 3:
            raise BaselineValidationError(f"{path}: YAML frontmatter is required")
        metadata = yaml.safe_load(parts[1])
        if not isinstance(metadata, dict) or metadata.get("name") != expected_name:
            raise BaselineValidationError(f"{path}: subagent name does not match")
        if not metadata.get("description") or not metadata.get("tools"):
            raise BaselineValidationError(f"{path}: description and tools are required")
        definitions[expected_name] = metadata
    reviewer_tools = {item.strip() for item in definitions["code-reviewer"]["tools"].split(",")}
    if reviewer_tools & {"Edit", "Write", "Bash"}:
        raise BaselineValidationError("Claude code-reviewer must remain read-only")
    return {"settings": settings, "agents": definitions}


def validate_evals(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    schema_path = "evals/eval-case.schema.json"
    schema = load_json(schema_path)
    validate_schema_structure(schema, schema_path)
    all_case_ids: set[str] = set()
    datasets: dict[str, dict[str, Any]] = {}
    for agent_id, definition in agent_definitions.items():
        profile = definition["evaluation_profile"]
        path = profile["dataset"]
        if path.startswith("pending://") or not (ROOT / path).is_file():
            raise BaselineValidationError(f"{agent_id}: evaluation dataset is not implemented")
        dataset = load_yaml(path)
        validate_instance(dataset, schema)
        if dataset["owner_agent_id"] != agent_id:
            raise BaselineValidationError(f"{path}: owner does not match agent")
        if dataset["independent_reviewer"] != profile["independent_reviewer"]:
            raise BaselineValidationError(f"{path}: independent reviewer does not match agent profile")
        if abs(dataset["minimum_score"] - profile["minimum_score"]) > 1e-9:
            raise BaselineValidationError(f"{path}: minimum score does not match agent profile")
        if dataset["independent_reviewer"] == agent_id:
            raise BaselineValidationError(f"{path}: self-review is prohibited")
        for case in dataset["cases"]:
            if case["case_id"] in all_case_ids:
                raise BaselineValidationError(f"duplicate evaluation case ID: {case['case_id']}")
            all_case_ids.add(case["case_id"])
            if abs(sum(case["scoring"].values()) - 1.0) > 1e-9:
                raise BaselineValidationError(f"{case['case_id']}: scoring weights must total 1.0")
        if not any(case["risk_class"] == "HIGH" for case in dataset["cases"]):
            raise BaselineValidationError(f"{path}: at least one HIGH risk case is required")
        datasets[agent_id] = dataset
    gates = load_yaml("evals/gates.yaml")
    if gates.get("required", {}).get("high_risk_critical_failures") != 0:
        raise BaselineValidationError("evaluation gate must allow zero high-risk critical failures")
    return datasets


def validate_roulette() -> dict[str, Any]:
    rules = load_yaml("games/roulette/rules-reference.yaml")
    spec = load_yaml("games/roulette/test-spec.yaml")
    vectors = load_json("games/roulette/fixtures/test-vectors.json")
    expected_pockets = set(range(37))
    pockets = rules["table"]["pockets"]
    wheel = rules["table"]["wheel_order"]
    red = rules["table"]["red_numbers"]
    if set(pockets) != expected_pockets or len(pockets) != 37:
        raise BaselineValidationError("roulette pockets must contain 0 through 36 exactly once")
    if set(wheel) != expected_pockets or len(wheel) != 37:
        raise BaselineValidationError("roulette wheel order must be a 0 through 36 permutation")
    if len(red) != 18 or 0 in red or not set(red) < expected_pockets:
        raise BaselineValidationError("roulette red-number partition is invalid")
    expected_payouts = {
        "straight": 35, "split": 17, "street": 11, "corner": 8, "six_line": 5,
        "dozen": 2, "column": 2, "red": 1, "black": 1, "odd": 1,
        "even": 1, "low": 1, "high": 1,
    }
    if rules.get("payouts") != expected_payouts:
        raise BaselineValidationError("roulette payout table does not match the baseline")
    required_suites = {"topology", "bet_validation", "payout", "zero_behavior", "deterministic_replay", "ledger", "concurrency_reconnect", "statistical_sanity", "scope"}
    if {item["suite_id"] for item in spec.get("suites", [])} != required_suites:
        raise BaselineValidationError("roulette test suites are incomplete")
    gate = spec["acceptance_gate"]
    if any(gate[item] != 0 for item in ("blocker", "critical", "high")):
        raise BaselineValidationError("roulette gate must allow zero high-severity defects")
    if any(gate[item] != 1.0 for item in ("exhaustive_rule_vectors_pass_rate", "deterministic_replay_pass_rate", "ledger_property_pass_rate")):
        raise BaselineValidationError("roulette exact acceptance rates must be 1.0")

    from studio_core.roulette import settle_bet

    case_ids: set[str] = set()
    for vector in vectors.get("vectors", []):
        if vector["case_id"] in case_ids:
            raise BaselineValidationError(f"duplicate roulette vector: {vector['case_id']}")
        case_ids.add(vector["case_id"])
        bet = vector["bet"]
        expected_count = rules["bet_selection_counts"][bet["type"]]
        if len(bet.get("selections", [])) != expected_count:
            raise BaselineValidationError(f"{vector['case_id']}: invalid selection count")
        if settle_bet(bet, vector["result"], rules) != vector["expected"]:
            raise BaselineValidationError(f"{vector['case_id']}: settlement does not match expected result")
    if len(case_ids) < 12:
        raise BaselineValidationError("roulette fixture baseline requires at least 12 vectors")
    return {"rules": rules, "spec": spec, "vectors": vectors}


def validate_policies() -> dict[str, dict[str, Any]]:
    security = load_yaml("policies/security.yaml")
    cost = load_yaml("policies/cost.yaml")
    audit = load_yaml("policies/audit.yaml")
    risk = load_yaml("policies/risk.yaml")
    audit_schema_path = "audit/audit-event.schema.json"
    validate_schema_structure(load_json(audit_schema_path), audit_schema_path)
    if security.get("mode") != "deny_by_default" or security["production"]["agent_direct_access"] != "denied":
        raise BaselineValidationError("security must be default-deny with no agent production access")
    if any(security["secrets"][target] != "prohibited" for target in ("repository_values", "prompt_values", "log_values")):
        raise BaselineValidationError("secret values must be prohibited in repository, prompts, and logs")
    if not cost.get("stop_on_limit") or cost["thresholds"]["hard_stop_ratio"] != 1.0:
        raise BaselineValidationError("cost policy must stop at the hard budget limit")
    required_events = {"TASK_STATE", "APPROVAL", "KNOWLEDGE", "PROVIDER_CALL", "COST", "SECURITY", "ARTIFACT", "RELEASE_GATE"}
    if set(audit.get("required_event_types", [])) != required_events or not audit["integrity"]["immutable"]:
        raise BaselineValidationError("audit event coverage or immutability is incomplete")
    if risk.get("automatic_downgrade") != "denied" or set(risk["mandatory_high_risk_reviewers"]) != {"A-50", "A-02", "A-00"}:
        raise BaselineValidationError("HIGH risk review policy is incomplete")
    return {"security": security, "cost": cost, "audit": audit, "risk": risk}


def validate_r0_approval(agent_definitions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    schema_path = "approvals/r0-approval.schema.json"
    schema = load_json(schema_path)
    validate_schema_structure(schema, schema_path)
    approval = load_yaml("approvals/SYS-010-R0-approval.yaml")
    validate_instance(approval, schema)

    recommendation_ids = [item["agent_id"] for item in approval["agent_recommendations"]]
    if set(recommendation_ids) != {"A-00", "A-02", "A-50"} or len(recommendation_ids) != 3:
        raise BaselineValidationError("SYS-010 requires unique PASS recommendations from A-00, A-02, and A-50")
    if any(agent_id not in agent_definitions for agent_id in recommendation_ids):
        raise BaselineValidationError("SYS-010 recommendation references an unknown agent")
    missing_evidence = [path for path in approval["evidence_refs"] if not (ROOT / path).is_file()]
    if missing_evidence:
        raise BaselineValidationError(f"SYS-010 evidence files are missing: {missing_evidence!r}")
    if not any("R5" in item for item in approval["binding_constraints"]):
        raise BaselineValidationError("SYS-010 must preserve the R5 production-schedule restriction")
    return approval


def validate_r1_roulette() -> dict[str, Any]:
    from studio_core.ledger import post_transaction
    from studio_core.roulette import load_r1_rules, settle_bet, theoretical_return, valid_selection_sets, validate_bet
    from studio_core.rounds import evaluate_round_transition

    game_brief = load_yaml("games/roulette/game-brief.yaml")
    round_state = load_yaml("games/roulette/round-state.yaml")
    rng = load_yaml("games/roulette/rng-contract.yaml")
    economy = load_yaml("games/roulette/economy-model.yaml")
    acceptance = load_yaml("games/roulette/r1-acceptance.yaml")
    rules = load_r1_rules()

    schema_examples = (
        ("games/roulette/ledger-transaction.schema.json", "games/roulette/fixtures/ledger-transaction.example.json"),
        ("games/roulette/round.schema.json", "games/roulette/fixtures/round.example.json"),
    )
    instances: dict[str, dict[str, Any]] = {}
    for schema_path, example_path in schema_examples:
        schema = load_json(schema_path)
        validate_schema_structure(schema, schema_path)
        instance = load_json(example_path)
        validate_instance(instance, schema)
        instances[example_path] = instance

    out_of_scope = " ".join(game_brief.get("out_of_scope", []))
    if "cash" not in out_of_scope or "production schedule" not in out_of_scope:
        raise BaselineValidationError("R1 game brief must exclude cash-out and production scheduling")
    if round_state.get("authority") != "GAME_SERVER" or round_state["guards"].get("client_authority") != "denied":
        raise BaselineValidationError("roulette rounds must be server-authoritative")
    transitions = {(item["from"], item["to"]) for item in round_state["transitions"]}
    if not {("OPEN", "LOCKED"), ("LOCKED", "SPINNING"), ("SPINNING", "SETTLING"), ("SETTLING", "SETTLED")} <= transitions:
        raise BaselineValidationError("roulette round happy-path transitions are incomplete")
    if any(source in set(round_state["terminal_states"]) for source, _ in transitions):
        raise BaselineValidationError("terminal roulette states cannot transition")

    if rng["requirements"].get("modulo_bias") != "prohibited" or rng["requirements"].get("seed_value_in_logs") != "prohibited":
        raise BaselineValidationError("RNG bias and seed-log protections are incomplete")
    if rng["failure_behavior"].get("duplicate_draw_request") != "RETURN_ORIGINAL_RESULT":
        raise BaselineValidationError("duplicate RNG draws must return the original result")

    expected_rtp = 36 / 37
    expected_edge = 1 / 37
    math_model = economy["mathematics"]
    if abs(math_model["common_rtp_decimal"] - expected_rtp) > 1e-15:
        raise BaselineValidationError("economy-model RTP does not equal 36/37")
    if abs(math_model["house_edge_decimal"] - expected_edge) > 1e-15:
        raise BaselineValidationError("economy-model house edge does not equal 1/37")
    if economy["currency"].get("cash_redemption") != "prohibited" or economy["currency"].get("real_world_reward") != "prohibited":
        raise BaselineValidationError("R1 economy must prohibit cash redemption and real-world rewards")

    supported = set(rules["payouts"])
    representative_bets = {
        "straight": [17], "split": [17, 20], "street": [10, 11, 12],
        "corner": [14, 15, 17, 18], "six_line": [1, 2, 3, 4, 5, 6],
        "dozen": [2], "column": [3], "red": [], "black": [], "odd": [],
        "even": [], "low": [], "high": [],
    }
    if set(representative_bets) != supported:
        raise BaselineValidationError("R1 representative bets do not cover all supported types")
    expected_geometry_counts = {
        "straight": 37, "split": 60, "street": 12, "corner": 22, "six_line": 11,
        "dozen": 3, "column": 3, "red": 1, "black": 1, "odd": 1,
        "even": 1, "low": 1, "high": 1,
    }
    for bet_type, selections in representative_bets.items():
        selection_sets = valid_selection_sets(bet_type)
        if len(selection_sets) != expected_geometry_counts[bet_type]:
            raise BaselineValidationError(f"{bet_type}: canonical geometry count is incorrect")
        for candidate in selection_sets:
            validate_bet({"type": bet_type, "selections": candidate, "stake_units": 1}, rules)
        bet = {"type": bet_type, "selections": selections, "stake_units": 1}
        validate_bet(bet, rules)
        math = theoretical_return(bet_type, rules)
        if abs(math["rtp"] - expected_rtp) > 1e-15 or abs(math["house_edge"] - expected_edge) > 1e-15:
            raise BaselineValidationError(f"{bet_type}: theoretical math is inconsistent")
        settlements = [settle_bet(bet, result, rules) for result in range(37)]
        if sum(int(item["net_change_units"]) for item in settlements) != -1:
            raise BaselineValidationError(f"{bet_type}: exhaustive net result must total -1 unit across 37 pockets")

    transaction = instances["games/roulette/fixtures/ledger-transaction.example.json"]
    balances = {"player:demo": 1000, "escrow:RR-DEMO-0001": 0}
    posted = post_transaction(transaction, balances, [])
    if not posted.applied or posted.balances != {"player:demo": 900, "escrow:RR-DEMO-0001": 100}:
        raise BaselineValidationError("R1 balanced ledger example did not apply correctly")
    duplicate = post_transaction(transaction, posted.balances, [transaction["idempotency_key"]])
    if duplicate.applied or duplicate.balances != posted.balances:
        raise BaselineValidationError("R1 duplicate ledger transaction must be an idempotent no-op")
    if not evaluate_round_transition("OPEN", "LOCKED", actor="GAME_SERVER", evidence=["audit://lock"]).allowed:
        raise BaselineValidationError("R1 server round transition should be allowed")
    if evaluate_round_transition("OPEN", "LOCKED", actor="CLIENT", evidence=["audit://lock"]).allowed:
        raise BaselineValidationError("R1 client round transition must be denied")

    required = acceptance.get("required", {})
    boolean_requirements = [value for key, value in required.items() if key != "blocker_critical_high_defects"]
    if not boolean_requirements or not all(value is True for value in boolean_requirements):
        raise BaselineValidationError("R1 acceptance requirements must all be enabled")
    if required.get("blocker_critical_high_defects") != 0:
        raise BaselineValidationError("R1 acceptance permits no high-severity defects")
    if not any("production schedule" in item for item in acceptance["deferred_to_later_gates"]):
        raise BaselineValidationError("R1 must defer production scheduling")

    return {
        "game_brief": game_brief,
        "round_state": round_state,
        "rng": rng,
        "economy": economy,
        "acceptance": acceptance,
    }


class _CountingEntropySource:
    """Deterministic byte source that also reports how much entropy the draw path consumed.

    The validator needs the accept/reject split to check the debiasing rate, and that split
    is not observable from the draw records on purpose. Counting it here, outside the engine,
    keeps the count out of every audit-visible surface.
    """

    source_id = "validator-fixed"
    is_deterministic = True

    def __init__(self, seed: int) -> None:
        import random

        self._random = random.Random(seed)
        self.bytes_read = 0

    def read(self, size: int) -> bytes:
        self.bytes_read += size
        return self._random.randbytes(size)


#: Files ``validate_r2_rng`` reads. Exposed so a caller can materialise an isolated copy and
#: exercise the negative cases without mutating the live repository.
R2_RNG_INPUT_FILES: tuple[str, ...] = (
    "games/roulette/rng-draw-record.schema.json",
    "games/roulette/fixtures/rng-draw-record.example.json",
    "games/roulette/round.schema.json",
    "games/roulette/rng-contract.yaml",
    "audit/audit-event.schema.json",
    "audit/events/R2-RNG-0001-events.json",
    "tasks/R2-RNG-0001.json",
    "docs/approvals/R1-checklist.md",
    "docs/approvals/R1-evidence-closure.md",
    "docs/approvals/R2-RNG-0001-validation-report.md",
    "docs/operations/R2-RNG-0001-recovery.md",
    "docs/games/R2-rng-csprng.md",
    "artifacts/R2-RNG-0001-artifact.json",
    "studio_core/rng_stats.py",
)


def validate_r2_rng(root: Path | None = None) -> dict[str, Any]:
    """Validate the R2 unit 1 production CSPRNG draw boundary and its statistical evidence.

    ``root`` defaults to the repository. Pointing it at a copy lets the negative tests prove
    that a tampered input is actually rejected without writing to tracked files -- one of
    which, the R1 checklist, would forge a human QA approval if a mutation ever leaked.
    """

    base = ROOT if root is None else Path(root)

    def _json(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be an object")
        return value

    def _yaml(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be a mapping")
        return value

    def _text(relative_path: str) -> str:
        return (base / relative_path).read_text(encoding="utf-8")

    from studio_core.rng import (
        ACCEPTED_BYTE_LIMIT,
        ALGORITHM_ID,
        ALGORITHM_VERSION,
        BYTE_DOMAIN,
        POCKET_COUNT,
        PROHIBITED_RECORD_FIELDS,
        AuditChain,
        DeterministicTestEntropySource,
        DrawRequest,
        FailureAction,
        OsCsprngEntropySource,
        RngDenied,
        RngEnvironment,
        RouletteDrawEngine,
        compute_proof_hash,
        draw_pocket,
        mapping_distribution,
        verify_audit_chain,
        verify_draw_record,
    )
    from studio_core.rng_stats import certify_stream
    from studio_core.collaboration import scan_for_plaintext_secrets

    record_schema_path = "games/roulette/rng-draw-record.schema.json"
    record_schema = _json(record_schema_path)
    validate_schema_structure(record_schema, record_schema_path)
    if record_schema.get("additionalProperties") is not False:
        raise BaselineValidationError(f"{record_schema_path}: additionalProperties must be false")
    leaking = [name for name in PROHIBITED_RECORD_FIELDS if name in record_schema["properties"]]
    if leaking:
        raise BaselineValidationError(f"{record_schema_path}: prohibited entropy fields are declared: {leaking!r}")

    fixture = _json("games/roulette/fixtures/rng-draw-record.example.json")
    validate_instance(fixture, record_schema)

    # -- unbiasedness is proved by enumeration, never by sampling ------------------------
    if ACCEPTED_BYTE_LIMIT != BYTE_DOMAIN - (BYTE_DOMAIN % POCKET_COUNT):
        raise BaselineValidationError("the accepted byte limit is not the largest multiple of the pocket count")
    distribution = mapping_distribution()
    per_pocket = {distribution[pocket] for pocket in range(POCKET_COUNT)}
    if per_pocket != {ACCEPTED_BYTE_LIMIT // POCKET_COUNT}:
        raise BaselineValidationError(f"the byte mapping is biased: pockets claim {sorted(per_pocket)!r} values")
    if distribution[None] != BYTE_DOMAIN - ACCEPTED_BYTE_LIMIT:
        raise BaselineValidationError("the rejected byte count does not close the byte domain")

    # -- a real draw, its record, and its audit event -------------------------------------
    chain = AuditChain("RNGVAL")
    engine = RouletteDrawEngine(
        entropy_source=DeterministicTestEntropySource(bytes([250, 17])),
        environment=RngEnvironment.NON_PRODUCTION,
        audit_sink=chain,
        clock=lambda: "2026-09-01T00:00:00Z",
    )
    request = DrawRequest(request_id="RNG-R2-VALIDATOR-01", round_id="RR-R2-VALIDATOR-01", draw_index=0)
    record = engine.draw(request)
    payload = record.to_dict()
    validate_instance(payload, record_schema)
    if record.algorithm_id != ALGORITHM_ID or record.algorithm_version != ALGORITHM_VERSION:
        raise BaselineValidationError("the draw record does not carry the pinned algorithm identity")

    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    present = [name for name in PROHIBITED_RECORD_FIELDS if name in payload or f'"{name}"' in serialized]
    if present:
        raise BaselineValidationError(f"the draw record leaks entropy material: {present!r}")
    expected_proof = compute_proof_hash(
        algorithm_id=record.algorithm_id,
        algorithm_version=record.algorithm_version,
        draw_index=record.draw_index,
        pocket=record.pocket,
        request_id=record.request_id,
        round_id=record.round_id,
        ruleset_id=record.ruleset_id,
        seed_reference=record.seed_reference,
    )
    if record.proof_hash != expected_proof:
        raise BaselineValidationError("the draw proof hash is not reproducible from the record alone")

    audit_schema = _json("audit/audit-event.schema.json")
    problems = verify_audit_chain(chain.events)
    if problems:
        raise BaselineValidationError(f"the draw audit chain is broken: {problems!r}")
    for event in chain.events:
        validate_instance(event, audit_schema)
        if record.seed_reference not in " ".join(event["resource_refs"]):
            raise BaselineValidationError("the audit event does not record the seed reference")
        if scan_for_plaintext_secrets(event):
            raise BaselineValidationError("the draw audit event matched a secret pattern")

    # the record must survive the trip into a round document unchanged
    round_schema = _json("games/roulette/round.schema.json")
    rng_record_schema = round_schema["properties"]["rng_record"]["oneOf"][1]
    projection = record.to_round_rng_record()
    validate_instance(projection, rng_record_schema)
    if projection["proof_hash"] != record.proof_hash or projection["draw_index"] != record.draw_index:
        raise BaselineValidationError("the round projection does not preserve the draw binding")

    # -- fail-closed gates -----------------------------------------------------------------
    def _denied(callable_: Any, expected_code: str, expected_action: FailureAction) -> None:
        try:
            callable_()
        except RngDenied as exc:
            if exc.code != expected_code or exc.action is not expected_action:
                raise BaselineValidationError(
                    f"expected {expected_code}/{expected_action.value}, got {exc.code}/{exc.action.value}"
                ) from None
            return
        raise BaselineValidationError(f"{expected_code} was not enforced")

    _denied(
        lambda: RouletteDrawEngine(
            entropy_source=DeterministicTestEntropySource(b"\x01"),
            environment=RngEnvironment.PRODUCTION,
        ),
        "DETERMINISTIC_SOURCE_IN_PRODUCTION",
        FailureAction.BLOCK_AND_ESCALATE,
    )
    if OsCsprngEntropySource().is_deterministic:
        raise BaselineValidationError("the production entropy source must not be deterministic")

    replay = engine.draw(request)
    if replay.to_dict() != payload:
        raise BaselineValidationError("a duplicate draw request did not return the original result")
    _denied(
        lambda: engine.draw(DrawRequest(request_id=request.request_id, round_id="RR-R2-OTHER-01", draw_index=0)),
        "DUPLICATE_REQUEST_CONFLICT",
        FailureAction.BLOCK_AND_ESCALATE,
    )
    _denied(
        lambda: engine.draw(DrawRequest(request_id="RNG-R2-VALIDATOR-02", round_id=request.round_id, draw_index=1)),
        "ROUND_ALREADY_DRAWN",
        FailureAction.BLOCK_AND_ESCALATE,
    )
    _denied(
        lambda: engine.draw(DrawRequest(request_id="RNG-R2-VALIDATOR-03", round_id="RR-R2-VALIDATOR-01", draw_index=0, algorithm_version="9.9.9")),
        "ALGORITHM_VERSION_MISMATCH",
        FailureAction.BLOCK_AND_ESCALATE,
    )

    class _FailingSink:
        def append(self, body: Mapping[str, Any]) -> str:
            raise RuntimeError("audit store unavailable")

    unauditable = RouletteDrawEngine(
        entropy_source=DeterministicTestEntropySource(bytes([7])),
        environment=RngEnvironment.NON_PRODUCTION,
        audit_sink=_FailingSink(),
        clock=lambda: "2026-09-01T00:00:00Z",
    )
    _denied(
        lambda: unauditable.draw(DrawRequest(request_id="RNG-R2-VALIDATOR-04", round_id="RR-R2-AUDITFAIL-01")),
        "AUDIT_WRITE_FAILURE",
        FailureAction.BLOCK_AND_VOID,
    )
    if not unauditable.is_round_voided("RR-R2-AUDITFAIL-01"):
        raise BaselineValidationError("an unauditable round must be voided")

    # A discarded sample must not leave the round drawable: otherwise an operator able to
    # induce entropy or clock faults could re-roll a round with no audit trace.
    starved = RouletteDrawEngine(
        entropy_source=DeterministicTestEntropySource(bytes([255])),
        environment=RngEnvironment.NON_PRODUCTION,
        audit_sink=AuditChain("RNGSTARVE"),
        clock=lambda: "2026-09-01T00:00:00Z",
    )
    _denied(
        lambda: starved.draw(DrawRequest(request_id="RNG-R2-VALIDATOR-05", round_id="RR-R2-STARVED-01")),
        "ENTROPY_REJECTION_EXHAUSTED",
        FailureAction.VOID_ROUND,
    )
    if not starved.is_round_voided("RR-R2-STARVED-01"):
        raise BaselineValidationError("a round whose sample was discarded must be voided")
    _denied(
        lambda: starved.draw(DrawRequest(request_id="RNG-R2-VALIDATOR-06", round_id="RR-R2-STARVED-01")),
        "ROUND_VOIDED",
        FailureAction.BLOCK_AND_ESCALATE,
    )

    # ``missing_or_invalid_proof: VOID_ROUND`` needs something that actually re-checks a
    # stored proof, or the contract row would be satisfied by nothing at all.
    verify_draw_record(record)
    _denied(
        lambda: verify_draw_record(dict(payload, pocket=(record.pocket + 1) % POCKET_COUNT)),
        "PROOF_INVALID",
        FailureAction.VOID_ROUND,
    )
    _denied(
        lambda: verify_draw_record({key: value for key, value in payload.items() if key != "proof_hash"}),
        "PROOF_MISSING",
        FailureAction.VOID_ROUND,
    )

    # -- the implementation must answer to the declared RNG contract ----------------------
    contract = _yaml("games/roulette/rng-contract.yaml")
    behaviour = contract["failure_behavior"]
    expected_behaviour = {
        "duplicate_draw_request": "RETURN_ORIGINAL_RESULT",
        "algorithm_version_mismatch": FailureAction.BLOCK_AND_ESCALATE.value,
        "audit_write_failure": FailureAction.BLOCK_AND_VOID.value,
        "missing_or_invalid_proof": FailureAction.VOID_ROUND.value,
    }
    for key, value in expected_behaviour.items():
        if behaviour.get(key) != value:
            raise BaselineValidationError(f"rng-contract failure behaviour {key} does not match the implementation")
    if contract["requirements"]["unbiased_mapping"] != "rejection_sampling_or_equivalent":
        raise BaselineValidationError("the RNG contract no longer requires an unbiased mapping")
    # Every declared contract output must be reachable from a draw record, so the interface
    # cannot drift away from the implementation unnoticed.
    declared_outputs = {"pocket_0_to_36": "pocket", "proof_hash": "proof_hash", "audit_event_ref": "audit_event_ref"}
    for declared, field in declared_outputs.items():
        if declared not in contract["interface"]["output"]:
            raise BaselineValidationError(f"the RNG contract no longer declares the output {declared}")
        if field not in payload:
            raise BaselineValidationError(f"the draw record does not expose the declared output {declared}")
    # ``protected_seed_reference`` is declared as a draw input but is deliberately derived
    # server-side instead of accepted from a caller. Recording the deviation here keeps it a
    # known, reviewable divergence rather than silent drift.
    if "protected_seed_reference" in contract["interface"]["input"] and not record.seed_reference:
        raise BaselineValidationError("the engine must derive a seed reference for the declared contract input")

    # -- independent statistical certification over a reproducible stream -----------------
    # The stream is a fixed-seed Mersenne Twister, not the OS CSPRNG: the baseline must give
    # the same verdict on every machine and every run. That makes this a regression check on
    # the draw path, not a certification of the production entropy source -- the live CSPRNG
    # is certified in tests/test_rng.py::LiveCsprngCertificationTests.
    #
    # 60000 draws sizes the uniformity arm against the specific defect it guards: a naive
    # ``byte % 37`` puts 34 pockets at 7/256 and 3 at 6/256, which at this sample size gives
    # a non-centrality near 93 against a 0.001 critical value of 67.985, so the defect is
    # caught with probability ~0.99 rather than the coin flip 20000 draws would give.
    source = _CountingEntropySource(20260901)
    sample = [draw_pocket(source) for _ in range(60000)]
    report = certify_stream(
        sample,
        accepted=len(sample),
        rejected=source.bytes_read - len(sample),
        expected_acceptance_rate=ACCEPTED_BYTE_LIMIT / BYTE_DOMAIN,
    )
    if report["skipped"]:
        raise BaselineValidationError(f"statistical certification skipped tests: {report['skipped']!r}")
    if not report["all_passed"]:
        failed = [item["test_id"] for item in report["results"] if not item["passed"]]
        raise BaselineValidationError(f"statistical certification failed: {failed!r}")

    # -- the gate violation and its recovery must stay on the record ----------------------
    events_document = _json("audit/events/R2-RNG-0001-events.json")
    events = events_document["events"]
    for event in events:
        validate_instance(event, audit_schema)
        if event["task_id"] != "R2-RNG-0001":
            raise BaselineValidationError("a recovery audit event is attached to the wrong task")
    chain_problems = verify_audit_chain(events)
    if chain_problems:
        raise BaselineValidationError(f"the recovery audit chain is broken: {chain_problems!r}")
    actions = {event["action"] for event in events}
    required_actions = {
        "READY_GATE_VIOLATION_DETECTED",
        "UNTRACKED_DRAFT_PRESERVED",
        "TASK_CONTRACT_ISSUED_READY",
        "GATE_VIOLATION_RECOVERY_COMPLETED",
    }
    if not required_actions <= actions:
        raise BaselineValidationError(f"the recovery record is incomplete: missing {sorted(required_actions - actions)!r}")

    task = _json("tasks/R2-RNG-0001.json")
    if task["status"] not in {"READY", "IN_PROGRESS", "REVIEW", "QA"} or task["risk_class"] != "HIGH":
        raise BaselineValidationError("R2-RNG-0001 must remain a HIGH risk task under an open gate")
    if not {"A-50", "A-02", "A-00"} <= set(task["approvers"]):
        raise BaselineValidationError("a HIGH risk RNG task requires the mandatory reviewers")

    # -- the artifact's declared component hashes must be canonical and current -------------
    # ``content_hash`` is checked by ``validate_content_integrity``; these secondary hashes
    # name the statistics module and record schema the artifact claims to have shipped, and
    # would otherwise be unverified prose that drifts as the files change.
    specification = _json("artifacts/R2-RNG-0001-artifact.json")["specification"]
    for field, relative in (
        ("statistics_module_hash", specification["statistics_module"]),
        ("record_schema_hash", specification["record_schema"]),
    ):
        actual = hash_file(base / relative, label=relative)
        if specification[field] != actual:
            raise BaselineValidationError(
                f"artifact {field} does not match {relative}: {actual} != {specification[field]}"
            )

    # -- R1 evidence closure must not claim approvals that no human gave ------------------
    checklist = _text("docs/approvals/R1-checklist.md")
    section = checklist.split("## 후속 승인", 1)
    if len(section) != 2:
        raise BaselineValidationError("docs/approvals/R1-checklist.md is missing the follow-up approval section")
    follow_up = section[1].split("\n## ", 1)[0]
    if "- [x]" in follow_up.lower():
        raise BaselineValidationError("a human follow-up approval is marked complete without a human sign-off")

    for relative in ("docs/operations/R2-RNG-0001-recovery.md", "docs/approvals/R1-evidence-closure.md",
                     "docs/approvals/R2-RNG-0001-validation-report.md", "docs/games/R2-rng-csprng.md",
                     "audit/events/R2-RNG-0001-events.json"):
        text = _text(relative)
        if scan_for_plaintext_secrets(text):
            raise BaselineValidationError(f"{relative}: plaintext credential material detected")

    return {"record_schema": record_schema, "statistics": report, "recovery_events": events}


#: Files ``validate_r2_durable_state`` reads. Exposed so a caller can materialise an isolated
#: copy and exercise the negative cases without mutating the live repository -- two of these,
#: the validation report and the R2 status page, would forge a human approval if a mutation
#: ever leaked into the working tree.
R2_DBC_INPUT_FILES: tuple[str, ...] = (
    "games/roulette/durable-state-contract.yaml",
    "games/roulette/durable-state-schema.sql",
    "games/roulette/ledger-transaction.schema.json",
    "audit/audit-event.schema.json",
    "audit/events/R2-DBC-0002-events.json",
    "tasks/R2-DBC-0002.json",
    "artifacts/R2-DBC-0002-artifact.json",
    "studio_core/durable_state.py",
    "studio_core/rng.py",
    "tests/test_durable_state.py",
    "docs/games/R2-durable-state.md",
    "docs/approvals/R2-DBC-0002-validation-report.md",
    "docs/status/R2-STATUS.md",
    "docs/operations/R2-followup-units.md",
)

#: Audit actions the R2-DBC-0002 record must carry. The provenance of the incomplete draft is
#: one of them on purpose: the recovery is only auditable if the thing being recovered from is
#: named, and a later reader must not have to infer it from a commit message.
R2_DBC_REQUIRED_AUDIT_ACTIONS = frozenset(
    {
        "TASK_CONTRACT_ISSUED_READY",
        "PRE_IMPLEMENTATION_ARTIFACT_REGISTERED",
        "INCOMPLETE_DRAFT_ATTRIBUTED",
        "DURABLE_STATE_IMPLEMENTATION_COMPLETED",
        "VALIDATION_COMMANDS_REPLAYED",
        "PRE_IMPLEMENTATION_RECORDS_SUPERSEDED",
    }
)

#: Work this unit does not do. Each must stay named in the carried-forward records so that
#: ``AC-013`` is a checked property of the repository rather than a claim in a report.
R2_DBC_DEFERRED_UNITS = ("R2-NET-0003", "R2-LOAD-0004", "R2-SEC-0005")


def _durable_settlement(record: Any, *, index: int = 1) -> dict[str, Any]:
    """Return a balanced integer settlement for a drawn round, for validator use only."""

    return {
        "schema_version": "1.0.0",
        "transaction_id": f"LT-R2DBCVAL-{index:04d}",
        "idempotency_key": f"idem:{record.round_id}:settlement",
        "round_id": record.round_id,
        "transaction_type": "ROUND_SETTLEMENT",
        "currency": "VIRTUAL_CHIP",
        "entries": [
            {"account_id": "player:validator", "account_type": "PLAYER", "amount_units": -100},
            {"account_id": "house:validator", "account_type": "HOUSE_BANKROLL", "amount_units": 100},
        ],
        "created_at": "2026-09-01T00:00:00Z",
        "request_hash": "sha256:" + "0" * 64,
    }


def validate_r2_durable_state(root: Path | None = None) -> dict[str, Any]:
    """Validate the R2 unit 2 durable-state boundary against its published contract.

    ``root`` defaults to the repository. Pointing it at a copy lets the negative tests prove
    that a contract, schema or evidence file which disagrees with the implementation is
    actually rejected, without writing to tracked files.

    The live exercise runs against a throwaway SQLite database in a temporary directory. The
    task contract forbids a database file inside the repository, and a validator that left one
    behind would be the first thing to break that rule.
    """

    base = ROOT if root is None else Path(root)

    def _json(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be an object")
        return value

    def _yaml(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be a mapping")
        return value

    def _text(relative_path: str) -> str:
        return (base / relative_path).read_text(encoding="utf-8")

    from studio_core.collaboration import scan_for_plaintext_secrets
    from studio_core.durable_state import (
        FAILURE_BEHAVIOR,
        FAULT_STAGES,
        PATH_HANDLING,
        PROHIBITED_STORAGE_FIELDS,
        DurableRoundStore,
        DurableStateError,
        SchemaVersionError,
        contract_declaration,
        prohibited_fields,
        resolve_database_path,
        schema_sql,
    )
    from studio_core.rng import DeterministicTestEntropySource, DrawRequest, RngDenied, RngEnvironment

    # -- the contract file must state what the implementation actually does ----------------
    contract_path = "games/roulette/durable-state-contract.yaml"
    contract = _yaml(contract_path)
    declared = contract.get("storage")
    if not isinstance(declared, Mapping):
        raise BaselineValidationError(f"{contract_path}: a storage block is required")
    expected_storage = contract_declaration()
    if dict(declared) != expected_storage:
        differing = sorted(
            key
            for key in set(declared) | set(expected_storage)
            if declared.get(key) != expected_storage.get(key)
        )
        raise BaselineValidationError(
            f"{contract_path}: storage declaration does not match the implementation: {differing!r}"
        )
    if dict(contract.get("failure_behavior", {})) != FAILURE_BEHAVIOR:
        raise BaselineValidationError(f"{contract_path}: failure_behavior does not match the implementation")
    declared_paths = contract.get("path_handling", {})
    for key, value in PATH_HANDLING.items():
        if declared_paths.get(key) != value:
            raise BaselineValidationError(f"{contract_path}: path_handling.{key} does not match the implementation")
    prohibited = contract.get("prohibited_storage", {})
    if prohibited.get("prohibited_field_names_source") != "studio_core.durable_state.PROHIBITED_STORAGE_FIELDS":
        raise BaselineValidationError(f"{contract_path}: the prohibited field source is not named")
    for key, value in prohibited.items():
        if key != "prohibited_field_names_source" and value != "prohibited":
            raise BaselineValidationError(f"{contract_path}: prohibited_storage.{key} must be 'prohibited'")
    if contract.get("rng_boundary", {}).get("modified_by_this_unit") is not False:
        raise BaselineValidationError(f"{contract_path}: this unit must not modify the RNG boundary")
    for unit in R2_DBC_DEFERRED_UNITS:
        if not any(unit in item for item in contract.get("out_of_scope", [])):
            raise BaselineValidationError(f"{contract_path}: out_of_scope does not carry {unit} forward")

    # -- the published SQL must be the SQL the implementation runs -------------------------
    published_sql = _text("games/roulette/durable-state-schema.sql").replace("\r\n", "\n")
    if published_sql != schema_sql():
        raise BaselineValidationError(
            "games/roulette/durable-state-schema.sql has drifted from studio_core.durable_state.SCHEMA_STATEMENTS"
        )

    # -- the RNG boundary this unit builds on must be untouched ----------------------------
    # ``AC-013`` and the task contract both say ``rng.py`` is used, not modified. The task
    # declares its hash as an input, so the two can be compared instead of asserted.
    task = _json("tasks/R2-DBC-0002.json")
    rng_inputs = [item for item in task["inputs"] if item["uri"] == "repo://studio_core/rng.py"]
    if len(rng_inputs) != 1:
        raise BaselineValidationError("tasks/R2-DBC-0002.json must declare studio_core/rng.py as a single input")
    rng_decision = verify_file(base / "studio_core/rng.py", rng_inputs[0]["content_hash"], label="studio_core/rng.py")
    if not rng_decision.matches:
        raise BaselineValidationError(f"the RNG boundary was modified by this unit: {rng_decision.message}")
    if task["status"] not in {"READY", "IN_PROGRESS", "REVIEW", "QA"} or task["risk_class"] != "HIGH":
        raise BaselineValidationError("R2-DBC-0002 must remain a HIGH risk task under an open gate")
    if not {"A-50", "A-02", "A-00"} <= set(task["approvers"]):
        raise BaselineValidationError("a HIGH risk durable-state task requires the mandatory reviewers")

    audit_schema = _json("audit/audit-event.schema.json")
    ledger_schema = _json("games/roulette/ledger-transaction.schema.json")

    # -- a real store, exercised end to end ------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="r2dbc-validate-") as workspace:
        database = Path(workspace) / "durable-state.sqlite3"
        # A marker whose bytes are all accepted by the debiasing rule, so exactly these values
        # reach the draw path and their absence from the file is evidence rather than luck.
        marker = bytes([7, 11, 13, 17, 19, 23])
        entropy = DeterministicTestEntropySource(marker)
        store = DurableRoundStore(
            database,
            namespace="DBCVAL",
            entropy_source=entropy,
            environment=RngEnvironment.NON_PRODUCTION,
            clock=lambda: "2026-09-01T00:00:00Z",
        )
        try:
            if store.path != resolve_database_path(database):
                raise BaselineValidationError("the store did not resolve its database path canonically")
            store.register_account("player:validator", "PLAYER", 1000)
            store.register_account("house:validator", "HOUSE_BANKROLL", 0)
            request = DrawRequest(request_id="R2-DBC-VALIDATOR-01", round_id="RR-R2-DBCVAL-01")
            committed = store.submit_round(request, settlement=lambda record: _durable_settlement(record))
            if committed.replayed or committed.settlement_transaction_id is None:
                raise BaselineValidationError("the first submission must commit a new authoritative result")
            if committed.balances != {"player:validator": 900, "house:validator": 100}:
                raise BaselineValidationError("the durable settlement did not move integer balances as posted")
            if any(not isinstance(value, int) or isinstance(value, bool) for value in committed.balances.values()):
                raise BaselineValidationError("durable balances must be integer minimum units")
            consumed_after_draw = entropy.consumed
            if consumed_after_draw == 0:
                raise BaselineValidationError("the authoritative draw did not read the entropy source")
        finally:
            store.close()

        # AC-001: reopening the store must replay the record without touching entropy again.
        reopened = DurableRoundStore(
            database,
            namespace="DBCVAL",
            entropy_source=entropy,
            environment=RngEnvironment.NON_PRODUCTION,
            clock=lambda: "2026-09-01T00:00:00Z",
        )
        try:
            replay = reopened.submit_round(request, settlement=lambda record: _durable_settlement(record))
            if not replay.replayed or replay.record.to_dict() != committed.record.to_dict():
                raise BaselineValidationError("a restarted store did not return the original authoritative record")
            if entropy.consumed != consumed_after_draw:
                raise BaselineValidationError("a replay after restart consumed entropy")
            if reopened.count("draw_record") != 1 or reopened.count("ledger_transaction") != 1:
                raise BaselineValidationError("a replay after restart committed a second result or settlement")
            if reopened.balances() != {"house:validator": 100, "player:validator": 900}:
                raise BaselineValidationError("a replay after restart moved balances a second time")

            # AC-002: the reloaded chain verifies, and its references are globally unique.
            problems = reopened.verify_chain()
            if problems:
                raise BaselineValidationError(f"the reloaded durable audit chain is broken: {problems!r}")
            events = reopened.audit_events()
            identifiers = [event["event_id"] for event in events]
            if len(identifiers) != len(set(identifiers)):
                raise BaselineValidationError("stored audit events do not carry globally unique identifiers")
            for event in events:
                validate_instance(event, audit_schema)
                leaking = prohibited_fields(event)
                if leaking:
                    raise BaselineValidationError(f"a stored audit event carries prohibited fields {leaking!r}")
                if scan_for_plaintext_secrets(event):
                    raise BaselineValidationError("a stored audit event matched a plaintext credential rule")

            # AC-010: the record and the settlement must both be storable and contract-shaped.
            stored_transaction = reopened.ledger_transaction(committed.settlement_transaction_id)
            validate_instance(stored_transaction, ledger_schema)
            for payload, label in ((stored_transaction, "ledger transaction"), (replay.record.to_dict(), "draw record")):
                if prohibited_fields(payload):
                    raise BaselineValidationError(f"the stored {label} carries prohibited fields")
                if any(isinstance(value, float) for value in payload.values()):
                    raise BaselineValidationError(f"the stored {label} carries a floating-point value")

            # AC-002: an audit event may not be updated or deleted, even through raw SQL.
            # ``closing`` is not decoration here: a leaked handle keeps the database file
            # locked on Windows and the enclosing TemporaryDirectory can then never be removed,
            # which turns a passing check into a failing teardown.
            for statement in (
                "UPDATE audit_event SET action = 'FORGED' WHERE event_seq = 1",
                "DELETE FROM audit_event WHERE event_seq = 1",
            ):
                with closing(sqlite3.connect(str(database), isolation_level=None)) as raw:
                    raw.execute("PRAGMA foreign_keys = ON")
                    try:
                        raw.execute(statement)
                    except sqlite3.IntegrityError:
                        continue
                raise BaselineValidationError(f"the durable audit log accepted {statement.split()[0]}")
        finally:
            reopened.close()

        # AC-010: nothing that reached the entropy path may appear in the file on disk.
        if marker in database.read_bytes():
            raise BaselineValidationError("entropy material reached the durable database file")

        # AC-007: reusing a request_id with different parameters must fail closed.
        conflicting = DurableRoundStore(
            database,
            namespace="DBCVAL",
            entropy_source=entropy,
            environment=RngEnvironment.NON_PRODUCTION,
            clock=lambda: "2026-09-01T00:00:00Z",
        )
        try:
            try:
                conflicting.submit_round(DrawRequest(request_id=request.request_id, round_id="RR-R2-DBCVAL-99"))
            except RngDenied as denied:
                if denied.code != "DUPLICATE_REQUEST_CONFLICT":
                    raise BaselineValidationError(f"expected DUPLICATE_REQUEST_CONFLICT, got {denied.code}") from None
            else:
                raise BaselineValidationError("a reused request_id with different parameters was accepted")
        finally:
            conflicting.close()

        # AC-005: a fault at any stage before the commit must leave no draw or settlement.
        for stage in FAULT_STAGES:
            if stage == "after_commit":
                continue
            fault_database = Path(workspace) / f"fault-{stage}.sqlite3"
            faulty = DurableRoundStore(
                fault_database,
                namespace="DBCVAL",
                entropy_source=DeterministicTestEntropySource(marker),
                environment=RngEnvironment.NON_PRODUCTION,
                clock=lambda: "2026-09-01T00:00:00Z",
                fault_hook=lambda reached, target=stage: _raise_injected(reached, target),
            )
            try:
                faulty.register_account("player:validator", "PLAYER", 1000)
                faulty.register_account("house:validator", "HOUSE_BANKROLL", 0)
                try:
                    faulty.submit_round(
                        DrawRequest(request_id=f"R2-DBC-FAULT-{stage}", round_id="RR-R2-DBCFAULT-01"),
                        settlement=lambda record: _durable_settlement(record),
                    )
                except RuntimeError:
                    pass
                else:
                    raise BaselineValidationError(f"the injected fault at {stage} did not reach the caller")
            finally:
                faulty.close()
            recovered = DurableRoundStore(
                fault_database,
                namespace="DBCVAL",
                entropy_source=DeterministicTestEntropySource(marker),
                environment=RngEnvironment.NON_PRODUCTION,
                clock=lambda: "2026-09-01T00:00:00Z",
            )
            try:
                residue = {table: recovered.count(table) for table in ("draw_record", "ledger_transaction", "ledger_entry")}
                if any(residue.values()):
                    raise BaselineValidationError(f"a fault at {stage} left committed rows behind: {residue!r}")
                if recovered.balances() != {"house:validator": 0, "player:validator": 1000}:
                    raise BaselineValidationError(f"a fault at {stage} moved balances")
                if any(event["action"] == "ROULETTE_RNG_DRAW" for event in recovered.audit_events()):
                    raise BaselineValidationError(f"a fault at {stage} left a draw audit event behind")
                if recovered.verify_chain():
                    raise BaselineValidationError(f"a fault at {stage} broke the audit chain")
            finally:
                recovered.close()

        # AC-009: a database from a future schema version is refused, never migrated down.
        future = Path(workspace) / "future.sqlite3"
        with closing(sqlite3.connect(str(future), isolation_level=None)) as seeded:
            seeded.execute(f"PRAGMA user_version = {contract_declaration()['schema_version'] + 1}")
        try:
            # The refusal happens inside the constructor, so there is no object to close
            # afterwards; ``DurableRoundStore`` releases its own connection when it refuses.
            DurableRoundStore(future, environment=RngEnvironment.NON_PRODUCTION).close()
        except SchemaVersionError as refused:
            if refused.code != "SCHEMA_VERSION_UNSUPPORTED":
                raise BaselineValidationError(f"unexpected schema refusal code {refused.code}") from None
        else:
            raise BaselineValidationError("a future schema version was opened instead of refused")

        # AC-008: an in-memory or URI database can never hold authoritative state.
        for spelling in (":memory:", "file:durable.sqlite3?mode=memory&cache=shared"):
            try:
                resolve_database_path(spelling)
            except DurableStateError as refused:
                if refused.code != "PATH_INVALID":
                    raise BaselineValidationError(f"unexpected path refusal code {refused.code}") from None
            else:
                raise BaselineValidationError(f"the store accepted the unsafe database path {spelling!r}")

    # -- the unit's own audit record -------------------------------------------------------
    from studio_core.rng import verify_audit_chain

    events_document = _json("audit/events/R2-DBC-0002-events.json")
    unit_events = events_document["events"]
    for event in unit_events:
        validate_instance(event, audit_schema)
        if event["task_id"] != "R2-DBC-0002":
            raise BaselineValidationError("a durable-state audit event is attached to the wrong task")
    chain_problems = verify_audit_chain(unit_events)
    if chain_problems:
        raise BaselineValidationError(f"the R2-DBC-0002 audit chain is broken: {chain_problems!r}")
    actions = {event["action"] for event in unit_events}
    if not R2_DBC_REQUIRED_AUDIT_ACTIONS <= actions:
        missing = sorted(R2_DBC_REQUIRED_AUDIT_ACTIONS - actions)
        raise BaselineValidationError(f"the durable-state audit record is incomplete: missing {missing!r}")

    # -- the artifact's declared component hashes must be canonical and current -------------
    specification = _json("artifacts/R2-DBC-0002-artifact.json")["specification"]
    for field, relative in (
        ("contract_hash", contract_path),
        ("sql_schema_hash", "games/roulette/durable-state-schema.sql"),
        ("test_suite_hash", "tests/test_durable_state.py"),
    ):
        actual = hash_file(base / relative, label=relative)
        if specification.get(field) != actual:
            raise BaselineValidationError(
                f"artifact {field} does not match {relative}: {actual} != {specification.get(field)}"
            )
    if specification.get("rng_module_modified") is not False:
        raise BaselineValidationError("the artifact must record that the RNG boundary was not modified")
    if specification.get("human_approved") is not False:
        raise BaselineValidationError("the artifact must not claim a human approval that was not issued")

    # -- the carried-forward scope must stay named ------------------------------------------
    status = _text("docs/status/R2-STATUS.md")
    follow_ups = _text("docs/operations/R2-followup-units.md")
    for unit in R2_DBC_DEFERRED_UNITS:
        if unit not in status or unit not in follow_ups:
            raise BaselineValidationError(f"{unit} is no longer carried forward in the R2 status records")

    report = _text("docs/approvals/R2-DBC-0002-validation-report.md")
    approval_section = report.split("## 9. 인간 게이트", 1)
    if len(approval_section) != 2:
        raise BaselineValidationError("the R2-DBC-0002 validation report is missing its human gate section")
    if "- [x]" in approval_section[1].lower():
        raise BaselineValidationError("a human gate item is marked complete without a human sign-off")

    for relative in (
        "docs/games/R2-durable-state.md",
        "docs/approvals/R2-DBC-0002-validation-report.md",
        "docs/status/R2-STATUS.md",
        "docs/operations/R2-followup-units.md",
        "audit/events/R2-DBC-0002-events.json",
        contract_path,
    ):
        if scan_for_plaintext_secrets(_text(relative)):
            raise BaselineValidationError(f"{relative}: plaintext credential material detected")

    return {
        "contract": contract,
        "events": unit_events,
        "prohibited_fields": list(PROHIBITED_STORAGE_FIELDS),
    }


#: Files ``validate_r4_playable_slice`` reads. Exposed so a caller can materialise an isolated
#: copy and exercise the negative cases without mutating the live repository -- two of these,
#: the validation report and the R4 design document, would forge a human approval if a
#: mutation ever leaked into the working tree.
R4_UI_INPUT_FILES: tuple[str, ...] = (
    "games/roulette/playable-slice-contract.yaml",
    "games/roulette/round-state.yaml",
    "audit/audit-event.schema.json",
    "audit/events/R4-UI-0006-events.json",
    "tasks/R4-UI-0006.json",
    "artifacts/R4-UI-0006-artifact.json",
    "apps/roulette_web/table.py",
    "apps/roulette_web/server.py",
    "apps/roulette_web/static/index.html",
    "apps/roulette_web/static/styles.css",
    "apps/roulette_web/static/app.js",
    "apps/roulette_web/README.md",
    "tests/test_roulette_web_server.py",
    "tests/test_roulette_web_ui.py",
    "docs/games/R4-roulette-playable-slice.md",
    "docs/approvals/R4-UI-0006-validation-report.md",
    "docs/status/R2-STATUS.md",
    "docs/operations/R2-followup-units.md",
)

#: Audit actions the R4-UI-0006 record must carry. The owner reassignment is one of them on
#: purpose: the delegation gate refused the contract as issued, and a later reader must be
#: able to see how that was resolved instead of inferring it from a diff.
R4_UI_REQUIRED_AUDIT_ACTIONS = frozenset(
    {
        "TASK_CONTRACT_ISSUED_READY",
        "PRE_IMPLEMENTATION_ARTIFACT_REGISTERED",
        "DELEGATION_OWNER_REASSIGNED",
        "PLAYABLE_SLICE_IMPLEMENTATION_COMPLETED",
        "VALIDATION_COMMANDS_REPLAYED",
        "BROWSER_VISUAL_QA_NOT_RUN",
        "PRE_IMPLEMENTATION_RECORDS_SUPERSEDED",
    }
)

#: ``studio_core`` modules the slice consumes through their published interfaces. The task
#: declares a hash for each, so "used, not modified" is a comparison rather than a claim.
R4_UI_BASELINE_MODULES = (
    "studio_core/rng.py",
    "studio_core/roulette.py",
    "studio_core/durable_state.py",
    "studio_core/ledger.py",
)

#: Suffixes that would mean a runtime database escaped into the repository surface. The slice
#: writes its authoritative state outside the working tree; if one ever lands inside, the
#: baseline should say so before a commit does.
R4_UI_RUNTIME_STATE_SUFFIXES = (".sqlite3", ".sqlite", ".db", ".sqlite3-wal", ".sqlite3-shm")

#: ``document.createElementNS`` requires this exact string to build SVG nodes; it is an XML
#: namespace identifier, never fetched, so it is the one URL app.js may spell out. It is
#: elided before the off-origin scan so every other ``http://``/``https://`` still fails.
R4_UI_SVG_NAMESPACE = "http://www.w3.org/2000/svg"

#: Anything in the client that would mean the browser is deciding an authoritative value, or
#: reaching somewhere other than this loopback origin.
R4_UI_CLIENT_PROHIBITED = (
    "Math.random",
    "getRandomValues",
    "crypto.subtle",
    "eval(",
    "new Function(",
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "document.cookie",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "navigator.sendBeacon",
    "http://",
    "https://",
    "//cdn.",
)


class _R4MarkupScan(HTMLParser):
    """Report the markup in index.html that the slice's content security policy would refuse.

    A pattern cannot tell an element from a mention of one. The CSP note in index.html spells
    out ``<script>``, ``<style>`` and ``style="..."`` inside an HTML comment to record why none
    of them are present, and a regular expression reads those words as the very markup the note
    promises is absent. A parser sees a comment as a comment, so only real elements and real
    attributes are reported -- which is also the only thing a browser would refuse.
    """

    def __init__(self, source: str) -> None:
        super().__init__(convert_charrefs=True)
        self.refused: list[str] = []
        self._script_depth = 0
        self.feed(source)
        self.close()

    def _inspect(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        # No 'unsafe-inline' in the policy, so a script element without a real src is dead
        # markup at best and a blocked inline script at worst.
        if tag == "script" and not attributes.get("src", "").strip():
            self.refused.append("<script> element without a src attribute")
        if tag == "style":
            self.refused.append("<style> element")
        if "style" in attributes:
            self.refused.append(f"style attribute on <{tag}>")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._inspect(tag, attrs)
        if tag == "script":
            self._script_depth += 1

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._inspect(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script_depth:
            self._script_depth -= 1

    def handle_data(self, data: str) -> None:
        # An external script element with a body would still be an inline script.
        if self._script_depth and data.strip():
            self.refused.append("inline script body")


def _r4_floats(payload: Any, path: str = "$") -> list[str]:
    """Return the location of every floating-point value inside ``payload``."""

    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            found.extend(_r4_floats(value, f"{path}.{key}"))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            found.extend(_r4_floats(value, f"{path}[{index}]"))
    elif isinstance(payload, float):
        found.append(path)
    return found


def _r4_declared_error_codes(table_source: str, server_source: str) -> set[str]:
    """Return every refusal code the slice can actually put in ``error.code``.

    Read out of the source rather than imported, because a code only exists at the moment a
    refusal is raised. Extracting them makes the contract's list a two-way check: an added
    refusal fails the baseline until it is declared, and a declared code that no longer
    exists fails it too.
    """

    codes = set(re.findall(r'TableError\(\s*"([A-Z0-9_]+)"', table_source))
    codes |= set(re.findall(r'TableError\(\s*"([A-Z0-9_]+)"', server_source))
    codes |= set(re.findall(r'_send_error_json\(\s*[^,]+?,\s*"([A-Z0-9_]+)"', server_source, re.S))
    return codes


R4_HUMAN_GATE_HEADING = re.compile(
    r"^##\s*\d+\.\s*Human approval gates\s*$", re.IGNORECASE | re.MULTILINE
)


def _r4_human_gate_section(report: str) -> str | None:
    """Return the body of the R4 report's human approval gate section, or ``None``.

    The section is bounded by its own heading and the next ``##`` heading, so no later
    section can be mistaken for gate content. The R2 report uses a different heading
    ('## 9. 인간 게이트'); matching on the R4 wording keeps this check tied to the
    document it is actually reading. The section number is not pinned, so renumbering
    the report cannot silently turn the check off.
    """

    match = R4_HUMAN_GATE_HEADING.search(report)
    if match is None:
        return None
    body = report[match.end() :]
    following = re.search(r"^##\s", body, re.MULTILINE)
    return body if following is None else body[: following.start()]


def validate_r4_playable_slice(root: Path | None = None) -> dict[str, Any]:
    """Validate the R4 unit 1 internal playable slice against its published contract.

    ``root`` defaults to the repository; pointing it at a copy lets a negative test prove
    that a contract, disclosure or evidence file which disagrees with the implementation is
    actually rejected without writing to tracked files. The implementation constants are
    always read from the installed package, because the thing being checked is whether the
    *declaration* still describes the code that runs.

    The live exercise runs against a throwaway SQLite database in a temporary directory. The
    task contract forbids a database file inside the repository, and a validator that left
    one behind would be the first thing to break that rule. No socket is bound here: the HTTP
    surface is exercised over real connections in ``tests/test_roulette_web_server.py``.
    """

    base = ROOT if root is None else Path(root)

    def _json(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be an object")
        return value

    def _yaml(relative_path: str) -> dict[str, Any]:
        with (base / relative_path).open("r", encoding="utf-8") as handle:
            value = yaml.safe_load(handle)
        if not isinstance(value, dict):
            raise BaselineValidationError(f"{relative_path}: root must be a mapping")
        return value

    def _text(relative_path: str) -> str:
        return (base / relative_path).read_text(encoding="utf-8")

    from studio_core.collaboration import scan_for_plaintext_secrets
    from studio_core.rng import DeterministicTestEntropySource, RngEnvironment, verify_audit_chain

    from apps.roulette_web.server import (
        ALLOWED_STATIC_SUFFIXES,
        DEFAULT_HOST,
        DEFAULT_PORT,
        LOOPBACK_HOSTS,
        MAX_BODY_BYTES,
        ROUTES,
        SECURITY_HEADERS,
        STATIC_ROOT,
        create_server,
        open_table,
    )
    from apps.roulette_web.table import (
        CLIENT_AUTHORITY_FIELDS,
        NOTICE,
        TERMINAL_PHASES,
        TRANSITIONS,
        RoundPhase,
        TableConfig,
        TableError,
        default_database_path,
        prohibited_client_fields,
    )

    contract_path = "games/roulette/playable-slice-contract.yaml"
    contract = _yaml(contract_path)

    # -- the contract must state the interface the transport actually serves ---------------
    if dict(contract.get("endpoints", {})) != ROUTES:
        raise BaselineValidationError(f"{contract_path}: declared endpoints do not match server.ROUTES")
    declared_headers = dict(contract.get("security_headers", {}))
    if declared_headers != dict(SECURITY_HEADERS):
        differing = sorted(
            name
            for name in set(declared_headers) | {name for name, _ in SECURITY_HEADERS}
            if declared_headers.get(name) != dict(SECURITY_HEADERS).get(name)
        )
        raise BaselineValidationError(f"{contract_path}: security headers do not match the server: {differing!r}")
    policy = dict(SECURITY_HEADERS)["Content-Security-Policy"]
    for directive in ("default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'"):
        if directive not in policy:
            raise BaselineValidationError(f"the content security policy no longer pins {directive!r}")
    if "unsafe-inline" in policy or "unsafe-eval" in policy:
        raise BaselineValidationError("the content security policy must not permit inline or evaluated code")

    static = contract.get("static_assets", {})
    if dict(static.get("allowed_suffixes", {})) != ALLOWED_STATIC_SUFFIXES:
        raise BaselineValidationError(f"{contract_path}: the static asset allowlist does not match the server")
    if static.get("traversal_defence") != "resolve_then_containment_check":
        raise BaselineValidationError(f"{contract_path}: the declared traversal defence is not the implemented one")
    served_root = Path(str(static.get("root", ""))).name
    if served_root != STATIC_ROOT.name:
        raise BaselineValidationError(f"{contract_path}: the declared static root is not the served directory")
    stray = sorted(
        path.name
        for path in STATIC_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() not in ALLOWED_STATIC_SUFFIXES
    )
    if stray:
        raise BaselineValidationError(f"the static directory holds files outside the allowlist: {stray!r}")

    limits = contract.get("transport_limits", {})
    if limits.get("bind") != "loopback_only" or set(limits.get("allowed_hosts", [])) != set(LOOPBACK_HOSTS):
        raise BaselineValidationError(f"{contract_path}: the declared binding policy is not the implemented one")
    if limits.get("default_host") != DEFAULT_HOST or limits.get("default_port") != DEFAULT_PORT:
        raise BaselineValidationError(f"{contract_path}: the declared default bind address is wrong")
    if limits.get("max_body_bytes") != MAX_BODY_BYTES:
        raise BaselineValidationError(f"{contract_path}: the declared body limit is not the enforced one")

    # -- the client may not compute an authoritative value, or leave this origin -----------
    authority = contract.get("authority", {})
    if set(authority.get("rejected_client_fields", [])) != set(CLIENT_AUTHORITY_FIELDS):
        raise BaselineValidationError(f"{contract_path}: the rejected client field list has drifted")
    for key in (
        "client_computes_result",
        "client_computes_payout",
        "client_computes_balance",
        "baseline_modules_modified",
    ):
        if authority.get(key) is not False:
            raise BaselineValidationError(f"{contract_path}: authority.{key} must be declared false")
    if authority.get("client_authority") != "denied" or authority.get("client_source_of_randomness") != "none":
        raise BaselineValidationError(f"{contract_path}: the client authority boundary is not declared closed")
    if authority.get("currency_units") != "integer_minimum_units_only":
        raise BaselineValidationError(f"{contract_path}: currency must be declared as integer minimum units")

    script = _text("apps/roulette_web/static/app.js")
    markup = _text("apps/roulette_web/static/index.html")
    styles = _text("apps/roulette_web/static/styles.css")
    for label, source in (("app.js", script), ("index.html", markup), ("styles.css", styles)):
        # Only app.js may name the SVG namespace, and only as that literal; dropping it here
        # narrows the exemption to those characters instead of relaxing the off-origin rule.
        scanned = source.replace(R4_UI_SVG_NAMESPACE, "") if label == "app.js" else source
        present = [needle for needle in R4_UI_CLIENT_PROHIBITED if needle in scanned]
        if present:
            raise BaselineValidationError(f"{label} carries client-side authority or off-origin access: {present!r}")
    # A payout multiplier in the client would be a second, unversioned copy of the rule the
    # server settles by, so the payout table must not be reproducible from this file.
    payouts_module = __import__("studio_core.roulette", fromlist=["load_r1_rules"])
    payouts = payouts_module.load_r1_rules()["payouts"]
    for bet_type, multiplier in payouts.items():
        if re.search(rf'["\']?{re.escape(bet_type)}["\']?\s*:\s*{int(multiplier)}\b', script):
            raise BaselineValidationError(f"app.js appears to carry the payout multiplier for {bet_type!r}")
    refused = sorted(set(_R4MarkupScan(markup).refused))
    if refused:
        raise BaselineValidationError(
            f"index.html contains markup the content security policy would refuse: {refused!r}"
        )

    # -- the disclosure must be impossible to miss and must promise nothing ----------------
    disclosure = contract.get("disclosure", {})
    for key in ("scope", "currency", "cash_value", "text_en", "text_ko"):
        if disclosure.get(key) != NOTICE[key]:
            raise BaselineValidationError(f"{contract_path}: disclosure.{key} does not match the served notice")
    for surface, source in (("index.html", markup), ("apps/roulette_web/README.md", _text("apps/roulette_web/README.md"))):
        for phrase in (NOTICE["text_en"], NOTICE["text_ko"]):
            if phrase not in source:
                raise BaselineValidationError(f"{surface} does not carry the disclosure: {phrase!r}")

    # -- the round state machine must be the published one ---------------------------------
    round_state = _yaml("games/roulette/round-state.yaml")
    declared = [(item["from"], item["to"]) for item in contract["round_state"]["transitions"]]
    published = [(item["from"], item["to"]) for item in round_state["transitions"]]
    implemented = [(source.value, target.value) for source, target in TRANSITIONS]
    if declared != published or implemented != published:
        raise BaselineValidationError("the slice transition table does not match games/roulette/round-state.yaml")
    if set(contract["round_state"]["terminal_states"]) != {phase.value for phase in TERMINAL_PHASES}:
        raise BaselineValidationError(f"{contract_path}: the declared terminal states are not the implemented ones")
    guards = round_state["guards"]
    for key, expected in (
        ("accept_bets_only_in", contract["round_state"]["accept_bets_only_in"]),
        ("result_generated_only_in", contract["round_state"]["result_generated_only_in"]),
        ("ledger_settlement_only_in", contract["round_state"]["ledger_settlement_only_in"]),
    ):
        if guards[key] != expected:
            raise BaselineValidationError(f"{contract_path}: round_state.{key} does not match the published guard")

    # -- every refusal the slice can emit must be declared, and only those --------------------
    table_source = _text("apps/roulette_web/table.py")
    server_source = _text("apps/roulette_web/server.py")
    raised = _r4_declared_error_codes(table_source, server_source)
    listed = set(contract["error_codes"]["authority"]) | set(contract["error_codes"]["transport"])
    if raised != listed:
        raise BaselineValidationError(
            f"{contract_path}: error codes disagree with the implementation; "
            f"undeclared={sorted(raised - listed)!r} unimplemented={sorted(listed - raised)!r}"
        )

    # -- the baseline modules are used, never modified ---------------------------------------
    task = _json("tasks/R4-UI-0006.json")
    if task["status"] not in {"READY", "IN_PROGRESS", "REVIEW", "QA"} or task["risk_class"] != "HIGH":
        raise BaselineValidationError("R4-UI-0006 must remain a HIGH risk task under an open gate")
    if not {"A-50", "A-02", "A-00"} <= set(task["approvers"]):
        raise BaselineValidationError("a HIGH risk playable-slice task requires the mandatory reviewers")
    inputs = {item["uri"]: item["content_hash"] for item in task["inputs"]}
    for relative in R4_UI_BASELINE_MODULES:
        expected = inputs.get(f"repo://{relative}")
        if expected is None:
            raise BaselineValidationError(f"tasks/R4-UI-0006.json must declare {relative} as an input")
        decision = verify_file(base / relative, expected, label=relative)
        if not decision.matches:
            raise BaselineValidationError(f"a baseline module was modified by this unit: {decision.message}")

    # -- a real table, exercised end to end ---------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="r4ui-validate-") as workspace:
        database = Path(workspace) / "runtime" / "roulette-web.sqlite3"
        # Bytes that all survive the debiasing rule, so the draw is reached deterministically.
        entropy = DeterministicTestEntropySource(bytes([7, 11, 13, 17, 19, 23]))
        store, table = open_table(
            database,
            config=TableConfig(opening_player_units=1000, opening_house_units=100000),
            clock=lambda: "2026-09-01T00:00:00Z",
            entropy_source=entropy,
            environment=RngEnvironment.NON_PRODUCTION,
        )
        try:
            opening = table.state()
            if opening["notice"] != dict(NOTICE) or opening["currency"] != "VIRTUAL_CHIP":
                raise BaselineValidationError("the authoritative snapshot does not carry the disclosure")
            if opening["round"]["phase"] != RoundPhase.OPEN.value:
                raise BaselineValidationError("a fresh table does not open a round in OPEN")

            placed = table.place_bet("R4-VALIDATOR-BET-01", {"type": "red", "selections": [], "stake_units": 10})
            if placed.get("accepted") is not True:
                raise BaselineValidationError("the authoritative table refused a legal bet")

            # A rejected bet may not move the balance or the phase.
            before = table.state()
            try:
                table.place_bet("R4-VALIDATOR-BET-02", {"type": "straight", "selections": [37], "stake_units": 1})
            except TableError:
                pass
            else:
                raise BaselineValidationError("an impossible selection was accepted")
            after = table.state()
            if after["balance_units"] != before["balance_units"] or after["round"]["phase"] != before["round"]["phase"]:
                raise BaselineValidationError("a refused bet changed the balance or the round phase")

            consumed_before_spin = entropy.consumed
            spun = table.spin("R4-VALIDATOR-SPIN-01")
            result = spun["result"]
            if spun.get("replayed") is not False or not isinstance(result["pocket"], int):
                raise BaselineValidationError("the authoritative spin did not produce an integer pocket")
            if entropy.consumed == consumed_before_spin:
                raise BaselineValidationError("the authoritative draw did not read the entropy source")
            if table.state()["round"]["phase"] != RoundPhase.SETTLED.value:
                raise BaselineValidationError("a spun round did not reach SETTLED")

            # AC-006: a duplicate spin replays without spending entropy a second time.
            consumed_after_spin = entropy.consumed
            replay = table.spin("R4-VALIDATOR-SPIN-01")
            if replay.get("replayed") is not True or replay["result"]["pocket"] != result["pocket"]:
                raise BaselineValidationError("a duplicate spin did not replay the original result")
            if entropy.consumed != consumed_after_spin:
                raise BaselineValidationError("a duplicate spin consumed entropy again")

            # AC-002: no floating-point currency value exists on any authoritative surface.
            floats = _r4_floats(spun) + _r4_floats(table.state())
            if floats:
                raise BaselineValidationError(f"an authoritative payload carries floating-point values: {floats!r}")

            # AC-008: the recent-result list is the stored commit order.
            history = [item["round_id"] for item in table.state()["recent_results"]]
            if history != [item["round_id"] for item in table.reload_history()]:
                raise BaselineValidationError("the recent-result list is not the stored commit order")

            # AC-007: a request carrying a server-owned value is refused, not filtered.
            forged = {"request_id": "R4-VALIDATOR-FORGE-1", "bet": {"type": "red", "pocket": 7, "payout_units": 1}}
            if prohibited_client_fields(forged) != ["payout_units", "pocket"]:
                raise BaselineValidationError("forged authoritative fields are not detected in a nested payload")
        finally:
            store.close()

        if not database.is_file():
            raise BaselineValidationError("the slice did not create its database at the requested location")

    # AC-011: the server binds loopback only, and refuses anything else before binding.
    if DEFAULT_HOST not in LOOPBACK_HOSTS or "0.0.0.0" in LOOPBACK_HOSTS:
        raise BaselineValidationError("the slice default bind address is not loopback")
    for host in ("0.0.0.0", "::", "example.invalid"):
        try:
            create_server(object(), host=host, port=0)  # type: ignore[arg-type]
        except ValueError:
            continue
        raise BaselineValidationError(f"the server accepted the non-loopback host {host!r}")

    # The runtime database is not repository content, and no run may have left one behind.
    if Path(default_database_path()).is_absolute() and Path(default_database_path()).is_relative_to(ROOT):
        raise BaselineValidationError("the default runtime database resolves inside the repository")
    inside = sorted(
        path.relative_to(ROOT).as_posix()
        for path in repository_files()
        if path.suffix.lower() in R4_UI_RUNTIME_STATE_SUFFIXES
    )
    if inside:
        raise BaselineValidationError(f"a runtime database file is present in the repository: {inside!r}")

    # -- the unit's own audit record -----------------------------------------------------------
    audit_schema = _json("audit/audit-event.schema.json")
    events_document = _json("audit/events/R4-UI-0006-events.json")
    unit_events = events_document["events"]
    for event in unit_events:
        validate_instance(event, audit_schema)
        if event["task_id"] != "R4-UI-0006":
            raise BaselineValidationError("a playable-slice audit event is attached to the wrong task")
    chain_problems = verify_audit_chain(unit_events)
    if chain_problems:
        raise BaselineValidationError(f"the R4-UI-0006 audit chain is broken: {chain_problems!r}")
    actions = {event["action"] for event in unit_events}
    if not R4_UI_REQUIRED_AUDIT_ACTIONS <= actions:
        missing = sorted(R4_UI_REQUIRED_AUDIT_ACTIONS - actions)
        raise BaselineValidationError(f"the playable-slice audit record is incomplete: missing {missing!r}")

    # -- the artifact's declared component hashes must be canonical and current ----------------
    # ``content_hash`` covers the primary application file only; these secondary hashes name
    # every other component the artifact claims to have shipped, which would otherwise be
    # unverified prose that drifts as the files change. They are flat
    # ``component_hash:<path>`` keys because ``contracts/artifact.schema.json`` restricts
    # ``specification`` values to scalars; a nested mapping would fail schema validation.
    specification = _json("artifacts/R4-UI-0006-artifact.json")["specification"]
    prefix = "component_hash:"
    components = {
        key.removeprefix(prefix): value
        for key, value in specification.items()
        if key.startswith(prefix)
    }
    if not components:
        raise BaselineValidationError("the R4 artifact must declare component hashes")
    for relative, declared_hash in sorted(components.items()):
        if not isinstance(declared_hash, str) or not declared_hash.startswith("sha256:"):
            raise BaselineValidationError(f"the artifact component hash for {relative} is not a sha256 digest")
        if not (base / relative).is_file():
            raise BaselineValidationError(f"the artifact declares a hash for a missing file: {relative}")
        actual = hash_file(base / relative, label=relative)
        if declared_hash != actual:
            raise BaselineValidationError(
                f"artifact component hash does not match {relative}: {actual} != {declared_hash}"
            )
    for relative in (
        "apps/roulette_web/table.py",
        "apps/roulette_web/server.py",
        "apps/roulette_web/static/index.html",
        "apps/roulette_web/static/styles.css",
        "apps/roulette_web/static/app.js",
        "tests/test_roulette_web_server.py",
        "tests/test_roulette_web_ui.py",
        contract_path,
    ):
        if relative not in components:
            raise BaselineValidationError(f"the artifact does not declare a component hash for {relative}")

    # -- nothing may claim an approval, a run or a capability that did not happen --------------
    for field in (
        "human_approved",
        "browser_visual_qa_observed",
        "hosted_ci_observed",
        "independent_review_completed",
        "committed",
        "pushed",
        "rng_module_modified",
        "roulette_rules_module_modified",
        "durable_state_module_modified",
        "ledger_module_modified",
        "network_reconnect_guarantee_implemented",
        "load_or_performance_characterised",
        "penetration_tested",
        "production_ready",
    ):
        if specification.get(field) is not False:
            raise BaselineValidationError(f"the R4 artifact must record {field} as false")

    report = _text("docs/approvals/R4-UI-0006-validation-report.md")
    approval_section = _r4_human_gate_section(report)
    if approval_section is None:
        raise BaselineValidationError("the R4-UI-0006 validation report is missing its human gate section")
    if "- [x]" in approval_section.lower():
        raise BaselineValidationError("a human gate item is marked complete without a human sign-off")

    # -- the carried-forward scope must stay named ---------------------------------------------
    status = _text("docs/status/R2-STATUS.md")
    follow_ups = _text("docs/operations/R2-followup-units.md")
    design = _text("docs/games/R4-roulette-playable-slice.md")
    out_of_scope = " ".join(str(item) for item in contract.get("out_of_scope", []))
    for unit in R2_DBC_DEFERRED_UNITS:
        for label, document in (
            ("docs/status/R2-STATUS.md", status),
            ("docs/operations/R2-followup-units.md", follow_ups),
            ("docs/games/R4-roulette-playable-slice.md", design),
            (contract_path, out_of_scope),
        ):
            if unit not in document:
                raise BaselineValidationError(f"{label} no longer carries {unit} forward")

    for relative in (
        contract_path,
        "docs/games/R4-roulette-playable-slice.md",
        "docs/approvals/R4-UI-0006-validation-report.md",
        "apps/roulette_web/README.md",
        "audit/events/R4-UI-0006-events.json",
    ):
        if scan_for_plaintext_secrets(_text(relative)):
            raise BaselineValidationError(f"{relative}: plaintext credential material detected")

    return {"contract": contract, "events": unit_events, "error_codes": sorted(raised)}


def _raise_injected(reached: str, target: str) -> None:
    """Raise at exactly one durable-state fault stage. Used only by the validator."""

    if reached == target:
        raise RuntimeError(f"injected durable-state fault at {target}")


def run_validation() -> list[str]:
    checks: list[tuple[str, Any]] = [
        ("필수 기준선 파일", validate_required_files),
        ("상시 에이전트 9종 Registry", validate_agent_registry),
    ]
    passed: list[str] = []
    agent_definitions: dict[str, dict[str, Any]] | None = None
    for label, function in checks:
        result = function()
        if label.startswith("상시"):
            agent_definitions = result
        passed.append(label)
    assert agent_definitions is not None
    validate_contracts(agent_definitions)
    passed.append("Task·Handoff·Artifact 계약과 예제")
    validate_operations(agent_definitions)
    passed.append("SYS-004 채팅방·권한·상태 워크플로")
    validate_knowledge(agent_definitions)
    passed.append("SYS-005 지식 승인·검색·폐기")
    validate_providers(agent_definitions)
    passed.append("SYS-006 Provider Adapter 계약")
    validate_claude_workspace()
    passed.append("ADR-0003 Claude 단독 프로그래밍 작업장")
    validate_evals(agent_definitions)
    passed.append("SYS-007 파트별 Eval Set v1")
    validate_roulette()
    passed.append("SYS-008 룰렛 규칙·테스트 명세")
    validate_policies()
    passed.append("SYS-009 보안·비용·감사 정책")
    validate_r0_approval(agent_definitions)
    passed.append("SYS-010 R0 사용자 최종 승인")
    validate_r1_roulette()
    passed.append("R1 룰렛 규칙·경제 후보 기준선")
    validate_binary_asset_policy()
    passed.append("SYS-AST-0014 바이너리 자산 기본 거부 정책·매니페스트 스키마·.gitattributes 고정")
    validate_content_integrity()
    passed.append("산출물 content_hash 정규 표현 무결성 (LF 정규화 텍스트·원시 바이트 이진)")
    validate_collaboration(agent_definitions)
    passed.append("SYS-CLD-0011 Codex 발주·Claude 구현·Codex 독립검증 협업 프로토콜")
    validate_r2_rng()
    passed.append("R2-RNG-0001 생산용 CSPRNG 추첨 경계·독립 통계·게이트 회수 기록")
    validate_r2_durable_state()
    passed.append("R2-DBC-0002 내구 상태 경계·격리 수준·원자성·동시성·장애 복구")
    validate_r4_playable_slice()
    passed.append("R4-UI-0006 로컬 플레이어블 슬라이스 계약·서버 권위·클라이언트 무권위·공개 문구")
    validate_r2_reconnect()
    passed.append("R2-NET-0003 재접속·라운드 연속성 계약·무경로 확장·동결 경로 무결성")
    return passed


def main() -> int:
    try:
        passed = run_validation()
    except (BaselineValidationError, OSError, ArithmeticError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"[FAIL] R0 baseline: {exc}", file=sys.stderr)
        return 1

    for label in passed:
        print(f"[PASS] {label}")
    print("[PASS] R0 v1.1.0 is approved; R1 roulette candidate is internally consistent")
    print("[NOTICE] R1 remains a candidate; production scheduling remains prohibited until R5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
