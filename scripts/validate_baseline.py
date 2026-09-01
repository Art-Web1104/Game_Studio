#!/usr/bin/env python3
"""Validate the TS STUDIO R0 control-plane baseline and executable policies."""

from __future__ import annotations

import json
import hashlib
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
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
        "providers/connection-proof.schema.json",
        "providers/evidence/SYS-CLD-0011-claude-connection-proof.yaml",
        "tasks/SYS-CLD-0011.json",
        "artifacts/SYS-CLD-0011-artifact.json",
        "handoffs/SYS-CLD-0011-handoff.json",
        "docs/operations/SYS-CLD-0011-codex-claude-collaboration.md",
        "tests/test_collaboration.py",
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
        actual_hash = "sha256:" + hashlib.sha256(content_path.read_bytes()).hexdigest()
        if item["provenance"]["content_hash"] != actual_hash:
            raise BaselineValidationError("knowledge provenance hash does not match content_ref")
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
            actual = "sha256:" + hashlib.sha256((ROOT / content_path).read_bytes()).hexdigest()
            if artifact["content_hash"] != actual:
                raise BaselineValidationError(f"{task['task_id']}: artifact content_hash does not match {content_path}")

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
    validate_collaboration(agent_definitions)
    passed.append("SYS-CLD-0011 Codex 발주·Claude 구현·Codex 독립검증 협업 프로토콜")
    return passed


def main() -> int:
    try:
        passed = run_validation()
    except (BaselineValidationError, OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"[FAIL] R0 baseline: {exc}", file=sys.stderr)
        return 1

    for label in passed:
        print(f"[PASS] {label}")
    print("[PASS] R0 v1.1.0 is approved; R1 roulette candidate is internally consistent")
    print("[NOTICE] R1 remains a candidate; production scheduling remains prohibited until R5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
