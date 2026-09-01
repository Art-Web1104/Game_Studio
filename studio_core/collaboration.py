"""Executable gates for the SYS-CLD-0011 Codex/Claude/Codex collaboration protocol.

The policy data lives in ``operations/collaboration.yaml``; this module is its executable
interpretation, used by ``scripts/validate_baseline.py`` and by the negative test suite.
Every gate is pure and returns a decision object instead of raising, so a denial stays
auditable and can be replayed by the independent verifier.

Secret-detection patterns are intentionally kept in code rather than in the protocol file:
the validator scans the protocol and its sibling artifacts with these same patterns, and a
pattern stored next to the scanned text would have to be written so that it never matches
itself.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .config import load_yaml

PROTOCOL_PATH = "operations/collaboration.yaml"

AGENT_ID_PATTERN = re.compile(r"^A-[0-9]{2}$")

#: Patterns that indicate a plaintext credential value. They must match credential material
#: only, never the policy vocabulary (``secret-ref://``, ``secrets_policy`` and friends).
FORBIDDEN_VALUE_PATTERNS: tuple[str, ...] = (
    r"sk-ant-[A-Za-z0-9_\-]{16,}",
    r"\bsk-[A-Za-z0-9]{20,}",
    r"\bghp_[A-Za-z0-9]{20,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)"
    r"\b\s*[:=]\s*[\"']?[A-Za-z0-9+/=_\-]{12,}",
    r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}",
)


@dataclass(frozen=True)
class CollaborationDecision:
    """Outcome of a collaboration gate."""

    allowed: bool
    code: str
    message: str


@dataclass(frozen=True)
class ActivationDecision:
    """Outcome of the provider activation gate, including the status the caller may record."""

    allowed: bool
    code: str
    resulting_status: str
    message: str


def load_protocol(protocol: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return the collaboration protocol, loading it from the repository when omitted."""

    if protocol is not None:
        return dict(protocol)
    return load_yaml(PROTOCOL_PATH)


def required_commands(protocol: Mapping[str, Any] | None = None) -> list[str]:
    """Return the standard verification commands every completion report must replay."""

    return list(load_protocol(protocol)["completion_gate"]["required_checks"])


def expected_paths(task_id: str, protocol: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Return the repository paths a delegated task must produce, derived from the protocol."""

    directories = load_protocol(protocol)["directories"]
    return {
        "task_contract": f"{directories['task_contracts']}/{task_id}.json",
        "artifact_contract": f"{directories['artifact_contracts']}/{task_id}-artifact.json",
        "handoff_packet": f"{directories['handoff_packets']}/{task_id}-handoff.json",
    }


def _serialize(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def scan_for_plaintext_secrets(payload: Any) -> list[str]:
    """Return the forbidden credential patterns that match anywhere inside ``payload``.

    Only the matching pattern is returned; the matched value is never echoed so that a
    detection cannot itself leak the secret into logs or evidence files.
    """

    text = _serialize(payload)
    return [pattern for pattern in FORBIDDEN_VALUE_PATTERNS if re.search(pattern, text)]


def missing_evidence_commands(handoff: Mapping[str, Any], commands: Iterable[str]) -> list[str]:
    """Return the required commands the handoff does not record as a passing check."""

    passed = {
        item.get("check")
        for item in handoff.get("verification_evidence", [])
        if item.get("result") == "PASS"
    }
    return [command for command in commands if command not in passed]


def evaluate_role_action(
    role: str,
    action: str,
    *,
    protocol: Mapping[str, Any] | None = None,
) -> CollaborationDecision:
    """Decide whether a collaboration role may perform an action.

    Actions are default-deny: a role may act only through an explicit ``allowed`` flag or a
    declared duty, and an explicit ``denied`` flag always wins.
    """

    roles = load_protocol(protocol)["roles"]
    definition = roles.get(role)
    if not isinstance(definition, Mapping):
        return CollaborationDecision(False, "ROLE_UNKNOWN", f"{role!r} is not a collaboration role")

    flag = definition.get(action)
    if flag == "denied":
        return CollaborationDecision(False, "ACTION_DENIED", f"{role} may not perform {action}")
    if flag == "allowed" or action in definition.get("duties", []):
        return CollaborationDecision(True, "ACTION_ALLOWED", f"{role} may perform {action}")
    return CollaborationDecision(False, "ACTION_DENIED", f"{action} is not a declared duty of {role}")


def evaluate_delegation(
    task: Mapping[str, Any],
    *,
    console: str,
    actor_agent_id: str,
    protocol: Mapping[str, Any] | None = None,
) -> CollaborationDecision:
    """Decide whether a Task Contract may be implemented by the programming console."""

    policy = load_protocol(protocol)
    gate = policy["delegation_gate"]
    implementer = policy["roles"]["implementer"]

    missing = [field for field in gate["required_task_fields"] if field not in task]
    if missing:
        return CollaborationDecision(False, "MISSING_TASK_FIELD", f"task contract is missing {missing!r}")

    if console != implementer["console"]:
        return CollaborationDecision(
            False,
            "CONSOLE_DENIED",
            f"implementation runs only on {implementer['console']!r}; {console!r} is denied",
        )
    if implementer["provider_id"] != gate["code_provider"]:
        return CollaborationDecision(
            False, "PROVIDER_SUBSTITUTION_DENIED", "the implementer provider does not match the code provider"
        )

    owner = task["owner_agent_id"]
    if not isinstance(owner, str) or AGENT_ID_PATTERN.fullmatch(owner) is None:
        return CollaborationDecision(False, "OWNER_INVALID", f"owner_agent_id is malformed: {owner!r}")
    if gate["require_single_owner"] and actor_agent_id != owner:
        return CollaborationDecision(
            False, "ACTOR_DENIED", f"{actor_agent_id} is not the single owner {owner} of {task['task_id']}"
        )
    if actor_agent_id not in implementer["acts_for"]:
        return CollaborationDecision(
            False, "ACTOR_DENIED", f"{actor_agent_id} may not act as the implementer role"
        )

    status = task["status"]
    if status not in gate["allowed_task_status"]:
        return CollaborationDecision(
            False, "STATUS_DENIED", f"delegation requires {gate['allowed_task_status']!r}, found {status!r}"
        )

    security = task["security"]
    order = gate["classification_order"]
    classification = security["data_classification"]
    if classification not in order or order.index(classification) > order.index(gate["max_data_classification"]):
        return CollaborationDecision(
            False,
            "CLASSIFICATION_DENIED",
            f"{classification} exceeds {gate['max_data_classification']}",
        )
    if security.get("contains_pii") is not False:
        return CollaborationDecision(False, "PII_DENIED", "personal data may not be delegated to a provider")
    if security["secrets_policy"] not in gate["allowed_secrets_policy"]:
        return CollaborationDecision(
            False,
            "SECRETS_POLICY_DENIED",
            f"secrets policy {security['secrets_policy']!r} is not in {gate['allowed_secrets_policy']!r}",
        )

    if gate["require_stop_on_limit"] and task["budget"].get("stop_on_limit") is not True:
        return CollaborationDecision(False, "BUDGET_POLICY_DENIED", "the task budget must stop on limit")
    if gate["required_approver"] not in task["approvers"]:
        return CollaborationDecision(
            False, "APPROVER_MISSING", f"{gate['required_approver']} must approve a delegated task"
        )

    return CollaborationDecision(
        True, "DELEGATED", f"{task['task_id']} may be implemented by {gate['code_provider']} on {console}"
    )


def evaluate_independent_verification(
    handoff: Mapping[str, Any],
    *,
    console: str,
    verifier_agent_id: str,
    protocol: Mapping[str, Any] | None = None,
) -> CollaborationDecision:
    """Decide whether a Handoff Packet can be independently verified by the named actor."""

    policy = load_protocol(protocol)
    verifier_role = policy["roles"]["independent_verifier"]
    duties = policy["separation_of_duties"]
    completion = policy["completion_gate"]

    if console != verifier_role["console"]:
        return CollaborationDecision(
            False,
            "CONSOLE_DENIED",
            f"independent verification runs only on {verifier_role['console']!r}; {console!r} is denied",
        )
    if duties["generator_is_reviewer"] == "denied" and verifier_agent_id == handoff["from_agent_id"]:
        return CollaborationDecision(
            False, "SELF_VERIFICATION_DENIED", f"{verifier_agent_id} generated the work and cannot verify it"
        )
    if verifier_agent_id not in verifier_role["acts_for"]:
        return CollaborationDecision(
            False, "ROLE_DENIED", f"{verifier_agent_id} is not an eligible independent verifier"
        )
    if handoff["from_agent_id"] == handoff["to_agent_id"]:
        return CollaborationDecision(False, "SELF_HANDOFF_DENIED", "a handoff cannot be addressed to its sender")
    if handoff["readiness"] not in completion["allowed_readiness"]:
        return CollaborationDecision(
            False, "INVALID_READINESS", f"unsupported readiness {handoff['readiness']!r}"
        )
    if completion["acknowledgement_required"] and handoff.get("acknowledgement_required") is not True:
        return CollaborationDecision(
            False, "ACKNOWLEDGEMENT_REQUIRED", "the receiver must acknowledge the handoff"
        )
    if len(handoff["verification_evidence"]) < completion["minimum_verification_evidence"]:
        return CollaborationDecision(
            False,
            "INSUFFICIENT_EVIDENCE",
            f"at least {completion['minimum_verification_evidence']} verification records are required",
        )

    missing = missing_evidence_commands(handoff, completion["required_checks"])
    if missing:
        return CollaborationDecision(
            False, "MISSING_EVIDENCE", f"commands without a {completion['required_result']} record: {missing!r}"
        )

    return CollaborationDecision(
        True, "VERIFIABLE", f"{verifier_agent_id} may independently verify {handoff['handoff_id']}"
    )


def evaluate_final_gate(
    handoff: Mapping[str, Any],
    *,
    approver: str,
    verification_result: str,
    protocol: Mapping[str, Any] | None = None,
) -> CollaborationDecision:
    """Decide whether the final QA gate decision may be issued by ``approver``."""

    policy = load_protocol(protocol)
    duties = policy["separation_of_duties"]
    completion = policy["completion_gate"]

    if duties["generator_is_final_approver"] == "denied" and approver == handoff["from_agent_id"]:
        return CollaborationDecision(
            False, "SELF_APPROVAL_DENIED", f"{approver} generated the work and cannot issue the final gate"
        )
    if approver not in duties["final_gate"]:
        return CollaborationDecision(
            False, "GATE_DENIED", f"the final gate requires one of {duties['final_gate']!r}"
        )
    if verification_result != completion["required_result"]:
        return CollaborationDecision(
            False,
            "VERIFICATION_INCOMPLETE",
            f"independent verification is {verification_result!r}, not {completion['required_result']!r}",
        )

    return CollaborationDecision(
        True, "FINAL_GATE_ALLOWED", f"{approver} may issue the final gate for {handoff['handoff_id']}"
    )


def evaluate_provider_activation(
    provider_id: str,
    target_status: str,
    proof: Mapping[str, Any] | None,
    *,
    protocol: Mapping[str, Any] | None = None,
) -> ActivationDecision:
    """Decide whether a provider registry entry may hold ``target_status``.

    Only a promotion to the proven status is gated; keeping or restoring the unproven status
    never requires evidence.
    """

    policy = load_protocol(protocol)
    gate = policy["provider_activation"]
    blocked = gate["on_incomplete_evidence"]

    if target_status not in (gate["proven_status"], gate["unproven_status"]):
        return ActivationDecision(
            False, "STATUS_UNSUPPORTED", blocked, f"{target_status!r} is not a gated provider status"
        )
    if target_status != gate["proven_status"]:
        return ActivationDecision(
            True, "NOT_AN_ACTIVATION", target_status, f"{provider_id} stays at {target_status} without evidence"
        )
    if provider_id != gate["provider_id"]:
        return ActivationDecision(
            False,
            "PROVIDER_DENIED",
            blocked,
            f"only {gate['provider_id']} may be activated by this gate; {provider_id!r} is denied",
        )

    if not isinstance(proof, Mapping):
        return ActivationDecision(False, "PROOF_MISSING", blocked, "a connection proof record is required")
    if proof.get("provider_id") != provider_id:
        return ActivationDecision(
            False, "PROOF_PROVIDER_MISMATCH", blocked, f"the proof targets {proof.get('provider_id')!r}"
        )

    authorization = proof.get("user_authorization", {})
    if authorization.get("granted") is not True or authorization.get("approver") != "USER":
        return ActivationDecision(
            False, "AUTHORIZATION_MISSING", blocked, "explicit user authorization is required to activate"
        )

    if proof.get("secret_values_recorded") is not False:
        return ActivationDecision(
            False, "SECRET_LEAK_RISK", blocked, "the proof claims recorded secret values"
        )
    if proof.get("environment", {}).get("contains_secret_values") is not False:
        return ActivationDecision(
            False, "SECRET_LEAK_RISK", blocked, "the proof environment claims secret values"
        )

    credential_ref = proof.get("credential_ref")
    prefix = policy["credentials"]["reference_prefix"]
    if not isinstance(credential_ref, str) or not credential_ref.startswith(prefix):
        return ActivationDecision(
            False, "CREDENTIAL_NOT_REFERENCED", blocked, f"credentials must be recorded as {prefix} references"
        )
    if re.fullmatch(r"[a-z0-9][a-z0-9/_-]{2,80}", credential_ref[len(prefix):]) is None:
        return ActivationDecision(
            False, "CREDENTIAL_NOT_REFERENCED", blocked, "the credential locator is malformed"
        )
    if proof.get("credential_source") not in gate["allowed_credential_sources"]:
        return ActivationDecision(
            False,
            "CREDENTIAL_SOURCE_DENIED",
            blocked,
            f"credential source {proof.get('credential_source')!r} is not an approved store",
        )

    if proof.get("recorded_by") == proof.get("verified_by"):
        return ActivationDecision(
            False, "SELF_VERIFICATION_DENIED", blocked, "the proof recorder cannot also be its verifier"
        )

    probes: Sequence[Mapping[str, Any]] = proof.get("probes", [])
    if len(probes) < gate["minimum_probes"]:
        return ActivationDecision(
            False,
            "PROBE_INCOMPLETE",
            blocked,
            f"at least {gate['minimum_probes']} probes are required, found {len(probes)}",
        )
    unmet = [probe.get("probe_id") for probe in probes if probe.get("result") != "PASS"]
    if unmet:
        return ActivationDecision(False, "PROBE_INCOMPLETE", blocked, f"probes are not PASS: {unmet!r}")

    if proof.get("overall_result") != "PASS" or proof.get("activation_recommendation") != "ENABLE":
        return ActivationDecision(
            False, "PROOF_INCOMPLETE", blocked, f"the proof result is {proof.get('overall_result')!r}"
        )

    matched = scan_for_plaintext_secrets(proof)
    if matched:
        return ActivationDecision(
            False, "SECRET_LEAK_RISK", blocked, f"connection evidence matched {len(matched)} secret rules"
        )

    return ActivationDecision(
        True,
        "ACTIVATION_ALLOWED",
        gate["proven_status"],
        f"{provider_id} may be promoted to {gate['proven_status']}",
    )
