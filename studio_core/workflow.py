"""Reference evaluator for SYS-004 task state transitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .config import load_yaml


@dataclass(frozen=True)
class TransitionDecision:
    allowed: bool
    code: str
    message: str


def evaluate_transition(
    task: dict[str, Any],
    target_state: str,
    *,
    actor_agent_id: str,
    approvals: Iterable[str] = (),
    evidence_refs: Iterable[str] = (),
    blocked_reason: str | None = None,
    policy: dict[str, Any] | None = None,
) -> TransitionDecision:
    policy = policy or load_yaml("operations/workflow.yaml")
    current = task.get("status")
    transition = next(
        (
            item
            for item in policy["transitions"]
            if item["from"] == current and item["to"] == target_state
        ),
        None,
    )
    if transition is None:
        return TransitionDecision(False, "INVALID_TRANSITION", f"{current} -> {target_state} is not allowed")

    actor_rule = transition.get("actor", "owner")
    if actor_rule == "owner" and actor_agent_id != task.get("owner_agent_id"):
        return TransitionDecision(False, "ACTOR_DENIED", "only the task owner may perform this transition")
    if actor_rule.startswith("agent:") and actor_agent_id != actor_rule.split(":", 1)[1]:
        return TransitionDecision(False, "ACTOR_DENIED", f"{actor_rule} is required")

    if transition.get("requires_blocked_reason") and not blocked_reason:
        return TransitionDecision(False, "MISSING_BLOCK_REASON", "a blocked reason is required")
    if transition.get("requires_evidence") and not list(evidence_refs):
        return TransitionDecision(False, "MISSING_EVIDENCE", "verification evidence is required")

    provided = set(approvals)
    required = set(transition.get("required_approvals", []))
    if target_state == "DONE":
        required.update(policy["done_gate"][task["risk_class"]])
    missing = sorted(required - provided)
    if missing:
        return TransitionDecision(False, "MISSING_APPROVAL", f"missing approvals: {', '.join(missing)}")

    return TransitionDecision(True, "ALLOWED", "transition satisfies the workflow policy")
