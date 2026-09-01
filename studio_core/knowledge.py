"""Reference evaluator for SYS-005 approved-knowledge retrieval."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


CLASSIFICATION_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


@dataclass(frozen=True)
class KnowledgeDecision:
    allowed: bool
    code: str
    message: str


def evaluate_retrieval(
    item: dict[str, Any],
    *,
    agent_id: str,
    requested_scope: str,
    max_classification: str,
) -> KnowledgeDecision:
    if item.get("status") != "APPROVED":
        return KnowledgeDecision(False, "STATUS_DENIED", "only APPROVED knowledge is retrievable")
    if item.get("scope") not in {requested_scope, "studio"}:
        return KnowledgeDecision(False, "SCOPE_DENIED", "knowledge scope does not match the request")
    allowed_agents = item.get("retrieval", {}).get("allowed_agents", [])
    if "*" not in allowed_agents and agent_id not in allowed_agents:
        return KnowledgeDecision(False, "AGENT_DENIED", "agent is not in the retrieval allowlist")
    item_level = item.get("security", {}).get("classification")
    if item_level not in CLASSIFICATION_RANK or max_classification not in CLASSIFICATION_RANK:
        return KnowledgeDecision(False, "CLASSIFICATION_INVALID", "classification is not recognized")
    if CLASSIFICATION_RANK[item_level] > CLASSIFICATION_RANK[max_classification]:
        return KnowledgeDecision(False, "CLASSIFICATION_DENIED", "request clearance is insufficient")
    if not item.get("rights", {}).get("ai_use_allowed", False):
        return KnowledgeDecision(False, "RIGHTS_DENIED", "AI use rights are not approved")
    return KnowledgeDecision(True, "ALLOWED", "knowledge item is eligible for retrieval")
