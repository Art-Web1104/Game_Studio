"""Server-authoritative roulette round state reference for R1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .config import load_yaml


@dataclass(frozen=True)
class RoundDecision:
    allowed: bool
    code: str


def evaluate_round_transition(
    current_state: str,
    target_state: str,
    *,
    actor: str,
    evidence: Iterable[str] = (),
) -> RoundDecision:
    policy = load_yaml("games/roulette/round-state.yaml")
    transition = next((item for item in policy["transitions"] if item["from"] == current_state and item["to"] == target_state), None)
    if transition is None:
        return RoundDecision(False, "INVALID_TRANSITION")
    if actor != transition["actor"]:
        return RoundDecision(False, "ACTOR_DENIED")
    if transition.get("requires_evidence") and not list(evidence):
        return RoundDecision(False, "MISSING_EVIDENCE")
    return RoundDecision(True, "ALLOWED")
