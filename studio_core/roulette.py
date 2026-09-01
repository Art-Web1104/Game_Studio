"""Deterministic European roulette settlement reference for SYS-008."""

from __future__ import annotations

from typing import Any

from .config import load_yaml


INSIDE_BETS = {"straight", "split", "street", "corner", "six_line"}
INDEX_BETS = {"dozen", "column"}
OUTSIDE_BETS = {"red", "black", "odd", "even", "low", "high"}


def load_r1_rules() -> dict[str, Any]:
    rules = load_yaml("games/roulette/rules-reference.yaml")
    extension = load_yaml("games/roulette/r1-rules-extension.yaml")
    rules["gate_status"] = extension["gate_status"]
    rules["limits"] = extension["limits"]
    rules["unsupported_bets"] = extension["unsupported_bets"]
    return rules


def _valid_inside_geometry(kind: str, selections: list[int]) -> bool:
    values = sorted(selections)
    if kind == "straight":
        return len(values) == 1
    if kind == "split":
        if len(values) != 2:
            return False
        low, high = values
        if low == 0:
            return high in {1, 2, 3}
        return high - low == 3 or (high - low == 1 and (low - 1) // 3 == (high - 1) // 3)
    if kind == "street":
        return len(values) == 3 and values[0] > 0 and values == list(range(values[0], values[0] + 3)) and values[0] % 3 == 1
    if kind == "corner":
        if len(values) != 4 or values[0] <= 0:
            return False
        start = values[0]
        return start <= 32 and start % 3 in {1, 2} and values == [start, start + 1, start + 3, start + 4]
    if kind == "six_line":
        return len(values) == 6 and values[0] > 0 and values[0] <= 31 and values[0] % 3 == 1 and values == list(range(values[0], values[0] + 6))
    return False


def valid_selection_sets(bet_type: str) -> list[list[int]]:
    """Enumerate every canonical selection set supported by the R1 table."""

    if bet_type == "straight":
        return [[number] for number in range(37)]
    if bet_type == "split":
        values = [{0, number} for number in (1, 2, 3)]
        values.extend({number, number + 1} for number in range(1, 37) if number % 3 != 0)
        values.extend({number, number + 3} for number in range(1, 34))
        return [sorted(item) for item in sorted(values, key=lambda item: tuple(sorted(item)))]
    if bet_type == "street":
        return [list(range(start, start + 3)) for start in range(1, 35, 3)]
    if bet_type == "corner":
        return [[start, start + 1, start + 3, start + 4] for row in range(11) for start in (1 + row * 3, 2 + row * 3)]
    if bet_type == "six_line":
        return [list(range(start, start + 6)) for start in range(1, 32, 3)]
    if bet_type in INDEX_BETS:
        return [[index] for index in (1, 2, 3)]
    if bet_type in OUTSIDE_BETS:
        return [[]]
    raise ValueError(f"unsupported bet type: {bet_type}")


def validate_bet(bet: dict[str, Any], rules: dict[str, Any] | None = None) -> None:
    """Reject malformed or geometrically impossible R1 bets."""

    rules = rules or load_r1_rules()
    kind = bet.get("type")
    if kind not in rules["payouts"]:
        raise ValueError(f"unsupported bet type: {kind}")
    stake = bet.get("stake_units")
    limits = rules.get("limits", {"min_stake_units": 1, "max_stake_units": 100000})
    if not isinstance(stake, int) or isinstance(stake, bool) or not limits["min_stake_units"] <= stake <= limits["max_stake_units"]:
        raise ValueError("stake_units is outside the allowed positive-integer range")
    selections = bet.get("selections", [])
    if not isinstance(selections, list) or any(not isinstance(item, int) or isinstance(item, bool) for item in selections):
        raise ValueError("selections must be an integer list")
    if len(selections) != len(set(selections)):
        raise ValueError("selections must be unique")
    if len(selections) != rules["bet_selection_counts"][kind]:
        raise ValueError("selection count does not match the bet type")
    if kind in INSIDE_BETS:
        if not set(selections) <= set(rules["table"]["pockets"]) or not _valid_inside_geometry(kind, selections):
            raise ValueError("inside-bet selections are not valid table geometry")
    elif kind in INDEX_BETS:
        if selections[0] not in {1, 2, 3}:
            raise ValueError("dozen and column indexes must be 1, 2, or 3")
    elif kind in OUTSIDE_BETS and selections:
        raise ValueError("outside bets cannot include selections")


def _wins(bet: dict[str, Any], result: int, rules: dict[str, Any]) -> bool:
    kind = bet["type"]
    selections = bet.get("selections", [])
    if kind in {"straight", "split", "street", "corner", "six_line"}:
        return result in selections
    if result == 0:
        return False
    if kind == "red":
        return result in rules["table"]["red_numbers"]
    if kind == "black":
        return result not in rules["table"]["red_numbers"]
    if kind == "odd":
        return result % 2 == 1
    if kind == "even":
        return result % 2 == 0
    if kind == "low":
        return 1 <= result <= 18
    if kind == "high":
        return 19 <= result <= 36
    if kind == "dozen":
        index = selections[0]
        return (index - 1) * 12 + 1 <= result <= index * 12
    if kind == "column":
        return result > 0 and ((result - 1) % 3) + 1 == selections[0]
    raise ValueError(f"unsupported bet type: {kind}")


def settle_bet(bet: dict[str, Any], result: int, rules: dict[str, Any] | None = None) -> dict[str, int | bool]:
    rules = rules or load_r1_rules()
    if result not in rules["table"]["pockets"]:
        raise ValueError("result must be a European roulette pocket from 0 through 36")
    validate_bet(bet, rules)
    stake = bet["stake_units"]
    payout = rules["payouts"].get(bet["type"])
    if payout is None:
        raise ValueError(f"unsupported bet type: {bet['type']}")
    won = _wins(bet, result, rules)
    profit = stake * payout if won else -stake
    total_return = stake * (payout + 1) if won else 0
    return {"won": won, "net_change_units": profit, "total_return_units": total_return}


def theoretical_return(bet_type: str, rules: dict[str, Any] | None = None) -> dict[str, float]:
    """Return exact single-zero hit probability, RTP, and house edge."""

    rules = rules or load_r1_rules()
    winning_pockets = rules["bet_selection_counts"].get(bet_type)
    if bet_type in OUTSIDE_BETS:
        winning_pockets = 18
    elif bet_type in INDEX_BETS:
        winning_pockets = 12
    if not winning_pockets or bet_type not in rules["payouts"]:
        raise ValueError(f"unsupported bet type: {bet_type}")
    probability = winning_pockets / 37
    total_return_multiplier = rules["payouts"][bet_type] + 1
    rtp = probability * total_return_multiplier
    return {"hit_probability": probability, "rtp": rtp, "house_edge": 1.0 - rtp}
