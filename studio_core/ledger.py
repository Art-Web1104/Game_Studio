"""Integer, balanced, idempotent virtual-currency ledger reference for R1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class LedgerDecision:
    applied: bool
    code: str
    balances: dict[str, int]


def post_transaction(
    transaction: dict[str, Any],
    balances: dict[str, int],
    applied_idempotency_keys: Iterable[str],
) -> LedgerDecision:
    key = transaction.get("idempotency_key")
    if not isinstance(key, str) or not key:
        raise ValueError("idempotency_key is required")
    if key in set(applied_idempotency_keys):
        return LedgerDecision(False, "DUPLICATE_NOOP", dict(balances))
    entries = transaction.get("entries")
    if not isinstance(entries, list) or len(entries) < 2:
        raise ValueError("a ledger transaction requires at least two entries")
    amounts = [entry.get("amount_units") for entry in entries]
    if any(not isinstance(amount, int) or isinstance(amount, bool) or amount == 0 for amount in amounts):
        raise ValueError("ledger amounts must be non-zero integers")
    if sum(amounts) != 0:
        raise ValueError("ledger entries must sum to zero")
    updated = dict(balances)
    for entry in entries:
        account_id = entry.get("account_id")
        if not isinstance(account_id, str) or not account_id:
            raise ValueError("ledger account_id is required")
        if account_id not in updated:
            raise ValueError(f"unknown ledger account: {account_id}")
        updated[account_id] += entry["amount_units"]
        if entry.get("account_type") == "PLAYER" and updated[account_id] < 0:
            raise ValueError("player balance cannot become negative")
    return LedgerDecision(True, "APPLIED", updated)
