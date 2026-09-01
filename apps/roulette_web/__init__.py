"""R4-UI-0006: internal, local, single-player European single-zero roulette slice.

The package holds two layers and nothing else:

``table``
    The authority. It owns the round state machine, integer virtual-chip balances,
    bet validation and settlement. It answers every question the client is not
    allowed to answer for itself.
``server``
    A transport. It parses JSON, enforces request limits, and hands whole decisions
    to :class:`~apps.roulette_web.table.RouletteTable`. It contains no game rules.

Rules, entropy and durability are *used*, never restated: bets go through
:func:`studio_core.roulette.validate_bet` and :func:`studio_core.roulette.settle_bet`,
the draw goes through :class:`studio_core.rng.RouletteDrawEngine` behind
:class:`studio_core.durable_state.DurableRoundStore`, and every authoritative commit is
the store's single transaction. This package adds no table, no pragma and no second
opinion about what a round means.

Scope: one local user, one process, one table, virtual chips with no cash value. There is
no account, no login, no personal data, no outbound network call and no purchase path.
"""

from .table import (
    NOTICE,
    RoundPhase,
    RouletteTable,
    TableError,
    TableConfig,
)

__all__ = [
    "NOTICE",
    "RoundPhase",
    "RouletteTable",
    "TableConfig",
    "TableError",
]
