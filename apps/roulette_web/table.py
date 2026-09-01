"""Authoritative single-table roulette service for the R4 internal playable slice.

Where authority lives
---------------------
Every value a player could benefit from mis-stating is produced here and nowhere else:
the pocket, whether a bet won, the payout, and the resulting balance. The client sends
an intent (``place this bet``, ``spin``) and renders whatever comes back. A request that
carries a result, a payout or a balance is refused rather than ignored, because a field
that is silently dropped is a field a future refactor might start honouring.

Why the ledger posts once per round
-----------------------------------
``DurableRoundStore.submit_round`` commits the draw record, the settlement and the audit
events in one transaction. That is the only durable write path this slice is allowed to
use -- adding a second one would mean adding a table to R2's approved schema -- so the
whole round settles as a single ``ROUND_SETTLEMENT``. The escrow round-trip declared by
``games/roulette/economy-model.yaml`` is preserved inside that transaction's entries
rather than split across two commits: stake leaves the player into ``BET_ESCROW``, escrow
empties, and the difference settles against the house bankroll.

Because chips are therefore not debited when a bet is *placed*, an unspun round would let
a player commit more than they hold. :attr:`_reserved_units` closes that: an open stake is
reserved against the balance at validation time, so the settlement can never be the first
moment an overdraw is discovered. The house side is checked the same way, against the
worst pocket rather than the expected one, which is what
``exposure.accept_bet_only_when_reserved_house_bankroll_covers_max_liability`` asks for.

What a restart keeps
--------------------
Committed rounds. Balances, draw records, settlements and the audit chain are all read
back from the database, so the recent-result list after a restart is the stored commit
order and not a client-supplied history. An *open* round's bets are deliberately not
durable: nothing has been committed for them, no entropy has been spent, and restoring a
half-built betting board would mean inventing a durable representation of state that the
approved schema does not define. A restart therefore opens a fresh round, and the player
has lost nothing but their unsubmitted selections.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping

from studio_core.durable_state import (
    CommittedRound,
    DurableRoundStore,
    DurableStateError,
)
from studio_core.rng import DrawRecord, DrawRequest, RngDenied
from studio_core.roulette import load_r1_rules, settle_bet, validate_bet

__all__ = [
    "BET_FIELDS",
    "CLIENT_AUTHORITY_FIELDS",
    "COLOR_LABELS",
    "ESCROW_ACCOUNT",
    "HOUSE_ACCOUNT",
    "NOTICE",
    "PLAYER_ACCOUNT",
    "REQUEST_ID_PATTERN",
    "SCHEMA_VERSION",
    "TERMINAL_PHASES",
    "TRANSITIONS",
    "RoundPhase",
    "RouletteTable",
    "TableConfig",
    "TableError",
    "default_database_path",
    "prohibited_client_fields",
]

SCHEMA_VERSION = "1.0.0"
TASK_ID = "R4-UI-0006"
TABLE_ID = "TBL-ROULETTE-LOCAL-1"

#: Restated on every screen and in every API response. ``AC-009`` requires the internal,
#: virtual-chip, no-cash-value framing to be impossible to miss, and requires that nothing
#: here hints at a purchase, exchange or launch path -- so this is the whole of it.
NOTICE: dict[str, str] = {
    "scope": "INTERNAL_PROTOTYPE",
    "currency": "VIRTUAL_CHIP",
    "cash_value": "NONE",
    "text_en": "Internal prototype. Virtual chips only. No cash value.",
    "text_ko": "내부 프로토타입입니다. 가상 칩만 사용하며 현금 가치가 없습니다.",
}

#: Which pockets are red is a rule -- ``games/roulette/table-rules.yaml`` owns
#: ``red_numbers`` -- and the *name* of a colour is presentation. Both are published by the
#: server, in the same payload as the pocket itself, so the client never has to decide that
#: 32 is red. A client that classified pockets would hold a second, unversioned copy of a
#: rule, and the first thing to notice a disagreement would be a player.
COLOR_LABELS: dict[str, str] = {"red": "빨강", "black": "검정", "green": "초록"}

PLAYER_ACCOUNT = "player:local"
HOUSE_ACCOUNT = "house:bankroll"
ESCROW_ACCOUNT = "escrow:table"

#: The only keys a client may put in a bet. Anything else is refused, so a request cannot
#: smuggle a payout or a win flag past the parser by naming it plausibly.
BET_FIELDS = frozenset({"type", "selections", "stake_units"})

#: Names that only the server may produce. A request containing any of them is rejected
#: outright rather than sanitised: a client that sends one has a bug or an intent, and
#: both are better surfaced than absorbed.
CLIENT_AUTHORITY_FIELDS = frozenset(
    {
        "balance_units",
        "color",
        "color_label",
        "house_bankroll_units",
        "net_change_units",
        "payout_units",
        "pocket",
        "pocket_label",
        "proof_hash",
        "recent_results",
        "result",
        "total_return_units",
        "won",
    }
)

#: ``request_id`` is the idempotency boundary of the whole API, and for a spin it becomes
#: the ``DrawRequest.request_id`` verbatim, so it is held to exactly the shape
#: ``studio_core.rng`` accepts. Validating it here rather than at the draw means a bad
#: identifier is a 400 before any state moves.
REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$"

_REQUEST_ID_MAX = 64
_MAX_BETS_PER_ROUND = 100


class RoundPhase(str, Enum):
    """The states of ``games/roulette/round-state.yaml``, spelled exactly as declared."""

    OPEN = "OPEN"
    LOCKED = "LOCKED"
    SPINNING = "SPINNING"
    SETTLING = "SETTLING"
    SETTLED = "SETTLED"
    VOIDED = "VOIDED"


#: Transcribed from ``games/roulette/round-state.yaml``. Kept as data so the contract file
#: and the implementation can be compared by a test instead of by a reviewer's memory.
TRANSITIONS: tuple[tuple[RoundPhase, RoundPhase], ...] = (
    (RoundPhase.OPEN, RoundPhase.LOCKED),
    (RoundPhase.LOCKED, RoundPhase.SPINNING),
    (RoundPhase.SPINNING, RoundPhase.SETTLING),
    (RoundPhase.SETTLING, RoundPhase.SETTLED),
    (RoundPhase.OPEN, RoundPhase.VOIDED),
    (RoundPhase.LOCKED, RoundPhase.VOIDED),
    (RoundPhase.SPINNING, RoundPhase.VOIDED),
)

TERMINAL_PHASES: frozenset[RoundPhase] = frozenset({RoundPhase.SETTLED, RoundPhase.VOIDED})

#: Guards restated from the same contract file.
BETS_ACCEPTED_IN = RoundPhase.OPEN
RESULT_GENERATED_IN = RoundPhase.SPINNING
SETTLEMENT_POSTED_IN = RoundPhase.SETTLING


class TableError(Exception):
    """A refusal carrying a stable policy code and a message safe to show a player.

    Messages are written for the person at the keyboard. They never carry a stack trace,
    a filesystem path or a database detail, because :class:`TableError` is the only thing
    the HTTP layer is allowed to turn into a response body.
    """

    def __init__(self, code: str, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def default_database_path() -> str:
    """Return the runtime database location, which is deliberately outside the repository.

    An authoritative SQLite file inside a working tree is one ``git add -A`` away from
    being committed, and a prototype's balances are not repository content. The default
    therefore lives under the platform temporary directory; ``ROULETTE_WEB_DB`` overrides
    it so a test can point at its own directory without touching the code.
    """

    override = os.environ.get("ROULETTE_WEB_DB")
    if override:
        return override
    import tempfile

    return os.path.join(tempfile.gettempdir(), "ts-studio-roulette-web", "roulette-web.sqlite3")


def prohibited_client_fields(payload: Any) -> list[str]:
    """Return every server-authoritative key found anywhere inside ``payload``."""

    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            found.update(key for key in value if isinstance(key, str) and key in CLIENT_AUTHORITY_FIELDS)
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return sorted(found)


def _validate_request_id(request_id: Any) -> str:
    import re

    if not isinstance(request_id, str) or re.fullmatch(REQUEST_ID_PATTERN, request_id) is None:
        raise TableError(
            "REQUEST_ID_INVALID",
            f"request_id must be 8..{_REQUEST_ID_MAX} characters of letters, digits, '.', '_', ':' or '-'",
        )
    return request_id


# ---------------------------------------------------------------------------------------
# configuration and round state
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TableConfig:
    """Opening conditions for the internal table.

    The chip figures are demonstration values inside the range
    ``games/roulette/economy-model.yaml`` allows. There is no path that increases them at
    runtime: the slice has no purchase, no top-up and no exchange of any kind.
    """

    opening_player_units: int = 10_000
    opening_house_units: int = 1_000_000
    recent_results_limit: int = 12

    def __post_init__(self) -> None:
        for name in ("opening_player_units", "opening_house_units", "recent_results_limit"):
            value = getattr(self, name)
            if not _is_integer(value) or value < 0:
                raise TableError("CONFIG_INVALID", f"{name} must be a non-negative integer")


@dataclass
class _Round:
    round_id: str
    sequence: int
    phase: RoundPhase = RoundPhase.OPEN
    bets: list[dict[str, Any]] = field(default_factory=list)
    opened_at: str = field(default_factory=_utc_now_iso)
    history: list[dict[str, str]] = field(default_factory=list)
    result: dict[str, Any] | None = None

    @property
    def total_stake_units(self) -> int:
        return sum(int(bet["stake_units"]) for bet in self.bets)


# ---------------------------------------------------------------------------------------
# the table
# ---------------------------------------------------------------------------------------


class RouletteTable:
    """One local table: one player, one open round at a time, server-owned outcomes."""

    def __init__(
        self,
        store: DurableRoundStore,
        *,
        config: TableConfig | None = None,
        rules: Mapping[str, Any] | None = None,
        clock: Callable[[], str] | None = None,
        instance_token: str | None = None,
    ) -> None:
        self._store = store
        self._config = config or TableConfig()
        self._rules = dict(rules) if rules is not None else load_r1_rules()
        self._clock = clock if clock is not None else _utc_now_iso
        self._lock = threading.RLock()

        # Round and transaction identifiers must stay unique across restarts against a
        # database that already holds committed rounds. A per-instance token is cheaper and
        # more reliable than trying to infer the next free number from stored rows, and it
        # keeps the identifier meaningful to a human reading an audit trail.
        self._token = (instance_token or secrets.token_hex(4)).upper()
        if not self._token.isalnum():
            raise TableError("CONFIG_INVALID", "the instance token must be alphanumeric")

        #: request_id -> (fingerprint, response). The API-level idempotency journal. Durable
        #: idempotency for a *drawn* round is the store's job and survives a restart; this
        #: covers the requests that commit nothing, and gives a concurrent duplicate an
        #: answer without a second trip through validation.
        self._journal: dict[str, tuple[str, dict[str, Any]]] = {}
        self._sequence = 0
        self._reserved_units = 0
        self._recent: list[dict[str, Any]] = []

        self._open_accounts()
        self.reload_history()
        self._round = self._new_round_locked()

    # -- construction -------------------------------------------------------------------

    def _open_accounts(self) -> None:
        """Register the three accounts, tolerating a database that already holds them.

        ``register_account`` is a no-op when the type and opening balance match and a
        refusal when they do not. Re-opening an existing table therefore keeps the
        committed balance instead of resetting it, which is the behaviour a restart test
        depends on; only the very first run actually issues the opening chips.
        """

        existing = self._store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT, ESCROW_ACCOUNT])
        if PLAYER_ACCOUNT not in existing:
            self._store.register_account(PLAYER_ACCOUNT, "PLAYER", self._config.opening_player_units)
        if HOUSE_ACCOUNT not in existing:
            self._store.register_account(HOUSE_ACCOUNT, "HOUSE_BANKROLL", self._config.opening_house_units)
        if ESCROW_ACCOUNT not in existing:
            self._store.register_account(ESCROW_ACCOUNT, "BET_ESCROW", 0)

    def reload_history(self) -> list[dict[str, Any]]:
        """Rebuild the recent-result list from committed storage, in commit order.

        The audit chain is walked rather than the draw table because the chain *is* the
        commit order: ``event_seq`` is assigned inside the same transaction as the record
        it authorises. Each draw event names its request, and the request is then resolved
        through the store's public reader, so nothing here depends on the shape of a table
        this module does not own.
        """

        history: list[dict[str, Any]] = []
        for event in self._store.audit_events():
            if event.get("action") != "ROULETTE_RNG_DRAW":
                continue
            request_id = _reference_value(event.get("resource_refs", []), "rng-request://")
            if request_id is None:
                continue
            record = self._store.draw_record(request_id)
            if record is None:
                continue
            history.append(self._result_summary(record))
        with self._lock:
            self._recent = history
        return history

    # -- reads --------------------------------------------------------------------------

    @property
    def rules(self) -> dict[str, Any]:
        return dict(self._rules)

    def state(self) -> dict[str, Any]:
        with self._lock:
            return self._snapshot()

    # -- commands -----------------------------------------------------------------------

    def place_bet(self, request_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and record one bet on the open round. Commits nothing."""

        request_id = _validate_request_id(request_id)
        bet = self._parse_bet(payload)
        with self._lock:
            replay = self._replay_journal(request_id, "bets", bet)
            if replay is not None:
                return replay
            self._require_phase(BETS_ACCEPTED_IN, "bets are accepted only while the round is OPEN")
            if len(self._round.bets) >= _MAX_BETS_PER_ROUND:
                raise TableError(
                    "BET_LIMIT_REACHED", f"a round accepts at most {_MAX_BETS_PER_ROUND} bets"
                )

            # Rules first, then affordability. Order matters for the acceptance criterion
            # that a rejected bet leaves balance and phase untouched: nothing below this
            # point mutates state until every check has passed.
            try:
                validate_bet(dict(bet), self._rules)
            except ValueError as exc:
                raise TableError("BET_INVALID", str(exc)) from None

            stake = int(bet["stake_units"])
            available = self._available_units()
            if stake > available:
                raise TableError(
                    "INSUFFICIENT_CHIPS",
                    f"this bet stakes {stake} chips but only {available} are unreserved",
                )
            self._require_house_covers(self._round.bets + [bet])

            self._round.bets.append(bet)
            self._reserved_units += stake
            response = {"accepted": True, "bet_index": len(self._round.bets) - 1, "state": self._snapshot()}
            return self._record_journal(request_id, "bets", bet, response)

    def spin(self, request_id: str) -> dict[str, Any]:
        """Lock, draw, settle and commit the open round as one durable transaction."""

        request_id = _validate_request_id(request_id)
        with self._lock:
            replay = self._replay_journal(request_id, "spin", {})
            if replay is not None:
                return replay
            self._require_phase(BETS_ACCEPTED_IN, "only an OPEN round can be spun")
            if not self._round.bets:
                raise TableError("NO_BETS", "place at least one bet before spinning")

            current = self._round
            self._transition(RoundPhase.LOCKED)
            self._transition(RoundPhase.SPINNING)

            settled: dict[str, Any] = {}

            def build_settlement(record: DrawRecord) -> dict[str, Any]:
                # Reached only for a genuinely new draw: a replayed submission returns from
                # the store before any settlement factory runs. The phase moves here because
                # this is the exact moment the ledger body is produced, which is what
                # ``ledger_settlement_only_in: SETTLING`` is about.
                self._transition(RoundPhase.SETTLING)
                settled.update(self._settle_round(current, record.pocket))
                return settled["transaction"]

            try:
                committed = self._store.submit_round(
                    DrawRequest(request_id=request_id, round_id=current.round_id),
                    settlement=build_settlement,
                )
            except RngDenied as denied:
                self._fail_round(current)
                raise TableError("DRAW_DENIED", _safe_reason(denied.code), status=409) from None
            except DurableStateError as denied:
                self._fail_round(current)
                raise TableError("COMMIT_DENIED", _safe_reason(denied.code), status=409) from None

            if not settled:
                # The store served this ``request_id`` from a previous process. The current
                # round was never drawn, so it is failed closed rather than credited with a
                # result that belongs to a round the player never played.
                self._fail_round(current)
                raise TableError(
                    "REQUEST_ID_ALREADY_USED",
                    "this request identifier was already used for a committed round",
                    status=409,
                )

            current.result = self._result_payload(committed, settled)
            self._transition(RoundPhase.SETTLED)
            self._reserved_units = 0
            self._recent.append(self._result_summary(committed.record))
            response = {"accepted": True, "result": current.result, "state": self._snapshot()}
            return self._record_journal(request_id, "spin", {}, response)

    def new_round(self, request_id: str) -> dict[str, Any]:
        """Open a fresh round once the current one has reached a terminal state."""

        request_id = _validate_request_id(request_id)
        with self._lock:
            replay = self._replay_journal(request_id, "new-round", {})
            if replay is not None:
                return replay
            if self._round.phase not in TERMINAL_PHASES:
                raise TableError(
                    "ROUND_IN_PROGRESS",
                    f"the round is {self._round.phase.value}; it must reach a terminal state first",
                    status=409,
                )
            self._round = self._new_round_locked()
            response = {"accepted": True, "state": self._snapshot()}
            return self._record_journal(request_id, "new-round", {}, response)

    # -- idempotency --------------------------------------------------------------------

    def _replay_journal(self, request_id: str, route: str, payload: Any) -> dict[str, Any] | None:
        """Return the original response for a repeated request, or refuse a reused key.

        A duplicate that matches replays. A duplicate that does not match fails closed:
        handing back an unrelated earlier response would tell the caller its *new* request
        succeeded when nothing of the kind happened.
        """

        entry = self._journal.get(request_id)
        if entry is None:
            return None
        fingerprint, response = entry
        if fingerprint != _fingerprint({"route": route, "payload": payload}):
            raise TableError(
                "REQUEST_ID_CONFLICT",
                "this request identifier was already used with different parameters",
                status=409,
            )
        replayed = json.loads(json.dumps(response))
        replayed["replayed"] = True
        replayed["state"] = self._snapshot()
        return replayed

    def _record_journal(
        self, request_id: str, route: str, payload: Any, response: dict[str, Any]
    ) -> dict[str, Any]:
        self._journal[request_id] = (_fingerprint({"route": route, "payload": payload}), response)
        result = dict(response)
        result["replayed"] = False
        return result

    # -- round lifecycle ----------------------------------------------------------------

    def _new_round_locked(self) -> _Round:
        self._sequence += 1
        self._reserved_units = 0
        return _Round(
            round_id=f"RR-WEB-{self._token}-{self._sequence:04d}",
            sequence=self._sequence,
            opened_at=self._clock(),
        )

    def _transition(self, target: RoundPhase) -> None:
        current = self._round.phase
        if current in TERMINAL_PHASES:
            raise TableError(
                "TERMINAL_STATE",
                f"a {current.value} round cannot change state",
                status=409,
            )
        if (current, target) not in TRANSITIONS:
            raise TableError(
                "TRANSITION_DENIED",
                f"{current.value} to {target.value} is not a declared transition",
                status=409,
            )
        self._round.phase = target
        self._round.history.append({"from": current.value, "to": target.value, "at": self._clock()})

    def _fail_round(self, current: _Round) -> None:
        """Void a round whose commit did not happen, without masking the original refusal."""

        try:
            if current.phase not in TERMINAL_PHASES:
                self._transition(RoundPhase.VOIDED)
        except TableError:
            current.phase = RoundPhase.VOIDED
        self._reserved_units = 0

    def _require_phase(self, expected: RoundPhase, message: str) -> None:
        if self._round.phase is not expected:
            raise TableError("PHASE_DENIED", f"{message} (round is {self._round.phase.value})", status=409)

    # -- bets ---------------------------------------------------------------------------

    def _parse_bet(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Shape-check a bet before the rules engine sees it.

        ``validate_bet`` owns what a *legal* bet is. This owns what a legal *request* is,
        which is a different question: an unknown key or a float stake is a protocol fault
        and is refused here so the rules engine is never asked about it.
        """

        if not isinstance(payload, Mapping):
            raise TableError("BET_INVALID", "a bet must be a JSON object")
        unexpected = sorted(set(payload) - BET_FIELDS)
        if unexpected:
            raise TableError("BET_INVALID", f"unexpected bet fields: {', '.join(unexpected)}")
        missing = sorted(BET_FIELDS - set(payload) - {"selections"})
        if missing:
            raise TableError("BET_INVALID", f"the bet is missing: {', '.join(missing)}")

        stake = payload["stake_units"]
        if not _is_integer(stake):
            raise TableError("BET_INVALID", "stake_units must be an integer chip count")
        selections = payload.get("selections", [])
        if not isinstance(selections, list) or any(not _is_integer(item) for item in selections):
            raise TableError("BET_INVALID", "selections must be a list of integers")
        if not isinstance(payload["type"], str):
            raise TableError("BET_INVALID", "type must be a string")
        return {"type": payload["type"], "selections": list(selections), "stake_units": int(stake)}

    def _available_units(self) -> int:
        balance = self._store.balances([PLAYER_ACCOUNT]).get(PLAYER_ACCOUNT, 0)
        return int(balance) - self._reserved_units

    def _max_liability_units(self, bets: list[dict[str, Any]]) -> int:
        """Return the worst-case total return over all 37 pockets for ``bets``.

        Expected value is the wrong measure for an exposure check: the house has to be able
        to pay the pocket that actually lands, not the average one. Thirty-seven pockets is
        a small enough space to evaluate exactly, so it is evaluated exactly.
        """

        worst = 0
        for pocket in self._rules["table"]["pockets"]:
            total = 0
            for bet in bets:
                total += int(settle_bet(dict(bet), int(pocket), self._rules)["total_return_units"])
            worst = max(worst, total)
        return worst

    def _require_house_covers(self, bets: list[dict[str, Any]]) -> None:
        stake = sum(int(bet["stake_units"]) for bet in bets)
        liability = self._max_liability_units(bets)
        house = int(self._store.balances([HOUSE_ACCOUNT]).get(HOUSE_ACCOUNT, 0))
        # The stake is inside the escrow leg of the same transaction, so the bankroll only
        # has to cover what it would owe beyond the stake it collects.
        if liability - stake > house:
            raise TableError(
                "HOUSE_EXPOSURE_EXCEEDED",
                "the table bankroll does not cover the maximum liability of this bet",
                status=409,
            )

    # -- settlement ---------------------------------------------------------------------

    def _settle_round(self, current: _Round, pocket: int) -> dict[str, Any]:
        """Compute per-bet outcomes and the balanced ledger transaction for one pocket."""

        outcomes: list[dict[str, Any]] = []
        total_stake = 0
        total_return = 0
        for index, bet in enumerate(current.bets):
            outcome = settle_bet(dict(bet), int(pocket), self._rules)
            stake = int(bet["stake_units"])
            total_stake += stake
            total_return += int(outcome["total_return_units"])
            outcomes.append(
                {
                    "bet_index": index,
                    "type": bet["type"],
                    "selections": list(bet["selections"]),
                    "stake_units": stake,
                    "won": bool(outcome["won"]),
                    "payout_units": int(outcome["total_return_units"]),
                    "net_change_units": int(outcome["net_change_units"]),
                }
            )

        entries = [
            {"account_id": PLAYER_ACCOUNT, "account_type": "PLAYER", "amount_units": -total_stake},
            {"account_id": ESCROW_ACCOUNT, "account_type": "BET_ESCROW", "amount_units": total_stake},
            {"account_id": ESCROW_ACCOUNT, "account_type": "BET_ESCROW", "amount_units": -total_stake},
        ]
        if total_return:
            entries.append(
                {"account_id": PLAYER_ACCOUNT, "account_type": "PLAYER", "amount_units": total_return}
            )
        if total_stake != total_return:
            entries.append(
                {
                    "account_id": HOUSE_ACCOUNT,
                    "account_type": "HOUSE_BANKROLL",
                    "amount_units": total_stake - total_return,
                }
            )

        transaction = {
            "schema_version": SCHEMA_VERSION,
            "transaction_id": f"LT-WEB-{self._token}-{current.sequence:04d}",
            "idempotency_key": f"idem:{current.round_id}:settlement",
            "round_id": current.round_id,
            "transaction_type": "ROUND_SETTLEMENT",
            "currency": "VIRTUAL_CHIP",
            "entries": entries,
            "created_at": self._clock(),
            "request_hash": _fingerprint(
                {"bets": current.bets, "round_id": current.round_id, "pocket": int(pocket)}
            ),
        }
        return {
            "transaction": transaction,
            "outcomes": outcomes,
            "total_stake_units": total_stake,
            "total_return_units": total_return,
            "net_change_units": total_return - total_stake,
        }

    def _result_payload(self, committed: CommittedRound, settled: Mapping[str, Any]) -> dict[str, Any]:
        record = committed.record
        return {
            "round_id": record.round_id,
            "pocket": int(record.pocket),
            "color": self._color_of(int(record.pocket)),
            "outcomes": settled["outcomes"],
            "total_stake_units": int(settled["total_stake_units"]),
            "total_return_units": int(settled["total_return_units"]),
            "net_change_units": int(settled["net_change_units"]),
            "settlement_transaction_id": committed.settlement_transaction_id,
            "proof_hash": record.proof_hash,
            "audit_event_refs": list(committed.audit_event_refs),
            "settled_at": record.created_at,
        }

    def _result_summary(self, record: DrawRecord) -> dict[str, Any]:
        return {
            "round_id": record.round_id,
            "pocket": int(record.pocket),
            "color": self._color_of(int(record.pocket)),
            "settled_at": record.created_at,
        }

    def _color_of(self, pocket: int) -> str:
        if pocket == 0:
            return "green"
        return "red" if pocket in self._rules["table"]["red_numbers"] else "black"

    # -- snapshot -----------------------------------------------------------------------

    def _snapshot(self) -> dict[str, Any]:
        """Return everything the client is allowed to render, and nothing it may compute."""

        balances = self._store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT, ESCROW_ACCOUNT])
        balance = int(balances.get(PLAYER_ACCOUNT, 0))
        limits = self._rules.get("limits", {})
        recent = self._recent[-self._config.recent_results_limit :]
        return {
            "schema_version": SCHEMA_VERSION,
            "task_id": TASK_ID,
            "table_id": TABLE_ID,
            "notice": dict(NOTICE),
            "currency": "VIRTUAL_CHIP",
            "balance_units": balance,
            "reserved_units": self._reserved_units,
            "available_units": balance - self._reserved_units,
            "house_bankroll_units": int(balances.get(HOUSE_ACCOUNT, 0)),
            "round": {
                "round_id": self._round.round_id,
                "sequence": self._round.sequence,
                "phase": self._round.phase.value,
                "is_terminal": self._round.phase in TERMINAL_PHASES,
                "accepts_bets": self._round.phase is BETS_ACCEPTED_IN,
                "opened_at": self._round.opened_at,
                "bets": [dict(bet) for bet in self._round.bets],
                "bet_count": len(self._round.bets),
                "total_stake_units": self._round.total_stake_units,
                "transitions": list(self._round.history),
                "result": self._round.result,
            },
            "limits": {
                "min_stake_units": int(limits.get("min_stake_units", 1)),
                "max_stake_units": int(limits.get("max_stake_units", 100000)),
                "max_bets_per_round": _MAX_BETS_PER_ROUND,
            },
            "table": {
                "pockets": list(self._rules["table"]["pockets"]),
                "red_numbers": list(self._rules["table"]["red_numbers"]),
                # The classification itself, not just the rule it comes from. ``red_numbers``
                # is published because it is part of the rules snapshot, but a client that
                # read it would have to re-derive "32 is red" -- a second, unversioned copy
                # of a rule. ``_color_of`` is the same function that colours a drawn pocket,
                # so the board, the wheel and the result can never disagree. Keys are strings
                # because JSON object keys are.
                "pocket_colors": {
                    str(int(pocket)): self._color_of(int(pocket))
                    for pocket in self._rules["table"]["pockets"]
                },
                "payouts": dict(self._rules["payouts"]),
                "bet_selection_counts": dict(self._rules["bet_selection_counts"]),
            },
            "recent_results": recent,
        }


def _reference_value(references: Any, prefix: str) -> str | None:
    if not isinstance(references, list):
        return None
    for reference in references:
        if isinstance(reference, str) and reference.startswith(prefix):
            return reference[len(prefix) :]
    return None


def _safe_reason(code: str) -> str:
    """Return a player-facing reason for a boundary refusal, carrying the code only."""

    return f"the round was refused by the authoritative boundary ({code})"
