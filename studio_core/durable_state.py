"""R2-DBC-0002: durable-state reference boundary for authoritative roulette state.

Scope and non-scope
-------------------
``studio_core.rng`` owns the entropy path and keeps its state in process memory: its lock
stops two threads racing inside one process, but a restart forgets every ``request_id`` and
its ``AuditChain`` sequence restarts at 1 for every engine instance. This module closes that
gap with the Python standard library ``sqlite3`` only. No external database server, no
network client, no production deployment: it is the executable definition of *what the
storage layer must guarantee*, so a later production store has a testable target rather than
a paragraph of prose.

It does not weaken anything ``rng.py`` declares. The draw itself still runs through
:class:`~studio_core.rng.RouletteDrawEngine` behind the published
:class:`~studio_core.rng.EntropySource` and ``AuditSink`` protocols, and every refusal is
still an :class:`~studio_core.rng.RngDenied` carrying the failure action from
``games/roulette/rng-contract.yaml``. The balance arithmetic still runs through
:func:`studio_core.ledger.post_transaction`, so the R1 invariants (integer units, entries
summing to zero, no negative player balance) hold here by reuse rather than by re-statement.

The database is the system of record
------------------------------------
A :class:`RouletteDrawEngine` instance is created *per submission attempt* and discarded.
That is deliberate. If the engine kept state across attempts, a rolled-back transaction would
leave the engine believing a round was drawn while the database says it was not, and the two
answers to "was this round drawn?" would diverge exactly when it matters. Every authoritative
question -- has this ``request_id`` been served, does this round already have a draw, is this
round voided -- is answered from committed rows.

Isolation, transaction mode and concurrency
-------------------------------------------
SQLite offers serializable isolation; the risk is not weak isolation but a deferred
transaction that starts reading, then discovers it cannot upgrade to a writer and fails with
``SQLITE_BUSY`` after it has already made decisions. Every authoritative path therefore opens
``BEGIN IMMEDIATE``: the write lock is taken *before* the duplicate check reads anything, so
the check-and-act is atomic against every other connection and process. Two callers
submitting the same ``request_id`` from different threads and different connections are
serialised by that lock; the loser re-reads inside its own transaction, finds the committed
record, and returns it without consuming entropy again.

``PRAGMA busy_timeout`` makes a blocked writer wait rather than fail, and
:data:`MAX_BUSY_RETRIES` bounded retries cover the window where SQLite reports busy before
the timeout applies. Retries only ever re-run the ``BEGIN``; a transaction that has begun is
never retried blindly, because a retry of partially applied authoritative work is how double
settlements happen.

Durability
----------
``journal_mode=WAL`` lets readers proceed while a writer holds the lock, which is what makes
the replay fast path usable without blocking settlement. ``synchronous=FULL`` is chosen over
the usual WAL companion ``NORMAL``: ``NORMAL`` can lose the most recent commits on power
loss, and "the round settled but the record is gone" is not an acceptable outcome for
authoritative money movement. ``foreign_keys=ON`` is per-connection in SQLite and is set on
every connection, so a ledger row can never reference a missing audit event.

What is never stored
--------------------
Entropy bytes, seed material, rejection counts, plaintext credentials, floating-point
currency, and client-authoritative state. The first four are refused before an INSERT by
:func:`_reject_unstorable`; integer currency is additionally enforced by ``typeof()`` CHECK
constraints so a float cannot enter even through raw SQL.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from .collaboration import scan_for_plaintext_secrets
from .ledger import post_transaction
from .rng import (
    PROHIBITED_RECORD_FIELDS,
    DrawRecord,
    DrawRequest,
    EntropySource,
    FailureAction,
    OsCsprngEntropySource,
    RngDenied,
    RngEnvironment,
    RouletteDrawEngine,
    compute_event_hash,
    verify_audit_chain,
    verify_draw_record,
)

__all__ = [
    "AUDIT_SEGMENT_SIZE",
    "BUSY_TIMEOUT_MS",
    "CommittedRound",
    "DURABLE_SCHEMA_VERSION",
    "DurableRoundStore",
    "DurableStateError",
    "FAILURE_BEHAVIOR",
    "FAULT_STAGES",
    "FOREIGN_KEYS",
    "ISOLATION_LEVEL",
    "JOURNAL_MODE",
    "LedgerConflict",
    "MAX_AUDIT_SEGMENT",
    "MAX_BUSY_RETRIES",
    "PATH_HANDLING",
    "POLICY_VERSION",
    "PROHIBITED_STORAGE_FIELDS",
    "RETRY_BACKOFF_SECONDS",
    "SCHEMA_STATEMENTS",
    "SUPPORTED_SCHEMA_VERSIONS",
    "SYNCHRONOUS",
    "SchemaVersionError",
    "TASK_ID",
    "TRANSACTION_MODE",
    "contract_declaration",
    "prohibited_fields",
    "resolve_database_path",
    "schema_sql",
]

#: Schema version this build creates and is willing to open. A database recording anything
#: else is refused rather than migrated downward.
DURABLE_SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS: tuple[int, ...] = (1,)

#: SQLite gives every transaction a serializable view; naming it here is what lets the
#: contract file state an isolation level that the implementation can actually be checked
#: against, rather than one that is merely asserted in prose.
ISOLATION_LEVEL = "SERIALIZABLE"
JOURNAL_MODE = "wal"
SYNCHRONOUS = "full"
FOREIGN_KEYS = True
TRANSACTION_MODE = "IMMEDIATE"
BUSY_TIMEOUT_MS = 5000
MAX_BUSY_RETRIES = 5
RETRY_BACKOFF_SECONDS = 0.02

TASK_ID = "R2-DBC-0002"
POLICY_VERSION = "DURABLE-STATE-R2/1.0.0"

#: One audit segment holds 9999 events because ``audit/audit-event.schema.json`` pins
#: ``event_id`` to four digits. The segment number keeps the identifier globally unique past
#: that boundary instead of failing closed at the first ten thousandth event, and the store
#: still fails closed once segments are exhausted rather than reusing an identifier.
AUDIT_SEGMENT_SIZE = 9999
MAX_AUDIT_SEGMENT = 99

#: Points at which :class:`DurableRoundStore` calls its fault hook. Tests inject failures here
#: to prove that the draw record, the settlement and the audit events share one commit.
FAULT_STAGES: tuple[str, ...] = (
    "after_begin",
    "after_draw",
    "after_ledger",
    "before_commit",
    "after_commit",
)

#: Path spellings the store refuses, and the properties a caller may rely on. Declared as
#: data because ``games/roulette/durable-state-contract.yaml`` has to restate them and the
#: baseline validator compares the two; a rule that lives only inside a function body could
#: drift away from the published contract without anything noticing.
PATH_HANDLING: dict[str, Any] = {
    "memory_database": "prohibited",
    "uri_filename": "prohibited",
    "connect_uri_parameter": False,
    "relative_path_resolution": "anchored_to_process_cwd",
    "parent_directory_must_exist": True,
    "symlink_resolution": "not_performed",
    "nul_byte_in_path": "prohibited",
    "directory_as_database": "prohibited",
}

#: Field names that may never reach a stored row. The first eight are exactly
#: ``studio_core.rng.PROHIBITED_RECORD_FIELDS`` -- reused rather than restated, so a future
#: addition there is automatically refused here -- and the rest name the client-authoritative
#: and credential-shaped values a storage layer is the wrong place to hold.
PROHIBITED_STORAGE_FIELDS: tuple[str, ...] = (
    *PROHIBITED_RECORD_FIELDS,
    "api_key",
    "client_balance",
    "client_result",
    "credential",
    "password",
    "secret",
    "token",
)

#: What the boundary does when a named condition occurs. Restated in the contract file and
#: cross-checked by ``scripts/validate_baseline.py::validate_r2_durable_state``.
FAILURE_BEHAVIOR: dict[str, str] = {
    "duplicate_request_same_payload": "RETURN_ORIGINAL_RESULT",
    "duplicate_request_different_payload": "DUPLICATE_REQUEST_CONFLICT",
    "duplicate_idempotency_key_different_payload": "IDEMPOTENCY_KEY_CONFLICT",
    "round_already_drawn": "ROUND_ALREADY_DRAWN",
    "round_voided": "ROUND_VOIDED",
    "fault_before_commit": "ROLLBACK_AND_VOID_ROUND",
    "write_lock_unavailable": "WRITE_LOCK_UNAVAILABLE",
    "unsupported_schema_version": "SCHEMA_VERSION_UNSUPPORTED",
    "entropy_or_secret_material_offered": "ENTROPY_MATERIAL_DENIED",
    "float_currency_offered": "FLOAT_VALUE_DENIED",
}

_TRANSACTION_TYPES = ("BET_RESERVE", "BET_CANCEL", "ROUND_SETTLEMENT", "ROUND_VOID")
_ACCOUNT_TYPES = ("PLAYER", "BET_ESCROW", "HOUSE_BANKROLL", "SYSTEM_CLEARING")

_NAMESPACE_PATTERN = re.compile(r"^[A-Z0-9]{1,6}$")
_TRANSACTION_ID_PATTERN = re.compile(r"^LT-[A-Z0-9-]{1,60}$")
_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^idem:[a-zA-Z0-9:_-]{1,120}$")
_ROUND_ID_PATTERN = re.compile(r"^RR-[A-Z0-9-]{1,48}$")
_ACCOUNT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]{1,15}:[A-Za-z0-9._:-]{1,48}$")
_SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_VOID_REASON_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,39}$")

#: Every column of a ledger transaction as ``games/roulette/ledger-transaction.schema.json``
#: declares it. Anything else is refused, mirroring the schema's ``additionalProperties:
#: false`` so that an unknown field cannot smuggle client-authoritative state into storage.
_TRANSACTION_FIELDS = (
    "schema_version",
    "transaction_id",
    "idempotency_key",
    "round_id",
    "transaction_type",
    "currency",
    "entries",
    "created_at",
    "request_hash",
    "audit_event_ref",
)

_ENTRY_FIELDS = ("account_id", "account_type", "amount_units")

#: Tables this module owns. Used to tell an empty file apart from a database written by
#: something else that happens to report ``user_version = 0``.
_OWNED_TABLES = frozenset(
    {"schema_meta", "audit_event", "account", "ledger_transaction", "ledger_entry", "draw_record", "round_void"}
)


class DurableStateError(RuntimeError):
    """A durable-state operation was refused. Messages carry policy context only."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class SchemaVersionError(DurableStateError):
    """The database on disk is not at a schema version this build may open."""


class LedgerConflict(DurableStateError):
    """An idempotency key was reused with a different payload; the store fails closed."""


# ---------------------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------------------

#: DDL for :data:`DURABLE_SCHEMA_VERSION`, one statement per element.
#:
#: The statements are kept as separate strings rather than one script because
#: ``sqlite3.Connection.executescript`` issues an implicit COMMIT before it runs, which would
#: take the schema creation outside the transaction that guards it. Executed one at a time
#: inside ``BEGIN IMMEDIATE``, SQLite's transactional DDL makes a half-created schema
#: impossible.
SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
""".strip(),
    """
CREATE TABLE audit_event (
    event_seq           INTEGER PRIMARY KEY,
    event_id            TEXT NOT NULL UNIQUE,
    audit_ref           TEXT NOT NULL UNIQUE,
    event_hash          TEXT NOT NULL UNIQUE,
    previous_event_hash TEXT,
    action              TEXT NOT NULL,
    round_id            TEXT,
    recorded_at         TEXT NOT NULL,
    body_json           TEXT NOT NULL,
    CHECK (typeof(event_seq) = 'integer' AND event_seq > 0)
)
""".strip(),
    """
CREATE TRIGGER audit_event_is_append_only_update
BEFORE UPDATE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END
""".strip(),
    """
CREATE TRIGGER audit_event_is_append_only_delete
BEFORE DELETE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END
""".strip(),
    """
CREATE TABLE account (
    account_id    TEXT PRIMARY KEY,
    account_type  TEXT NOT NULL,
    balance_units INTEGER NOT NULL,
    CHECK (account_type IN ('PLAYER', 'BET_ESCROW', 'HOUSE_BANKROLL', 'SYSTEM_CLEARING')),
    CHECK (typeof(balance_units) = 'integer'),
    CHECK (account_type <> 'PLAYER' OR balance_units >= 0)
)
""".strip(),
    """
CREATE TABLE ledger_transaction (
    transaction_id      TEXT PRIMARY KEY,
    idempotency_key     TEXT NOT NULL UNIQUE,
    round_id            TEXT NOT NULL,
    transaction_type    TEXT NOT NULL,
    currency            TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    audit_event_seq     INTEGER NOT NULL REFERENCES audit_event(event_seq),
    payload_json        TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    CHECK (transaction_type IN ('BET_RESERVE', 'BET_CANCEL', 'ROUND_SETTLEMENT', 'ROUND_VOID')),
    CHECK (currency = 'VIRTUAL_CHIP')
)
""".strip(),
    """
CREATE TABLE ledger_entry (
    entry_seq      INTEGER PRIMARY KEY,
    transaction_id TEXT NOT NULL
                   REFERENCES ledger_transaction(transaction_id) DEFERRABLE INITIALLY DEFERRED,
    account_id     TEXT NOT NULL REFERENCES account(account_id),
    account_type   TEXT NOT NULL,
    amount_units   INTEGER NOT NULL,
    CHECK (account_type IN ('PLAYER', 'BET_ESCROW', 'HOUSE_BANKROLL', 'SYSTEM_CLEARING')),
    CHECK (typeof(amount_units) = 'integer' AND amount_units <> 0)
)
""".strip(),
    """
CREATE TRIGGER ledger_entry_precedes_its_transaction
BEFORE INSERT ON ledger_entry
BEGIN
    SELECT RAISE(ABORT, 'a settled ledger transaction cannot gain further entries')
    WHERE EXISTS (SELECT 1 FROM ledger_transaction WHERE transaction_id = NEW.transaction_id);
END
""".strip(),
    """
CREATE TRIGGER ledger_transaction_must_balance
AFTER INSERT ON ledger_transaction
BEGIN
    SELECT RAISE(ABORT, 'a ledger transaction requires at least two entries')
    WHERE (SELECT COUNT(*) FROM ledger_entry WHERE transaction_id = NEW.transaction_id) < 2;
    SELECT RAISE(ABORT, 'ledger entries must sum to zero')
    WHERE (SELECT SUM(amount_units) FROM ledger_entry WHERE transaction_id = NEW.transaction_id) <> 0;
END
""".strip(),
    """
CREATE TRIGGER ledger_transaction_is_immutable_update
BEFORE UPDATE ON ledger_transaction
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger transaction is immutable');
END
""".strip(),
    """
CREATE TRIGGER ledger_transaction_is_immutable_delete
BEFORE DELETE ON ledger_transaction
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger transaction is immutable');
END
""".strip(),
    """
CREATE TRIGGER ledger_entry_is_immutable_update
BEFORE UPDATE ON ledger_entry
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger entry is immutable');
END
""".strip(),
    """
CREATE TRIGGER ledger_entry_is_immutable_delete
BEFORE DELETE ON ledger_entry
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger entry is immutable');
END
""".strip(),
    """
CREATE TABLE draw_record (
    request_id                TEXT PRIMARY KEY,
    round_id                  TEXT NOT NULL UNIQUE,
    request_fingerprint       TEXT NOT NULL,
    pocket                    INTEGER NOT NULL,
    proof_hash                TEXT NOT NULL,
    audit_event_seq           INTEGER NOT NULL REFERENCES audit_event(event_seq),
    settlement_transaction_id TEXT REFERENCES ledger_transaction(transaction_id),
    payload_json              TEXT NOT NULL,
    created_at                TEXT NOT NULL,
    CHECK (typeof(pocket) = 'integer' AND pocket BETWEEN 0 AND 36)
)
""".strip(),
    """
CREATE TRIGGER draw_record_is_immutable
BEFORE UPDATE OF request_id, round_id, pocket, proof_hash, payload_json ON draw_record
BEGIN
    SELECT RAISE(ABORT, 'an authoritative draw record is immutable');
END
""".strip(),
    """
CREATE TABLE round_void (
    round_id        TEXT PRIMARY KEY,
    reason          TEXT NOT NULL,
    audit_event_seq INTEGER NOT NULL REFERENCES audit_event(event_seq),
    created_at      TEXT NOT NULL
)
""".strip(),
)

_SCHEMA_HEADER = f"""-- {TASK_ID} durable-state schema, version {DURABLE_SCHEMA_VERSION}.
--
-- Published form of studio_core.durable_state.SCHEMA_STATEMENTS. The baseline validator
-- rejects any drift between this file and the statements the implementation executes, so a
-- reviewer can read the storage contract without reading the module.
--
-- Isolation:    SQLite serializable; every authoritative write opens BEGIN {TRANSACTION_MODE}.
-- Journal mode: {JOURNAL_MODE.upper()}          Durability pragma: synchronous={SYNCHRONOUS.upper()}
-- Foreign keys: {'ON' if FOREIGN_KEYS else 'OFF'}           Busy timeout: {BUSY_TIMEOUT_MS} ms
--
-- Currency is integer minimum units only; typeof() CHECK constraints reject a float even
-- when it arrives through raw SQL. Entropy bytes and seed material are never columns here.
--
-- Write order for a settlement is entries first, then the ledger_transaction row. A CHECK
-- constraint can only see one row, so the zero-sum rule is enforced by a trigger that fires
-- once the transaction row arrives and can count and total its entries. The deferred foreign
-- key is what makes that order legal, and ledger_entry_precedes_its_transaction closes the
-- other end: once a transaction row exists, no entry may be added to unbalance it."""


def schema_sql() -> str:
    """Return the published SQL text for the current schema version."""

    body = ";\n\n".join(SCHEMA_STATEMENTS)
    return f"{_SCHEMA_HEADER}\n\n{body};\n"


def contract_declaration() -> dict[str, Any]:
    """Return the storage decisions ``games/roulette/durable-state-contract.yaml`` must state.

    ``AC-008`` requires the declared isolation level, transaction mode, retry policy, journal
    mode, durability pragma, foreign-key enforcement and schema version to match what the code
    actually does. Producing them from the module constants and comparing the result against
    the YAML in the baseline validator makes that a checked equality rather than a promise
    that a reviewer has to re-derive by reading both files.
    """

    return {
        "isolation_level": ISOLATION_LEVEL,
        "transaction_mode": TRANSACTION_MODE,
        "journal_mode": JOURNAL_MODE,
        "synchronous": SYNCHRONOUS,
        "foreign_keys": FOREIGN_KEYS,
        "busy_timeout_ms": BUSY_TIMEOUT_MS,
        "max_busy_retries": MAX_BUSY_RETRIES,
        "retry_backoff_seconds": RETRY_BACKOFF_SECONDS,
        "schema_version": DURABLE_SCHEMA_VERSION,
        "supported_schema_versions": list(SUPPORTED_SCHEMA_VERSIONS),
        "audit_segment_size": AUDIT_SEGMENT_SIZE,
        "max_audit_segment": MAX_AUDIT_SEGMENT,
        "policy_version": POLICY_VERSION,
        "task_id": TASK_ID,
    }


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _reject_unstorable(payload: Any, *, label: str) -> str:
    """Return the canonical JSON of ``payload`` after refusing anything unstorable.

    Three separate refusals, because they fail for three different reasons: an entropy or
    seed field would make the store a leak of the very material ``rng.py`` never records; a
    credential-shaped value would put a secret in a durable file; a float where currency
    belongs would make balances unrepeatable. All three are cheaper to refuse than to detect
    later in an audit.
    """

    serialized = _canonical(payload)
    leaking = prohibited_fields(payload)
    if leaking:
        raise DurableStateError("ENTROPY_MATERIAL_DENIED", f"{label} carries prohibited fields {leaking!r}")
    if scan_for_plaintext_secrets(serialized):
        raise DurableStateError("SECRET_MATERIAL_DENIED", f"{label} matched a plaintext credential rule")
    if _contains_float(payload):
        raise DurableStateError("FLOAT_VALUE_DENIED", f"{label} carries a floating-point value")
    return serialized


def prohibited_fields(payload: Any) -> list[str]:
    """Return the :data:`PROHIBITED_STORAGE_FIELDS` keys present anywhere inside ``payload``.

    Keys are matched, not the serialised text. A substring search over the JSON would report
    the audit event's ``rng-entropy://`` resource reference -- which names the entropy
    *authority* and is required by ``games/roulette/rng-contract.yaml`` -- as a leak of
    entropy material, and a check that cries wolf on a required field is a check that gets
    disabled. Matching keys says exactly what the criterion says: no such field is stored.
    """

    banned = set(PROHIBITED_STORAGE_FIELDS)
    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            found.update(key for key in value if isinstance(key, str) and key.lower() in banned)
            for item in value.values():
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)

    walk(payload)
    return sorted(found)


def _contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_contains_float(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_float(item) for item in value)
    return False


def resolve_database_path(path: str | os.PathLike[str]) -> Path:
    """Return the absolute file path a store may open, refusing unsafe spellings.

    ``sqlite3.connect`` accepts more than a filename: ``:memory:`` silently produces a
    private database that vanishes on close, and a ``file:`` URI can carry ``mode=`` or
    ``cache=shared`` parameters that change the durability and isolation this module
    documents. Both are refused here rather than in a code review, and connections are always
    opened with ``uri=False`` so a filename is only ever a filename.

    Symlinks are deliberately not resolved: the caller names the file it wants. The parent
    directory must already exist, so a typo creates an error instead of a database in an
    unexpected place.
    """

    if isinstance(path, Path):
        text = str(path)
    elif isinstance(path, str):
        text = path
    else:
        raise DurableStateError("PATH_INVALID", "a filesystem path is required")
    if not text.strip():
        raise DurableStateError("PATH_INVALID", "the database path is empty")
    if "\x00" in text:
        raise DurableStateError("PATH_INVALID", "the database path contains a NUL byte")
    if text == ":memory:" or text.startswith("file:"):
        raise DurableStateError(
            "PATH_INVALID", "an in-memory or URI database cannot hold authoritative state"
        )
    candidate = Path(os.path.normpath(str(Path(text).expanduser())))
    if not candidate.is_absolute():
        candidate = Path(os.path.normpath(str(Path.cwd() / candidate)))
    if candidate.is_dir():
        raise DurableStateError("PATH_INVALID", "the database path names a directory")
    if not candidate.parent.is_dir():
        raise DurableStateError("PATH_INVALID", "the parent directory of the database does not exist")
    return candidate


def _is_busy(exc: sqlite3.OperationalError) -> bool:
    return "locked" in str(exc).lower() or "busy" in str(exc).lower()


# ---------------------------------------------------------------------------------------
# audit sink
# ---------------------------------------------------------------------------------------


class _DurableAuditSink:
    """Append-only audit sink bound to one open transaction.

    It satisfies the ``AuditSink`` protocol ``rng.py`` declares, so the draw engine writes its
    event through the same call it would make to the in-memory chain. The difference is where
    the event lands: inside the caller's transaction, so an event and the result it authorises
    commit or roll back together, and with a sequence read from the database rather than from
    an instance counter, so two engines can never mint the same reference.
    """

    def __init__(self, connection: sqlite3.Connection, namespace: str, *, clock: Callable[[], str]) -> None:
        self._connection = connection
        self._namespace = namespace
        self._clock = clock
        self.appended: list[tuple[int, str]] = []

    def append(self, body: Mapping[str, Any]) -> str:
        head = self._connection.execute(
            "SELECT event_seq, event_hash FROM audit_event ORDER BY event_seq DESC LIMIT 1"
        ).fetchone()
        sequence = (head["event_seq"] if head is not None else 0) + 1
        segment, index = divmod(sequence - 1, AUDIT_SEGMENT_SIZE)
        if segment > MAX_AUDIT_SEGMENT:
            raise RngDenied(
                "AUDIT_SEQUENCE_EXHAUSTED",
                FailureAction.BLOCK_AND_VOID,
                "the durable audit segment space is full",
            )

        event = dict(body)
        if event.get("contains_secret") is not False:
            raise DurableStateError("AUDIT_EVENT_DENIED", "an audit event must declare contains_secret false")
        event["event_id"] = f"AE-{self._namespace}{segment:02d}-{index + 1:04d}"
        event["previous_event_hash"] = head["event_hash"] if head is not None else None
        event["event_hash"] = compute_event_hash(event)
        serialized = _reject_unstorable(event, label="an audit event")

        reference = f"audit://{event['event_id']}"
        self._connection.execute(
            "INSERT INTO audit_event (event_seq, event_id, audit_ref, event_hash, previous_event_hash,"
            " action, round_id, recorded_at, body_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                event["event_id"],
                reference,
                event["event_hash"],
                event["previous_event_hash"],
                str(event.get("action", "")),
                _round_id_of(event),
                self._clock(),
                serialized,
            ),
        )
        self.appended.append((sequence, reference))
        return reference


def _round_id_of(event: Mapping[str, Any]) -> str | None:
    for reference in event.get("resource_refs", []):
        if isinstance(reference, str) and reference.startswith("round://"):
            return reference.removeprefix("round://")
    return None


# ---------------------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CommittedRound:
    """The committed authoritative outcome of one round submission."""

    record: DrawRecord
    settlement_transaction_id: str | None
    balances: dict[str, int] = field(default_factory=dict)
    audit_event_refs: tuple[str, ...] = ()
    #: True when the result was read back from storage instead of newly drawn. A replay
    #: consumes no entropy and commits no second settlement.
    replayed: bool = False


# ---------------------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------------------


class DurableRoundStore:
    """Durable, transactional system of record for roulette draws, settlement and audit."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        namespace: str = "DBC",
        entropy_source: EntropySource | None = None,
        environment: RngEnvironment | str = RngEnvironment.PRODUCTION,
        clock: Callable[[], str] | None = None,
        busy_timeout_ms: int = BUSY_TIMEOUT_MS,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(namespace, str) or _NAMESPACE_PATTERN.fullmatch(namespace) is None:
            raise DurableStateError("NAMESPACE_INVALID", "the audit namespace must be 1..6 of [A-Z0-9]")
        if not _is_integer(busy_timeout_ms) or busy_timeout_ms <= 0:
            raise DurableStateError("BUSY_TIMEOUT_INVALID", "the busy timeout must be a positive integer")
        if fault_hook is not None and not callable(fault_hook):
            raise DurableStateError("FAULT_HOOK_INVALID", "the fault hook must be callable")

        self._path = resolve_database_path(path)
        self._namespace = namespace
        self._environment = environment
        self._entropy = OsCsprngEntropySource() if entropy_source is None else entropy_source
        self._clock = clock if clock is not None else _utc_now_iso
        self._busy_timeout_ms = busy_timeout_ms
        self._fault_hook = fault_hook
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        self._connection_lock = threading.Lock()
        self._closed = False

        # Building an engine here would be too late to be useful, but validating the entropy
        # source is not: a deterministic adapter paired with PRODUCTION must be refused when
        # the store is opened, not on the first draw.
        #
        # Both steps below can refuse the store, and a refusal that left the connection open
        # would be worse than the refusal: on Windows an open handle keeps the database file
        # locked, so a caller's temporary directory stays undeletable long after the object it
        # belonged to was discarded. A constructor that fails must leave nothing behind.
        try:
            RouletteDrawEngine(
                entropy_source=self._entropy,
                environment=self._environment,
                audit_sink=_NullAuditSink(),
                clock=self._clock,
            )
            self._prepare()
        except BaseException:
            self.close()
            raise

    # -- lifecycle ----------------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    @property
    def schema_version(self) -> int:
        return int(self._connection().execute("PRAGMA user_version").fetchone()[0])

    def release_thread_connection(self) -> None:
        """Close and forget the connection owned by the calling thread.

        ``sqlite3`` binds a connection to the thread that opened it, so :meth:`close` cannot
        shut a worker's connection down from the outside. A worker that finishes with the
        store calls this in a ``finally`` block; without it the handle survives until garbage
        collection, which on Windows is long enough to keep the database file locked and make
        a caller's temporary directory undeletable.
        """

        connection = getattr(self._local, "connection", None)
        if connection is None:
            return
        self._local.connection = None
        with self._connection_lock:
            if connection in self._connections:
                self._connections.remove(connection)
        try:
            connection.close()
        except sqlite3.Error:  # pragma: no cover - closing twice must stay harmless
            pass

    def close(self) -> None:
        self.release_thread_connection()
        with self._connection_lock:
            self._closed = True
            for connection in self._connections:
                try:
                    connection.close()
                except sqlite3.Error:  # pragma: no cover - closing twice must stay harmless
                    pass
            self._connections.clear()
        self._local = threading.local()

    def __enter__(self) -> "DurableRoundStore":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # -- connections --------------------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        if self._closed:
            raise DurableStateError("STORE_CLOSED", "the durable store has been closed")
        existing = getattr(self._local, "connection", None)
        if existing is not None:
            return existing
        connection = sqlite3.connect(
            str(self._path),
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
            uri=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        connection.execute(f"PRAGMA foreign_keys = {'ON' if FOREIGN_KEYS else 'OFF'}")
        mode = connection.execute(f"PRAGMA journal_mode = {JOURNAL_MODE}").fetchone()[0]
        if str(mode).lower() != JOURNAL_MODE:
            connection.close()
            raise DurableStateError(
                "JOURNAL_MODE_DENIED",
                f"the filesystem refused journal_mode={JOURNAL_MODE} and reported {mode!r}",
            )
        connection.execute(f"PRAGMA synchronous = {SYNCHRONOUS}")
        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != int(FOREIGN_KEYS):
            connection.close()
            raise DurableStateError("FOREIGN_KEYS_DENIED", "foreign key enforcement could not be enabled")
        with self._connection_lock:
            if self._closed:
                connection.close()
                raise DurableStateError("STORE_CLOSED", "the durable store has been closed")
            self._connections.append(connection)
        self._local.connection = connection
        return connection

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Open ``BEGIN IMMEDIATE`` with a bounded busy retry, then commit or roll back.

        Only the ``BEGIN`` is retried. Once a transaction is open its statements are never
        replayed: a blind retry of half-applied authoritative work is precisely how a second
        settlement gets written.
        """

        connection = self._connection()
        for attempt in range(1, MAX_BUSY_RETRIES + 1):
            try:
                connection.execute(f"BEGIN {TRANSACTION_MODE}")
                break
            except sqlite3.OperationalError as exc:
                if not _is_busy(exc) or attempt == MAX_BUSY_RETRIES:
                    raise DurableStateError(
                        "WRITE_LOCK_UNAVAILABLE", f"the write lock was not acquired in {attempt} attempts"
                    ) from None
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)
        try:
            yield connection
        except BaseException:
            self._rollback(connection)
            raise
        connection.execute("COMMIT")

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.OperationalError:
            # SQLite already rolled the transaction back itself; there is nothing left to undo.
            pass

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    # -- schema -------------------------------------------------------------------------

    def _prepare(self) -> None:
        connection = self._connection()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version > DURABLE_SCHEMA_VERSION:
            raise SchemaVersionError(
                "SCHEMA_VERSION_UNSUPPORTED",
                f"the database is at schema version {version}; this build supports "
                f"{list(SUPPORTED_SCHEMA_VERSIONS)!r} and will not downgrade it",
            )
        if version in SUPPORTED_SCHEMA_VERSIONS:
            self._verify_schema_meta(connection, version)
            return
        if version != 0:
            raise SchemaVersionError(
                "SCHEMA_VERSION_UNSUPPORTED", f"schema version {version} has no migration path"
            )

        with self._write_transaction() as transaction:
            # Re-read inside the write lock: another process may have created the schema
            # between the check above and this transaction.
            version = int(transaction.execute("PRAGMA user_version").fetchone()[0])
            if version in SUPPORTED_SCHEMA_VERSIONS:
                self._verify_schema_meta(transaction, version)
                return
            present = {
                row["name"]
                for row in transaction.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            if present & _OWNED_TABLES:
                raise SchemaVersionError(
                    "SCHEMA_STATE_AMBIGUOUS",
                    "the database reports version 0 but already holds durable-state tables; it is "
                    "not migrated automatically",
                )
            for statement in SCHEMA_STATEMENTS:
                transaction.execute(statement)
            now = self._clock()
            for key, value in (
                ("schema_version", str(DURABLE_SCHEMA_VERSION)),
                ("task_id", TASK_ID),
                ("policy_version", POLICY_VERSION),
                ("created_at", now),
            ):
                transaction.execute("INSERT INTO schema_meta (key, value) VALUES (?, ?)", (key, value))
            # ``PRAGMA user_version`` is not parameterisable; the value is a module constant.
            transaction.execute(f"PRAGMA user_version = {DURABLE_SCHEMA_VERSION}")

    @staticmethod
    def _verify_schema_meta(connection: sqlite3.Connection, version: int) -> None:
        """Refuse a database whose recorded version disagrees with ``PRAGMA user_version``.

        The pragma lives in the file header and the row lives in a table, so an edit that
        changes one without the other is visible here rather than being papered over.
        """

        row = connection.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
        if row is None:
            raise SchemaVersionError("SCHEMA_META_MISSING", "the database records no schema version row")
        if row["value"] != str(version):
            raise SchemaVersionError(
                "SCHEMA_META_MISMATCH",
                f"schema_meta records version {row['value']!r} but the file header records {version}",
            )

    # -- accounts -----------------------------------------------------------------------

    def register_account(self, account_id: str, account_type: str, balance_units: int = 0) -> None:
        """Create a ledger account with an integer opening balance.

        Accounts are registered explicitly so that a settlement can never conjure one. An
        unknown ``account_id`` in a transaction is an error, not an implicit account opening.

        Re-registering an account with exactly the same type and opening balance is a no-op,
        which makes start-up idempotent. Re-registering it with *different* values is refused
        rather than ignored: silently discarding a second opening balance would let a caller
        believe it had reset an account that in fact still holds its committed balance.
        """

        if not isinstance(account_id, str) or _ACCOUNT_ID_PATTERN.fullmatch(account_id) is None:
            raise DurableStateError("ACCOUNT_ID_INVALID", "account_id must look like '<kind>:<name>'")
        if account_type not in _ACCOUNT_TYPES:
            raise DurableStateError("ACCOUNT_TYPE_INVALID", f"account_type must be one of {_ACCOUNT_TYPES!r}")
        if not _is_integer(balance_units):
            raise DurableStateError("BALANCE_INVALID", "an opening balance must be an integer unit count")
        if account_type == "PLAYER" and balance_units < 0:
            raise DurableStateError("BALANCE_INVALID", "a player account cannot open with a negative balance")
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT account_type, balance_units FROM account WHERE account_id = ?", (account_id,)
            ).fetchone()
            if existing is not None:
                if str(existing["account_type"]) != account_type:
                    raise DurableStateError(
                        "ACCOUNT_TYPE_MISMATCH",
                        f"{account_id!r} is already registered as {existing['account_type']!r}",
                    )
                if int(existing["balance_units"]) != balance_units:
                    raise DurableStateError(
                        "ACCOUNT_ALREADY_REGISTERED",
                        f"{account_id!r} already holds a committed balance and cannot be reopened",
                    )
                return
            connection.execute(
                "INSERT INTO account (account_id, account_type, balance_units) VALUES (?, ?, ?)",
                (account_id, account_type, balance_units),
            )

    def balances(self, account_ids: Sequence[str] | None = None) -> dict[str, int]:
        """Return committed integer balances, for the named accounts or for all of them."""

        connection = self._connection()
        if account_ids is None:
            rows = connection.execute("SELECT account_id, balance_units FROM account ORDER BY account_id")
            return {row["account_id"]: int(row["balance_units"]) for row in rows}
        found: dict[str, int] = {}
        for account_id in account_ids:
            row = connection.execute(
                "SELECT balance_units FROM account WHERE account_id = ?", (account_id,)
            ).fetchone()
            if row is not None:
                found[account_id] = int(row["balance_units"])
        return found

    # -- reads --------------------------------------------------------------------------

    def draw_record(self, request_id: str) -> DrawRecord | None:
        """Return the committed authoritative record for ``request_id``, if one exists."""

        row = self._connection().execute(
            "SELECT payload_json FROM draw_record WHERE request_id = ?", (request_id,)
        ).fetchone()
        if row is None:
            return None
        return DrawRecord(**json.loads(row["payload_json"]))

    def ledger_transaction(self, transaction_id: str) -> dict[str, Any] | None:
        row = self._connection().execute(
            "SELECT payload_json FROM ledger_transaction WHERE transaction_id = ?", (transaction_id,)
        ).fetchone()
        return None if row is None else json.loads(row["payload_json"])

    def audit_events(self) -> list[dict[str, Any]]:
        """Return every stored audit event in chain order, reloaded from the database."""

        rows = self._connection().execute("SELECT body_json FROM audit_event ORDER BY event_seq")
        return [json.loads(row["body_json"]) for row in rows]

    def verify_chain(self) -> list[str]:
        """Return the linkage or integrity problems in the reloaded audit chain."""

        return verify_audit_chain(self.audit_events())

    def count(self, table: str) -> int:
        """Return the committed row count of one owned table."""

        if table not in _OWNED_TABLES:
            raise DurableStateError("TABLE_UNKNOWN", f"{table!r} is not a durable-state table")
        return int(self._connection().execute(f"SELECT COUNT(*) AS total FROM {table}").fetchone()["total"])

    def is_round_voided(self, round_id: str) -> bool:
        row = self._connection().execute(
            "SELECT 1 FROM round_void WHERE round_id = ?", (round_id,)
        ).fetchone()
        return row is not None

    # -- voids --------------------------------------------------------------------------

    def void_round(self, round_id: str, *, reason: str = "OPERATOR_VOID") -> None:
        """Durably mark a round unusable. Voiding survives a restart, unlike the engine's set."""

        if not isinstance(round_id, str) or _ROUND_ID_PATTERN.fullmatch(round_id) is None:
            raise RngDenied(
                "ROUND_ID_INVALID", FailureAction.BLOCK_AND_ESCALATE, "round_id must match ^RR-[A-Z0-9-]+$"
            )
        if not isinstance(reason, str) or _VOID_REASON_PATTERN.fullmatch(reason) is None:
            raise RngDenied(
                "VOID_REASON_INVALID",
                FailureAction.BLOCK_AND_ESCALATE,
                "a void reason must be 3..40 characters of [A-Z0-9_]",
            )
        with self._write_transaction() as connection:
            if connection.execute("SELECT 1 FROM round_void WHERE round_id = ?", (round_id,)).fetchone():
                return
            sink = _DurableAuditSink(connection, self._namespace, clock=self._clock)
            sink.append(
                self._audit_body(
                    event_type="SECURITY",
                    action="ROULETTE_ROUND_VOIDED",
                    decision="BLOCK",
                    round_id=round_id,
                    detail_refs=[f"rng-void-reason://{reason}"],
                    request_payload={"reason": reason, "round_id": round_id},
                )
            )
            connection.execute(
                "INSERT INTO round_void (round_id, reason, audit_event_seq, created_at) VALUES (?, ?, ?, ?)",
                (round_id, reason, sink.appended[-1][0], self._clock()),
            )

    # -- submission ---------------------------------------------------------------------

    def submit_round(
        self,
        request: DrawRequest,
        *,
        settlement: Callable[[DrawRecord], Mapping[str, Any] | None] | None = None,
    ) -> CommittedRound:
        """Draw, settle and audit one round as a single durable transaction.

        A duplicate ``request_id`` replays the committed record without touching entropy. A
        duplicate submitted concurrently from another connection blocks on the write lock,
        then finds the committed record and replays it too, so exactly one authoritative
        result and one settlement exist no matter how many callers raced.
        """

        if not isinstance(request, DrawRequest):
            raise RngDenied(
                "REQUEST_INVALID", FailureAction.BLOCK_AND_ESCALATE, "a DrawRequest instance is required"
            )
        request.validate()
        fingerprint = _sha256_text(request.fingerprint())

        sampled = False
        committed = False
        try:
            replay = self._replay(self._connection(), request, fingerprint)
            if replay is not None:
                return replay

            with self._write_transaction() as connection:
                self._fault("after_begin")
                replay = self._replay(connection, request, fingerprint)
                if replay is not None:
                    return replay
                if connection.execute(
                    "SELECT 1 FROM round_void WHERE round_id = ?", (request.round_id,)
                ).fetchone():
                    raise RngDenied(
                        "ROUND_VOIDED", FailureAction.BLOCK_AND_ESCALATE, f"{request.round_id} is voided"
                    )
                if connection.execute(
                    "SELECT 1 FROM draw_record WHERE round_id = ?", (request.round_id,)
                ).fetchone():
                    raise RngDenied(
                        "ROUND_ALREADY_DRAWN",
                        FailureAction.BLOCK_AND_ESCALATE,
                        f"{request.round_id} already has an authoritative draw",
                    )

                sink = _DurableAuditSink(connection, self._namespace, clock=self._clock)
                engine = RouletteDrawEngine(
                    entropy_source=self._entropy,
                    environment=self._environment,
                    audit_sink=sink,
                    clock=self._clock,
                )
                record = engine.draw(request)
                sampled = True
                self._fault("after_draw")

                transaction_id: str | None = None
                balances: dict[str, int] = {}
                if settlement is not None:
                    transaction_id, balances = self._settle(connection, sink, record, settlement)
                self._fault("after_ledger")

                payload = record.to_dict()
                connection.execute(
                    "INSERT INTO draw_record (request_id, round_id, request_fingerprint, pocket, proof_hash,"
                    " audit_event_seq, settlement_transaction_id, payload_json, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        record.request_id,
                        record.round_id,
                        fingerprint,
                        record.pocket,
                        record.proof_hash,
                        sink.appended[0][0],
                        transaction_id,
                        _reject_unstorable(payload, label="a draw record"),
                        record.created_at,
                    ),
                )
                self._fault("before_commit")

            committed = True
            self._fault("after_commit")
            return CommittedRound(
                record=record,
                settlement_transaction_id=transaction_id,
                balances=balances,
                audit_event_refs=tuple(reference for _, reference in sink.appended),
                replayed=False,
            )
        except RngDenied as denied:
            self._void_after_failure(request, sampled, committed, denied.code)
            self._record_denial(request, denied.code, denied.action.value)
            raise
        except DurableStateError as denied:
            self._void_after_failure(request, sampled, committed, denied.code)
            self._record_denial(request, denied.code, "BLOCK_AND_VOID")
            raise
        except Exception as exc:  # noqa: BLE001 - an injected or infrastructure fault
            self._void_after_failure(request, sampled, committed, type(exc).__name__)
            raise

    def _void_after_failure(
        self, request: DrawRequest, sampled: bool, committed: bool, code: str
    ) -> None:
        """Void a round whose sample was drawn and then discarded by a rollback.

        ``rng.py`` already refuses to leave a round drawable after a discarded sample, for the
        reason that a caller able to induce faults would otherwise be able to re-roll it. The
        same reasoning survives the move to durable storage, and here it matters more: the
        rollback erased every trace of the sample, so without this the retry would look like a
        first attempt. Recovering such a round is an operator decision, not an automatic one.
        """

        if not sampled or committed:
            return
        try:
            self.void_round(request.round_id, reason="POST_SAMPLE_ROLLBACK")
        except Exception:  # noqa: BLE001 - the original failure must not be replaced
            return

    def _record_denial(self, request: DrawRequest, code: str, action: str) -> None:
        """Record a refused submission. Best effort: an audit outage must not mask the denial."""

        try:
            with self._write_transaction() as connection:
                sink = _DurableAuditSink(connection, self._namespace, clock=self._clock)
                sink.append(
                    self._audit_body(
                        event_type="SECURITY",
                        action="ROULETTE_DURABLE_SUBMIT_DENIED",
                        decision="DENY",
                        round_id=request.round_id,
                        detail_refs=[
                            f"rng-request://{request.request_id}",
                            f"rng-denial-code://{code}",
                            f"rng-failure-action://{action}",
                        ],
                        request_payload=json.loads(request.fingerprint()),
                    )
                )
        except Exception:  # noqa: BLE001
            return

    def _replay(
        self, connection: sqlite3.Connection, request: DrawRequest, fingerprint: str
    ) -> CommittedRound | None:
        """Return the committed result for ``request``, or ``None`` when it has not been served.

        A stored record whose request fingerprint differs is *not* returned. Returning an
        unrelated prior result for a reused key would let a caller change the parameters of a
        settled round and receive a result that never answered its request.
        """

        row = connection.execute(
            "SELECT request_fingerprint, settlement_transaction_id, payload_json FROM draw_record"
            " WHERE request_id = ?",
            (request.request_id,),
        ).fetchone()
        if row is None:
            return None
        if row["request_fingerprint"] != fingerprint:
            raise RngDenied(
                "DUPLICATE_REQUEST_CONFLICT",
                FailureAction.BLOCK_AND_ESCALATE,
                f"request_id {request.request_id!r} was already used with different parameters",
            )
        record = DrawRecord(**json.loads(row["payload_json"]))
        # Re-derive the proof on every replay: a record edited in storage must not be handed
        # back to settlement as if it were authentic.
        verify_draw_record(record)
        transaction_id = row["settlement_transaction_id"]
        balances: dict[str, int] = {}
        references = [record.audit_event_ref]
        if transaction_id is not None:
            stored = json.loads(
                connection.execute(
                    "SELECT payload_json FROM ledger_transaction WHERE transaction_id = ?",
                    (transaction_id,),
                ).fetchone()["payload_json"]
            )
            references.append(stored["audit_event_ref"])
            accounts = [entry["account_id"] for entry in stored["entries"]]
            for account_id in accounts:
                balance = connection.execute(
                    "SELECT balance_units FROM account WHERE account_id = ?", (account_id,)
                ).fetchone()
                if balance is not None:
                    balances[account_id] = int(balance["balance_units"])
        return CommittedRound(
            record=record,
            settlement_transaction_id=transaction_id,
            balances=balances,
            audit_event_refs=tuple(references),
            replayed=True,
        )

    # -- settlement ---------------------------------------------------------------------

    def _settle(
        self,
        connection: sqlite3.Connection,
        sink: _DurableAuditSink,
        record: DrawRecord,
        settlement: Callable[[DrawRecord], Mapping[str, Any] | None],
    ) -> tuple[str | None, dict[str, int]]:
        body = settlement(record)
        if body is None:
            return None, {}
        if not isinstance(body, Mapping):
            raise DurableStateError("SETTLEMENT_INVALID", "a settlement factory must return a mapping")
        transaction = json.loads(json.dumps(dict(body), ensure_ascii=False))
        if "audit_event_ref" in transaction:
            raise DurableStateError(
                "SETTLEMENT_AUDIT_REF_DENIED",
                "the store binds the audit reference; a caller-supplied one would not be the "
                "event that actually authorised the settlement",
            )
        self._validate_transaction(transaction, expect_audit_ref=False)
        if transaction["round_id"] != record.round_id:
            raise DurableStateError(
                "SETTLEMENT_ROUND_MISMATCH", "the settlement does not belong to the drawn round"
            )

        # The fingerprint covers the caller's payload only. The audit reference is minted by
        # the store a moment later, so including it would make an honest retry look like a
        # conflicting one.
        fingerprint = _sha256_text(_canonical(transaction))
        existing = connection.execute(
            "SELECT transaction_id, request_fingerprint, payload_json FROM ledger_transaction"
            " WHERE idempotency_key = ?",
            (transaction["idempotency_key"],),
        ).fetchone()
        if existing is not None:
            if existing["request_fingerprint"] != fingerprint:
                raise LedgerConflict(
                    "IDEMPOTENCY_KEY_CONFLICT",
                    f"idempotency key {transaction['idempotency_key']!r} was already used with a "
                    "different payload",
                )
            stored = json.loads(existing["payload_json"])
            accounts = [entry["account_id"] for entry in stored["entries"]]
            return existing["transaction_id"], self._read_balances(connection, accounts)

        reference = sink.append(
            self._audit_body(
                event_type="ARTIFACT",
                action="ROULETTE_ROUND_SETTLED",
                decision="COMPLETE",
                round_id=record.round_id,
                detail_refs=[
                    f"ledger-transaction://{transaction['transaction_id']}",
                    f"ledger-idempotency://{transaction['idempotency_key']}",
                    f"rng-proof://{record.proof_hash}",
                ],
                request_payload={
                    "idempotency_key": transaction["idempotency_key"],
                    "round_id": record.round_id,
                    "transaction_id": transaction["transaction_id"],
                },
            )
        )
        audit_seq = sink.appended[-1][0]
        transaction["audit_event_ref"] = reference
        self._validate_transaction(transaction, expect_audit_ref=True)

        accounts = [entry["account_id"] for entry in transaction["entries"]]
        registered = self._read_account_types(connection, accounts)
        for entry in transaction["entries"]:
            if entry["account_id"] not in registered:
                raise DurableStateError(
                    "ACCOUNT_UNKNOWN", f"ledger account {entry['account_id']!r} is not registered"
                )
            if registered[entry["account_id"]] != entry["account_type"]:
                # A mislabelled entry would slip past the R1 rule that only PLAYER accounts
                # may not go negative, so the registered type wins over the submitted one.
                raise DurableStateError(
                    "ACCOUNT_TYPE_MISMATCH",
                    f"ledger account {entry['account_id']!r} is registered as "
                    f"{registered[entry['account_id']]!r}",
                )

        balances = self._read_balances(connection, accounts)
        try:
            decision = post_transaction(transaction, balances, [])
        except ValueError as exc:
            raise DurableStateError("LEDGER_REJECTED", str(exc)) from None
        if not decision.applied:
            raise DurableStateError("LEDGER_REJECTED", f"the ledger returned {decision.code}")

        # Entries first, then the transaction row. ``ledger_transaction_must_balance`` counts
        # and totals the entries when that row arrives, so the zero-sum rule is enforced by
        # the database and not only by ``_validate_transaction`` above; the deferred foreign
        # key on ``ledger_entry.transaction_id`` is what makes this order legal.
        for entry in transaction["entries"]:
            connection.execute(
                "INSERT INTO ledger_entry (transaction_id, account_id, account_type, amount_units)"
                " VALUES (?, ?, ?, ?)",
                (
                    transaction["transaction_id"],
                    entry["account_id"],
                    entry["account_type"],
                    entry["amount_units"],
                ),
            )
        connection.execute(
            "INSERT INTO ledger_transaction (transaction_id, idempotency_key, round_id, transaction_type,"
            " currency, request_fingerprint, audit_event_seq, payload_json, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                transaction["transaction_id"],
                transaction["idempotency_key"],
                transaction["round_id"],
                transaction["transaction_type"],
                transaction["currency"],
                fingerprint,
                audit_seq,
                _reject_unstorable(transaction, label="a ledger transaction"),
                transaction["created_at"],
            ),
        )
        for account_id, amount in decision.balances.items():
            connection.execute(
                "UPDATE account SET balance_units = ? WHERE account_id = ?", (int(amount), account_id)
            )
        return transaction["transaction_id"], {
            account_id: int(decision.balances[account_id]) for account_id in accounts
        }

    @staticmethod
    def _read_balances(connection: sqlite3.Connection, account_ids: Sequence[str]) -> dict[str, int]:
        balances: dict[str, int] = {}
        for account_id in account_ids:
            row = connection.execute(
                "SELECT balance_units FROM account WHERE account_id = ?", (account_id,)
            ).fetchone()
            if row is not None:
                balances[account_id] = int(row["balance_units"])
        return balances

    @staticmethod
    def _read_account_types(connection: sqlite3.Connection, account_ids: Sequence[str]) -> dict[str, str]:
        types: dict[str, str] = {}
        for account_id in account_ids:
            row = connection.execute(
                "SELECT account_type FROM account WHERE account_id = ?", (account_id,)
            ).fetchone()
            if row is not None:
                types[account_id] = str(row["account_type"])
        return types

    @staticmethod
    def _validate_transaction(transaction: Mapping[str, Any], *, expect_audit_ref: bool) -> None:
        """Enforce ``games/roulette/ledger-transaction.schema.json`` before anything is written.

        The JSON Schema is the published contract but it lives in the validator, not in the
        write path. Re-stating its rules here means a malformed transaction is refused at the
        boundary rather than discovered by a later baseline run.
        """

        allowed = set(_TRANSACTION_FIELDS)
        unexpected = sorted(set(transaction) - allowed)
        if unexpected:
            raise DurableStateError("TRANSACTION_INVALID", f"unexpected transaction fields {unexpected!r}")
        required = [name for name in _TRANSACTION_FIELDS if name != "audit_event_ref" or expect_audit_ref]
        missing = [name for name in required if name not in transaction]
        if missing:
            raise DurableStateError("TRANSACTION_INVALID", f"the transaction is missing {missing!r}")

        if transaction["schema_version"] != "1.0.0":
            raise DurableStateError("TRANSACTION_INVALID", "schema_version must be '1.0.0'")
        if _TRANSACTION_ID_PATTERN.fullmatch(str(transaction["transaction_id"])) is None:
            raise DurableStateError("TRANSACTION_INVALID", "transaction_id must match ^LT-[A-Z0-9-]+$")
        if _IDEMPOTENCY_KEY_PATTERN.fullmatch(str(transaction["idempotency_key"])) is None:
            raise DurableStateError("TRANSACTION_INVALID", "idempotency_key must match ^idem:[a-zA-Z0-9:_-]+$")
        if _ROUND_ID_PATTERN.fullmatch(str(transaction["round_id"])) is None:
            raise DurableStateError("TRANSACTION_INVALID", "round_id must match ^RR-[A-Z0-9-]+$")
        if transaction["transaction_type"] not in _TRANSACTION_TYPES:
            raise DurableStateError("TRANSACTION_INVALID", f"transaction_type must be in {_TRANSACTION_TYPES!r}")
        if transaction["currency"] != "VIRTUAL_CHIP":
            raise DurableStateError("TRANSACTION_INVALID", "currency must be VIRTUAL_CHIP")
        if _TIMESTAMP_PATTERN.fullmatch(str(transaction["created_at"])) is None:
            raise DurableStateError("TRANSACTION_INVALID", "created_at must be an ISO-8601 UTC timestamp")
        if _SHA256_PATTERN.fullmatch(str(transaction["request_hash"])) is None:
            raise DurableStateError("TRANSACTION_INVALID", "request_hash must be a sha256: digest")

        entries = transaction["entries"]
        if not isinstance(entries, list) or len(entries) < 2:
            raise DurableStateError("TRANSACTION_INVALID", "a transaction requires at least two entries")
        total = 0
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != set(_ENTRY_FIELDS):
                raise DurableStateError("TRANSACTION_INVALID", f"each entry must carry exactly {_ENTRY_FIELDS!r}")
            if not isinstance(entry["account_id"], str) or len(entry["account_id"]) < 3:
                raise DurableStateError("TRANSACTION_INVALID", "an entry account_id is required")
            if entry["account_type"] not in _ACCOUNT_TYPES:
                raise DurableStateError("TRANSACTION_INVALID", f"account_type must be in {_ACCOUNT_TYPES!r}")
            if not _is_integer(entry["amount_units"]) or entry["amount_units"] == 0:
                raise DurableStateError(
                    "TRANSACTION_INVALID", "amount_units must be a non-zero integer minimum unit count"
                )
            total += entry["amount_units"]
        if total != 0:
            raise DurableStateError("TRANSACTION_INVALID", "ledger entries must sum to zero")

    # -- audit bodies -------------------------------------------------------------------

    def _audit_body(
        self,
        *,
        event_type: str,
        action: str,
        decision: str,
        round_id: str,
        detail_refs: Sequence[str],
        request_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        environment = (
            self._environment.value if isinstance(self._environment, RngEnvironment) else str(self._environment)
        )
        return {
            "schema_version": "1.0.0",
            "event_type": event_type,
            "timestamp": self._clock(),
            "actor_type": "SERVICE",
            "actor_id": "game-server:durable-state",
            "task_id": TASK_ID,
            "action": action,
            "resource_refs": [
                f"round://{round_id}",
                f"durable-store://{self._namespace}",
                f"rng-environment://{environment}",
                *detail_refs,
            ],
            "decision": decision,
            "policy_version": POLICY_VERSION,
            "request_hash": _sha256_text(_canonical(dict(request_payload))),
            "contains_secret": False,
        }


class _NullAuditSink:
    """Sink used only for the constructor-time entropy source check; never records anything."""

    def append(self, body: Mapping[str, Any]) -> str:  # pragma: no cover - never called
        raise DurableStateError("AUDIT_SINK_UNBOUND", "this sink is not bound to a transaction")
