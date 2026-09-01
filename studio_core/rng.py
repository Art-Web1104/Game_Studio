"""Production CSPRNG draw boundary for European single-zero roulette (R2 unit 1).

Scope and non-scope
-------------------
This module owns exactly one responsibility: turning an authorised draw request into an
unbiased pocket in ``0..36`` and an audit-safe record of that draw. It deliberately imports
nothing from :mod:`studio_core.roulette` or :mod:`studio_core.ledger`; payout evaluation and
settlement read the recorded ``pocket`` and never reach into the entropy path. Keeping the
dependency edge one-directional is what makes "the RNG cannot be influenced by the payout
table" a structural property instead of a review promise.

Unbiasedness
------------
A byte has 256 values and the wheel has 37 pockets, so ``byte % 37`` is biased: 34 pockets
would occur 7 times per byte domain and 3 pockets only 6. The boundary therefore rejects
every byte at or above :data:`ACCEPTED_BYTE_LIMIT` (222 = 37 * 6) and maps the remaining 222
values with ``% 37``, giving each pocket exactly 6 of the accepted values. Rejection never
falls back to a biased mapping: exhausting :data:`MAX_REJECTION_ATTEMPTS` voids the round.

Secret hygiene
--------------
No raw entropy byte, seed value, or rejection count ever reaches a record, an audit event,
or an exception message. The rejection count is excluded on purpose: each rejection reveals
that one drawn byte fell in ``222..255``, which is genuine information about the CSPRNG
output stream. ``seed_reference`` names the entropy authority, not a recoverable seed --
an OS CSPRNG holds no application-visible seed to reference.

Fail-closed
-----------
Every gate raises :class:`RngDenied` carrying the failure action declared in
``games/roulette/rng-contract.yaml``. A draw is materialised only after its audit event has
been accepted; if the audit sink fails, the sampled pocket is discarded and the round is
voided, so an unauditable result can never be settled.

Scope of the idempotency guarantee
----------------------------------
:class:`RouletteDrawEngine` holds its records, round ownership and void set in memory and
serialises :meth:`RouletteDrawEngine.draw` with a lock, so the one-authoritative-draw-per-round
invariant holds across threads within one process. It does **not** survive a restart: a
client retry after a process restart would be treated as a new request. The durable store
that closes that gap is a named follow-up R2 unit, and until it exists this engine must not
be treated as the system of record for idempotency.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence

__all__ = [
    "ACCEPTED_BYTE_LIMIT",
    "ALGORITHM_ID",
    "ALGORITHM_VERSION",
    "AUDIT_TASK_ID",
    "AuditChain",
    "BYTE_DOMAIN",
    "DeterministicTestEntropySource",
    "DrawRecord",
    "DrawRequest",
    "FailureAction",
    "MAX_REJECTION_ATTEMPTS",
    "OsCsprngEntropySource",
    "POCKET_COUNT",
    "POLICY_VERSION",
    "PROHIBITED_RECORD_FIELDS",
    "RULESET_ID",
    "RRNG_SCHEMA_VERSION",
    "RngDenied",
    "RngEnvironment",
    "RouletteDrawEngine",
    "compute_event_hash",
    "compute_proof_hash",
    "draw_pocket",
    "map_entropy_byte",
    "mapping_distribution",
    "read_entropy",
    "verify_audit_chain",
    "verify_draw_record",
]

RRNG_SCHEMA_VERSION = "1.0.0"
RULESET_ID = "ROULETTE-EU-SINGLE-ZERO-1"
ALGORITHM_ID = "CSPRNG-REJECTION-UNIFORM-37"
ALGORITHM_VERSION = "1.0.0"
POLICY_VERSION = "RNG-ROULETTE-R1/1.0.0"
AUDIT_TASK_ID = "SYS-RNG-0012"

POCKET_COUNT = 37
BYTE_DOMAIN = 256
#: Largest multiple of :data:`POCKET_COUNT` inside the byte domain; bytes at or above it are
#: rejected so that the surviving values split evenly across the 37 pockets.
ACCEPTED_BYTE_LIMIT = BYTE_DOMAIN - (BYTE_DOMAIN % POCKET_COUNT)
#: A rejection has probability 34/256; 128 consecutive rejections is a ~1e-112 event and is
#: treated as a broken entropy source rather than something to retry forever.
MAX_REJECTION_ATTEMPTS = 128

#: Field names a draw record must never carry. Enforced by the record schema
#: (``additionalProperties: false``) and asserted by the validator and the test suite.
PROHIBITED_RECORD_FIELDS: tuple[str, ...] = (
    "seed",
    "seed_value",
    "entropy",
    "entropy_bytes",
    "random_bytes",
    "raw_bytes",
    "rejection_attempts",
    "state",
)

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")
_ROUND_ID_PATTERN = re.compile(r"^RR-[A-Z0-9-]{1,48}$")
_SOURCE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
_NAMESPACE_PATTERN = re.compile(r"^[A-Z0-9]{1,12}$")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_VOID_REASON_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,39}$")
#: An audit reference must be a scheme-qualified locator so that a record stays resolvable by
#: an auditor and cannot be satisfied by an arbitrary sink return value. Mirrors
#: ``audit_event_ref`` in ``games/roulette/rng-draw-record.schema.json``.
_AUDIT_REF_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]{1,15}://[A-Za-z0-9._:/~-]{3,128}$")
_MAX_DRAW_INDEX = 9999
_MAX_AUDIT_SEQUENCE = 9999


class FailureAction(str, Enum):
    """Failure behaviour declared by ``games/roulette/rng-contract.yaml``."""

    VOID_ROUND = "VOID_ROUND"
    BLOCK_AND_ESCALATE = "BLOCK_AND_ESCALATE"
    BLOCK_AND_VOID = "BLOCK_AND_VOID"


class RngEnvironment(str, Enum):
    """Deployment context of a draw engine. Unknown values are rejected, never coerced."""

    PRODUCTION = "PRODUCTION"
    NON_PRODUCTION = "NON_PRODUCTION"


class RngDenied(Exception):
    """A draw was refused. Messages carry policy context only, never entropy material."""

    def __init__(self, code: str, action: FailureAction, message: str) -> None:
        super().__init__(f"{code} ({action.value}): {message}")
        self.code = code
        self.action = action


class EntropySource(Protocol):
    """Byte source behind the draw boundary."""

    source_id: str
    is_deterministic: bool

    def read(self, size: int) -> bytes:
        """Return exactly ``size`` unpredictable bytes."""


class AuditSink(Protocol):
    """Append-only audit store. Returns the reference the draw record will cite."""

    def append(self, body: Mapping[str, Any]) -> str:
        """Persist ``body`` and return its audit reference."""


class OsCsprngEntropySource:
    """The only entropy source approved for production: the operating system CSPRNG.

    ``secrets.token_bytes`` delegates to ``os.urandom``, which is the platform CSPRNG
    (``getrandom(2)`` / ``BCryptGenRandom``). There is no application-held seed, so there is
    nothing to persist, log, or leak.
    """

    source_id = "os-csprng"
    is_deterministic = False

    def read(self, size: int) -> bytes:
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise RngDenied(
                "ENTROPY_REQUEST_INVALID", FailureAction.VOID_ROUND, "entropy read size must be a positive integer"
            )
        data = secrets.token_bytes(size)
        if len(data) != size:
            raise RngDenied(
                "ENTROPY_SOURCE_INVALID", FailureAction.VOID_ROUND, "the OS CSPRNG returned a short read"
            )
        return data

    def __repr__(self) -> str:  # pragma: no cover - trivial, but must never echo bytes
        return "OsCsprngEntropySource(source_id='os-csprng')"


class DeterministicTestEntropySource:
    """Reproducible byte source for tests and certification. Denied in production.

    :class:`RouletteDrawEngine` refuses to start when a deterministic source is paired with
    :attr:`RngEnvironment.PRODUCTION`, so this adapter cannot be reached by a production
    draw even if it is injected by mistake.
    """

    source_id = "deterministic-test"
    is_deterministic = True

    def __init__(self, stream: bytes | bytearray | Sequence[int], *, cycle: bool = True) -> None:
        data = bytes(stream)
        if not data:
            raise ValueError("a deterministic entropy stream must not be empty")
        self._stream = data
        self._cycle = cycle
        self._position = 0
        self._consumed = 0

    @property
    def consumed(self) -> int:
        """Total bytes handed out, counting every pass over a cycling stream.

        This is deliberately not the stream cursor: the certification suite uses this number
        to reason about how much entropy a draw actually cost, and a cursor that wraps to
        zero would under-report exactly the rejection-heavy cases worth measuring.
        """

        return self._consumed

    @property
    def position(self) -> int:
        """Cursor inside the stream, which wraps to zero whenever a cycling stream repeats."""

        return self._position

    def read(self, size: int) -> bytes:
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise RngDenied(
                "ENTROPY_REQUEST_INVALID", FailureAction.VOID_ROUND, "entropy read size must be a positive integer"
            )
        out = bytearray()
        for _ in range(size):
            if self._position >= len(self._stream):
                if not self._cycle:
                    raise RngDenied(
                        "ENTROPY_SOURCE_EXHAUSTED",
                        FailureAction.VOID_ROUND,
                        "the deterministic entropy stream is exhausted",
                    )
                self._position = 0
            out.append(self._stream[self._position])
            self._position += 1
            self._consumed += 1
        return bytes(out)

    def __repr__(self) -> str:
        # Neither the stream nor the consumption count is rendered. The stream would let a
        # debug log replay the draw sequence, and the consumed count is the rejection count
        # in disguise: subtract the draws issued and what remains is how many bytes fell in
        # the rejected band. The count stays available through :attr:`consumed` for the
        # certification suite, which is not an operator-visible surface.
        return f"DeterministicTestEntropySource(source_id={self.source_id!r}, length={len(self._stream)})"


#: Adapters this module owns and whose denial messages it therefore wrote itself.
_OWNED_ENTROPY_SOURCES = (OsCsprngEntropySource, DeterministicTestEntropySource)


def map_entropy_byte(value: int) -> int | None:
    """Map one entropy byte to a pocket, or ``None`` when the byte must be rejected.

    This is the single place the modulo is applied, so the certification suite can prove the
    mapping unbiased by exhausting the 256-value domain rather than by sampling it.
    """

    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < BYTE_DOMAIN:
        raise RngDenied(
            "ENTROPY_SOURCE_INVALID", FailureAction.VOID_ROUND, "entropy byte is outside the 0..255 domain"
        )
    if value >= ACCEPTED_BYTE_LIMIT:
        return None
    return value % POCKET_COUNT


def mapping_distribution() -> dict[int | None, int]:
    """Return how many of the 256 byte values map to each pocket, with ``None`` for rejects.

    Exhausting the domain is the unbiasedness proof: a uniform byte source makes every pocket
    equally likely exactly when every pocket claims the same number of accepted byte values.
    Sampling can only fail to reject this; enumeration settles it.
    """

    counts: dict[int | None, int] = {pocket: 0 for pocket in range(POCKET_COUNT)}
    counts[None] = 0
    for value in range(BYTE_DOMAIN):
        counts[map_entropy_byte(value)] += 1
    return counts


def read_entropy(source: "EntropySource", size: int) -> bytes:
    """Read exactly ``size`` bytes from ``source``, failing closed on any deviation.

    Third-party sources are treated as hostile: a raised exception is reported by type only
    and its traceback is dropped, because a chained traceback could carry byte material into
    a log.
    """

    try:
        data = source.read(size)
    except RngDenied as denied:
        # A foreign adapter may raise our own exception type with a message we did not write,
        # so the pass-through is restricted to the two adapters this module owns. Anything
        # else keeps its policy code and action but loses its message.
        if isinstance(source, _OWNED_ENTROPY_SOURCES):
            raise
        raise RngDenied(denied.code, denied.action, "the entropy source refused the read") from None
    except Exception as exc:  # noqa: BLE001 - any source failure is fail-closed
        raise RngDenied(
            "ENTROPY_SOURCE_FAILED",
            FailureAction.VOID_ROUND,
            f"the entropy source raised {type(exc).__name__}",
        ) from None
    if not isinstance(data, (bytes, bytearray)) or len(data) != size:
        raise RngDenied(
            "ENTROPY_SOURCE_INVALID",
            FailureAction.VOID_ROUND,
            "the entropy source returned a short or non-binary read",
        )
    return bytes(data)


def draw_pocket(source: "EntropySource") -> int:
    """Return one unbiased pocket in ``0..36`` drawn from ``source`` by rejection sampling.

    This is the whole entropy path, deliberately separated from :class:`RouletteDrawEngine`
    so that the statistical certification can draw a large sample without accumulating audit
    events or draw records, and so that a reviewer can read the sampling rule on its own.
    """

    for _ in range(MAX_REJECTION_ATTEMPTS):
        pocket = map_entropy_byte(read_entropy(source, 1)[0])
        if pocket is not None:
            return pocket
    raise RngDenied(
        "ENTROPY_REJECTION_EXHAUSTED",
        FailureAction.VOID_ROUND,
        f"no acceptable byte within {MAX_REJECTION_ATTEMPTS} attempts",
    )


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def compute_proof_hash(
    *,
    algorithm_id: str,
    algorithm_version: str,
    draw_index: int,
    pocket: int,
    request_id: str,
    round_id: str,
    ruleset_id: str,
    seed_reference: str,
) -> str:
    """Return the tamper-evidence binding between a draw request and its result.

    The binding is recomputable by any auditor holding only the draw record, and it contains
    no entropy. It proves the stored record was not edited after the fact; it is *not* a
    commit-reveal fairness proof, which is a named R2 follow-up candidate.
    """

    return _sha256(
        {
            "algorithm_id": algorithm_id,
            "algorithm_version": algorithm_version,
            "draw_index": draw_index,
            "pocket": pocket,
            "request_id": request_id,
            "round_id": round_id,
            "ruleset_id": ruleset_id,
            "seed_reference": seed_reference,
        }
    )


#: Fields an auditor needs in order to recompute a draw's tamper-evidence binding.
_PROOF_FIELDS: tuple[str, ...] = (
    "algorithm_id",
    "algorithm_version",
    "draw_index",
    "pocket",
    "proof_hash",
    "request_id",
    "round_id",
    "ruleset_id",
    "seed_reference",
)


def verify_draw_record(record: Any) -> None:
    """Re-derive a draw record's proof hash and raise when it does not match.

    ``games/roulette/rng-contract.yaml`` declares ``missing_or_invalid_proof: VOID_ROUND``.
    Computing the proof at draw time is not enough to satisfy that clause: something has to
    be able to *check* it later, otherwise a record edited in storage is indistinguishable
    from an authentic one. This is that check, and settlement should run it before paying
    out on a record it did not itself receive from the engine.
    """

    payload = record.to_dict() if isinstance(record, DrawRecord) else record
    if not isinstance(payload, Mapping):
        raise RngDenied("PROOF_MISSING", FailureAction.VOID_ROUND, "a draw record mapping is required")

    missing = [field for field in _PROOF_FIELDS if field not in payload]
    if missing:
        raise RngDenied(
            "PROOF_MISSING", FailureAction.VOID_ROUND, f"the draw record is missing {missing!r}"
        )

    expected = compute_proof_hash(
        algorithm_id=payload["algorithm_id"],
        algorithm_version=payload["algorithm_version"],
        draw_index=payload["draw_index"],
        pocket=payload["pocket"],
        request_id=payload["request_id"],
        round_id=payload["round_id"],
        ruleset_id=payload["ruleset_id"],
        seed_reference=payload["seed_reference"],
    )
    if payload["proof_hash"] != expected:
        raise RngDenied(
            "PROOF_INVALID",
            FailureAction.VOID_ROUND,
            "the draw record does not match its proof hash and may have been altered",
        )


def compute_event_hash(event: Mapping[str, Any]) -> str:
    """Return the hash of an audit event, excluding its own ``event_hash`` field."""

    return _sha256({key: value for key, value in event.items() if key != "event_hash"})


def verify_audit_chain(events: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return the linkage or integrity problems found in an audit chain, newest last."""

    problems: list[str] = []
    previous: str | None = None
    for index, event in enumerate(events):
        if event.get("previous_event_hash") != previous:
            problems.append(f"event {index}: previous_event_hash does not link to the prior event")
        expected = compute_event_hash(event)
        if event.get("event_hash") != expected:
            problems.append(f"event {index}: event_hash does not match the event body")
        if event.get("contains_secret") is not False:
            problems.append(f"event {index}: contains_secret must be false")
        previous = event.get("event_hash")
    return problems


@dataclass(frozen=True)
class DrawRequest:
    """One authoritative draw request. ``request_id`` is the idempotency boundary."""

    request_id: str
    round_id: str
    draw_index: int = 0
    ruleset_id: str = RULESET_ID
    algorithm_id: str = ALGORITHM_ID
    algorithm_version: str = ALGORITHM_VERSION

    def validate(self) -> None:
        if not isinstance(self.request_id, str) or _REQUEST_ID_PATTERN.fullmatch(self.request_id) is None:
            raise RngDenied(
                "REQUEST_ID_INVALID",
                FailureAction.BLOCK_AND_ESCALATE,
                "request_id must be 8..64 characters of [A-Za-z0-9._:-]",
            )
        if not isinstance(self.round_id, str) or _ROUND_ID_PATTERN.fullmatch(self.round_id) is None:
            raise RngDenied(
                "ROUND_ID_INVALID", FailureAction.BLOCK_AND_ESCALATE, "round_id must match ^RR-[A-Z0-9-]+$"
            )
        if (
            not isinstance(self.draw_index, int)
            or isinstance(self.draw_index, bool)
            or not 0 <= self.draw_index <= _MAX_DRAW_INDEX
        ):
            raise RngDenied(
                "DRAW_INDEX_INVALID",
                FailureAction.BLOCK_AND_ESCALATE,
                f"draw_index must be an integer in 0..{_MAX_DRAW_INDEX}",
            )

    def fingerprint(self) -> str:
        """Canonical identity of the request, used to detect idempotency-key reuse."""

        return _canonical(
            {
                "algorithm_id": self.algorithm_id,
                "algorithm_version": self.algorithm_version,
                "draw_index": self.draw_index,
                "request_id": self.request_id,
                "round_id": self.round_id,
                "ruleset_id": self.ruleset_id,
            }
        )


@dataclass(frozen=True)
class DrawRecord:
    """Audit-safe result of a draw. Every field here is publishable to an auditor."""

    schema_version: str
    request_id: str
    round_id: str
    ruleset_id: str
    algorithm_id: str
    algorithm_version: str
    draw_index: int
    pocket: int
    seed_reference: str
    proof_hash: str
    audit_event_ref: str
    environment: str
    entropy_source_id: str
    entropy_source_deterministic: bool
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "round_id": self.round_id,
            "ruleset_id": self.ruleset_id,
            "algorithm_id": self.algorithm_id,
            "algorithm_version": self.algorithm_version,
            "draw_index": self.draw_index,
            "pocket": self.pocket,
            "seed_reference": self.seed_reference,
            "proof_hash": self.proof_hash,
            "audit_event_ref": self.audit_event_ref,
            "environment": self.environment,
            "entropy_source_id": self.entropy_source_id,
            "entropy_source_deterministic": self.entropy_source_deterministic,
            "created_at": self.created_at,
        }

    def to_round_rng_record(self) -> dict[str, Any]:
        """Project this record into the ``rng_record`` shape of ``round.schema.json``.

        The round document deliberately stores less than the draw record: it carries the
        pinned algorithm identity and the tamper-evidence binding, and it references the
        entropy authority rather than embedding anything about the entropy itself.
        """

        return {
            "algorithm_id": self.algorithm_id,
            "version": self.algorithm_version,
            "seed_reference": self.seed_reference,
            "draw_index": self.draw_index,
            "proof_hash": self.proof_hash,
        }


class AuditChain:
    """In-memory append-only hash chain matching ``audit/audit-event.schema.json``.

    A durable store is the R2 database unit; this chain fixes the event shape and the
    linkage rules so the durable implementation has an executable target to match.
    """

    def __init__(self, namespace: str = "RNG") -> None:
        if not isinstance(namespace, str) or _NAMESPACE_PATTERN.fullmatch(namespace) is None:
            raise ValueError("audit namespace must be 1..12 uppercase alphanumeric characters")
        self._namespace = namespace
        self._events: list[dict[str, Any]] = []
        self._head: str | None = None

    @property
    def events(self) -> list[dict[str, Any]]:
        # A deep copy, not ``dict(event)``: a shallow copy shares the ``resource_refs`` list,
        # which would let a reader mutate the stored chain and break its own hash linkage.
        return copy.deepcopy(self._events)

    @property
    def head(self) -> str | None:
        return self._head

    def append(self, body: Mapping[str, Any]) -> str:
        sequence = len(self._events) + 1
        if sequence > _MAX_AUDIT_SEQUENCE:
            raise RngDenied(
                "AUDIT_SEQUENCE_EXHAUSTED", FailureAction.BLOCK_AND_VOID, "the audit chain segment is full"
            )
        event = dict(body)
        event["event_id"] = f"AE-{self._namespace}-{sequence:04d}"
        event["previous_event_hash"] = self._head
        event["event_hash"] = compute_event_hash(event)
        self._events.append(event)
        self._head = event["event_hash"]
        return f"audit://{event['event_id']}"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class RouletteDrawEngine:
    """Server-authoritative draw boundary for one roulette table.

    The engine is the only component allowed to touch entropy. It enforces the idempotency
    boundary, the one-authoritative-draw-per-round rule, and the audit-before-result
    ordering, then hands settlement a plain :class:`DrawRecord`.
    """

    def __init__(
        self,
        *,
        entropy_source: EntropySource | None = None,
        environment: RngEnvironment | str = RngEnvironment.PRODUCTION,
        audit_sink: AuditSink | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self._environment = self._resolve_environment(environment)
        source = OsCsprngEntropySource() if entropy_source is None else entropy_source
        self._validate_entropy_source(source, self._environment)
        self._entropy = source
        self._audit: AuditSink = AuditChain() if audit_sink is None else audit_sink
        if not hasattr(self._audit, "append") or not callable(self._audit.append):
            raise RngDenied(
                "AUDIT_SINK_INVALID", FailureAction.BLOCK_AND_VOID, "the audit sink must expose append()"
            )
        self._clock = clock if clock is not None else _utc_now_iso
        self._lock = threading.RLock()
        self._records: dict[str, DrawRecord] = {}
        self._fingerprints: dict[str, str] = {}
        self._round_requests: dict[str, str] = {}
        self._voided_rounds: set[str] = set()

    # -- construction gates -------------------------------------------------------------

    @staticmethod
    def _resolve_environment(environment: RngEnvironment | str) -> RngEnvironment:
        if isinstance(environment, RngEnvironment):
            return environment
        try:
            return RngEnvironment(environment)
        except (ValueError, TypeError):
            raise RngDenied(
                "ENVIRONMENT_INVALID",
                FailureAction.BLOCK_AND_ESCALATE,
                f"environment must be one of {[item.value for item in RngEnvironment]!r}",
            ) from None

    @staticmethod
    def _validate_entropy_source(source: Any, environment: RngEnvironment) -> None:
        for attribute in ("source_id", "is_deterministic", "read"):
            if not hasattr(source, attribute):
                raise RngDenied(
                    "ENTROPY_SOURCE_INVALID",
                    FailureAction.VOID_ROUND,
                    f"the entropy source is missing {attribute!r}",
                )
        if not callable(source.read):
            raise RngDenied("ENTROPY_SOURCE_INVALID", FailureAction.VOID_ROUND, "read must be callable")
        if not isinstance(source.source_id, str) or _SOURCE_ID_PATTERN.fullmatch(source.source_id) is None:
            raise RngDenied(
                "ENTROPY_SOURCE_INVALID",
                FailureAction.VOID_ROUND,
                "source_id must be 2..31 characters of [a-z0-9-]",
            )
        if not isinstance(source.is_deterministic, bool):
            raise RngDenied(
                "ENTROPY_SOURCE_INVALID", FailureAction.VOID_ROUND, "is_deterministic must be a boolean"
            )
        if environment is RngEnvironment.PRODUCTION and source.is_deterministic:
            raise RngDenied(
                "DETERMINISTIC_SOURCE_IN_PRODUCTION",
                FailureAction.BLOCK_AND_ESCALATE,
                "a deterministic entropy adapter may never back a production draw",
            )

    # -- properties ---------------------------------------------------------------------

    @property
    def environment(self) -> RngEnvironment:
        return self._environment

    @property
    def seed_reference(self) -> str:
        """Reference to the entropy authority. Never a seed value: the OS CSPRNG has none."""

        return f"entropy-ref://{self._entropy.source_id}/{ALGORITHM_ID}"

    def is_round_voided(self, round_id: str) -> bool:
        return round_id in self._voided_rounds

    def void_round(self, round_id: str, *, reason: str = "OPERATOR_VOID") -> None:
        """Mark a round unusable so no further draw can be issued for it.

        Voiding permanently blocks settlement for a round, so it is an authoritative state
        change: the identifier is validated like every other round-id entry point and the
        decision is recorded, rather than being an unaudited in-memory mutation.
        """

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
        with self._lock:
            self._voided_rounds.add(round_id)
            self._write_control_audit(
                action="ROULETTE_RNG_ROUND_VOIDED",
                decision="BLOCK",
                round_id=round_id,
                detail_refs=[f"rng-void-reason://{reason}"],
                request_payload={"reason": reason, "round_id": round_id},
            )

    # -- entropy path -------------------------------------------------------------------

    def _sample_pocket(self) -> int:
        # The engine owns policy, not sampling: the entropy path lives in ``draw_pocket`` so
        # the certification suite exercises exactly the code a production draw runs.
        return draw_pocket(self._entropy)

    # -- draw ---------------------------------------------------------------------------

    def draw(self, request: DrawRequest) -> DrawRecord:
        """Return the authoritative pocket for ``request``, replaying prior results exactly.

        The lock makes the one-authoritative-draw-per-round check an atomic check-and-act.
        Without it two callers racing on the same ``round_id`` would both read an unowned
        round, both consume entropy and both store a record, defeating the invariant this
        whole module exists to hold.

        A denial carrying :attr:`FailureAction.VOID_ROUND` or
        :attr:`FailureAction.BLOCK_AND_VOID` voids the round here rather than at each raise
        site. A pocket may already have been sampled and discarded by then, so leaving the
        round drawable would let a caller who can induce clock or entropy faults re-roll it.
        """

        if not isinstance(request, DrawRequest):
            raise RngDenied(
                "REQUEST_INVALID", FailureAction.BLOCK_AND_ESCALATE, "a DrawRequest instance is required"
            )
        request.validate()

        with self._lock:
            try:
                return self._draw_locked(request)
            except RngDenied as denied:
                if denied.action in (FailureAction.VOID_ROUND, FailureAction.BLOCK_AND_VOID):
                    self._voided_rounds.add(request.round_id)
                self._write_denial_audit(request, denied)
                raise

    def _draw_locked(self, request: DrawRequest) -> DrawRecord:
        """Perform the draw. The caller holds the lock and owns the failure handling."""

        if request.ruleset_id != RULESET_ID:
            raise RngDenied(
                "RULESET_MISMATCH", FailureAction.BLOCK_AND_ESCALATE, f"this engine serves {RULESET_ID}"
            )
        if request.algorithm_id != ALGORITHM_ID or request.algorithm_version != ALGORITHM_VERSION:
            raise RngDenied(
                "ALGORITHM_VERSION_MISMATCH",
                FailureAction.BLOCK_AND_ESCALATE,
                f"this engine implements {ALGORITHM_ID} {ALGORITHM_VERSION}",
            )

        fingerprint = request.fingerprint()
        existing = self._records.get(request.request_id)
        if existing is not None:
            if self._fingerprints[request.request_id] != fingerprint:
                raise RngDenied(
                    "DUPLICATE_REQUEST_CONFLICT",
                    FailureAction.BLOCK_AND_ESCALATE,
                    f"request_id {request.request_id!r} was already used with different parameters",
                )
            # ``RETURN_ORIGINAL_RESULT`` is unconditional: a retry replays the original
            # record even if the round was voided afterwards, because the alternative is a
            # retry that changes an already-issued authoritative result. Voiding is a
            # settlement-side decision, so settlement must consult ``is_round_voided``
            # rather than infer it from a draw succeeding.
            return existing

        if request.round_id in self._voided_rounds:
            raise RngDenied(
                "ROUND_VOIDED", FailureAction.BLOCK_AND_ESCALATE, f"{request.round_id} is voided"
            )
        owner = self._round_requests.get(request.round_id)
        if owner is not None and owner != request.request_id:
            raise RngDenied(
                "ROUND_ALREADY_DRAWN",
                FailureAction.BLOCK_AND_ESCALATE,
                f"{request.round_id} already has an authoritative draw",
            )

        pocket = self._sample_pocket()
        if not 0 <= pocket < POCKET_COUNT:  # pragma: no cover - defence in depth
            raise RngDenied(
                "POCKET_OUT_OF_RANGE", FailureAction.VOID_ROUND, "the sampled pocket left the wheel domain"
            )

        seed_reference = self.seed_reference
        proof_hash = compute_proof_hash(
            algorithm_id=request.algorithm_id,
            algorithm_version=request.algorithm_version,
            draw_index=request.draw_index,
            pocket=pocket,
            request_id=request.request_id,
            round_id=request.round_id,
            ruleset_id=request.ruleset_id,
            seed_reference=seed_reference,
        )
        created_at = self._timestamp()

        audit_ref = self._write_audit(request, pocket, proof_hash, seed_reference, created_at)

        record = DrawRecord(
            schema_version=RRNG_SCHEMA_VERSION,
            request_id=request.request_id,
            round_id=request.round_id,
            ruleset_id=request.ruleset_id,
            algorithm_id=request.algorithm_id,
            algorithm_version=request.algorithm_version,
            draw_index=request.draw_index,
            pocket=pocket,
            seed_reference=seed_reference,
            proof_hash=proof_hash,
            audit_event_ref=audit_ref,
            environment=self._environment.value,
            entropy_source_id=self._entropy.source_id,
            entropy_source_deterministic=self._entropy.is_deterministic,
            created_at=created_at,
        )
        self._records[request.request_id] = record
        self._fingerprints[request.request_id] = fingerprint
        self._round_requests[request.round_id] = request.request_id
        return record

    def _timestamp(self) -> str:
        try:
            value = self._clock()
        except Exception as exc:  # noqa: BLE001
            raise RngDenied(
                "CLOCK_FAILED", FailureAction.VOID_ROUND, f"the clock raised {type(exc).__name__}"
            ) from None
        if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
            raise RngDenied("CLOCK_INVALID", FailureAction.VOID_ROUND, "the clock did not return an ISO-8601 UTC time")
        return value

    def _safe_timestamp(self) -> str:
        """Return a usable timestamp even when the injected clock is the thing that failed."""

        try:
            return self._timestamp()
        except RngDenied:
            return _utc_now_iso()

    def _write_control_audit(
        self,
        *,
        action: str,
        decision: str,
        round_id: str,
        detail_refs: Sequence[str],
        request_payload: Mapping[str, Any],
    ) -> None:
        """Record a non-draw decision. Best effort: an audit outage must not mask the event.

        A refusal is the security-relevant half of the draw path. Recording only successes
        would leave a sequence of sample-discard-resample invisible to an auditor, which is
        precisely the pattern an audit trail exists to expose. This never raises: the caller
        is already failing closed, and turning a logging outage into a second, different
        failure would hide the original one.
        """

        body = {
            "schema_version": RRNG_SCHEMA_VERSION,
            "event_type": "SECURITY",
            "timestamp": self._safe_timestamp(),
            "actor_type": "SERVICE",
            "actor_id": f"game-server:{ALGORITHM_ID}",
            "task_id": AUDIT_TASK_ID,
            "action": action,
            "resource_refs": [
                f"round://{round_id}",
                f"rng-environment://{self._environment.value}",
                *detail_refs,
            ],
            "decision": decision,
            "policy_version": POLICY_VERSION,
            "request_hash": _sha256(dict(request_payload)),
            "contains_secret": False,
        }
        try:
            self._audit.append(body)
        except Exception:  # noqa: BLE001 - an audit outage must not replace the real failure
            return

    def _write_denial_audit(self, request: DrawRequest, denied: RngDenied) -> None:
        """Record a refused draw. Only the policy code and action are stored, never entropy."""

        self._write_control_audit(
            action="ROULETTE_RNG_DRAW_DENIED",
            decision="DENY",
            round_id=request.round_id,
            detail_refs=[
                f"rng-request://{request.request_id}",
                f"rng-denial-code://{denied.code}",
                f"rng-failure-action://{denied.action.value}",
            ],
            request_payload=json.loads(request.fingerprint()),
        )

    def _write_audit(
        self,
        request: DrawRequest,
        pocket: int,
        proof_hash: str,
        seed_reference: str,
        created_at: str,
    ) -> str:
        body = {
            "schema_version": RRNG_SCHEMA_VERSION,
            "event_type": "ARTIFACT",
            "timestamp": created_at,
            "actor_type": "SERVICE",
            "actor_id": f"game-server:{ALGORITHM_ID}",
            "task_id": AUDIT_TASK_ID,
            "action": "ROULETTE_RNG_DRAW",
            "resource_refs": [
                f"round://{request.round_id}",
                f"rng-request://{request.request_id}",
                f"rng-proof://{proof_hash}",
                f"rng-entropy://{seed_reference}",
                f"rng-environment://{self._environment.value}",
            ],
            "decision": "COMPLETE",
            "policy_version": POLICY_VERSION,
            "request_hash": _sha256(json.loads(request.fingerprint())),
            "contains_secret": False,
        }
        try:
            reference = self._audit.append(body)
        except RngDenied:
            self._voided_rounds.add(request.round_id)
            raise
        except Exception as exc:  # noqa: BLE001
            self._voided_rounds.add(request.round_id)
            raise RngDenied(
                "AUDIT_WRITE_FAILURE",
                FailureAction.BLOCK_AND_VOID,
                f"the audit sink raised {type(exc).__name__}; the round is voided and the result discarded",
            ) from None
        if not isinstance(reference, str) or _AUDIT_REF_PATTERN.fullmatch(reference) is None:
            self._voided_rounds.add(request.round_id)
            raise RngDenied(
                "AUDIT_WRITE_FAILURE",
                FailureAction.BLOCK_AND_VOID,
                "the audit sink did not return a resolvable event reference",
            )
        return reference
