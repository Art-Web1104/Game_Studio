"""R2-SEC-0005: bounded local defensive security verification for the roulette slice.

    python scripts/verify_r2_security.py

What this is
------------
A harness that tries to make the already-existing single-user loopback roulette slice do
something it promises it will not do, and writes down -- in sanitised form -- whether it
refused. Five dimensions, exactly as ``games/roulette/security-verification-contract.yaml``
declares them:

* **client authority forgery** -- every name in
  :data:`apps.roulette_web.table.CLIENT_AUTHORITY_FIELDS`, carried in a request body at a
  nested position, must be refused with ``CLIENT_AUTHORITY_DENIED``, and the authoritative
  mutation snapshot taken immediately before and immediately after the refusal must be
  identical.
* **betting phase and lock bypass** -- a bet outside the phase
  ``games/roulette/round-state.yaml`` and :data:`apps.roulette_web.table.BETS_ACCEPTED_IN`
  agree on must be refused, including the attempts that try to *name* a phase or a closing
  instant in the request body, and the snapshot must again be unchanged.
* **idempotency and settlement replay** -- a repeated ``request_id`` must commit exactly
  once: no second draw, no further entropy consumption, no second ledger transaction, no
  second payout, no further balance movement, and every caller observing the same commit. A
  reused identifier carrying different parameters must commit nothing and be refused with the
  declared conflict code.
* **audit tamper and deletion detection** -- performed only on a disposable copy of the run's
  own database inside the temporary workspace. The original is hashed before and after, and
  so is every audit record tracked in this repository.
* **seed reference confidentiality** -- no raw entropy byte, seed value, rejection count or
  internal entropy state may appear in an API response, a draw record, an audit event, this
  harness's own output, or the documents this unit writes.

Malformed requests are handled only as a fixed, finite, deterministic and non-destructive
set: no random generation, no repetition storm, no time-based mutation. Their responses are
checked for the absence of tracebacks, filesystem paths, SQLite messages and internal
exception text, and a normal request is issued afterwards to show the surface still works.

What this deliberately is not
-----------------------------
It adds no HTTP route, no error code, no runtime module and no dependency, and it repairs
nothing. A finding is recorded, sanitised, and handed to a separate remediation Task
Contract candidate; this unit has no authority to fix production code, and discovering a
defect does not grant it. There is no timing threshold, no load or stress behaviour, and no
performance number anywhere in the output: an execution bound is a safety limit, never a
pass/fail criterion.

Safety bounds
-------------
:data:`MAX_CASES`, :data:`MAX_HTTP_REQUESTS`, :data:`MAX_WALL_SECONDS` and
:data:`MAX_PAYLOAD_BYTES` bound a local run. :meth:`VerificationConfig.validate` refuses a
configuration above any of them *before* a temporary directory, a database, a socket, a
thread or a data copy exists, so a refusal leaves nothing behind to clean up. The payload
bound is held at or below :data:`apps.roulette_web.server.MAX_BODY_BYTES`, which is the
limit the observed transport already enforces.

Target binding
--------------
Loopback IP literals only, from :data:`ALLOWED_TARGET_HOSTS`, which is asserted to be a
subset of :data:`apps.roulette_web.server.LOOPBACK_HOSTS` and therefore of the
``transport_limits.allowed_hosts`` published by
``games/roulette/playable-slice-contract.yaml``. Every other IP literal and every name
string is refused in preflight. This module resolves no name: there is no ``gethostbyname``,
no ``getaddrinfo`` and no ``getfqdn`` call in it, because an off-loopback target is not
something to look up, it is something to refuse. The port is always ``0``, so the operating
system assigns one from the ephemeral range and a run can never collide with a slice a
developer already has open.

Cleaning up
-----------
The workspace is an ordinary ``TemporaryDirectory`` and its cleanup errors are not
suppressed. A failed delete means a database handle outlived the run, and swallowing it
would turn the one signal that a handle leaked into silence. Every request-serving worker is
enrolled and joined, and each releases its own thread-local SQLite connection, because
``sqlite3`` lets only the thread that opened a connection close it.

Nothing emitted here names a host, a user account, a credential, an absolute path or any
entropy material, and no real secret or personal datum is used anywhere: every identifier
and value in the case tables is synthetic and non-sensitive.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import pathlib
import platform
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import (  # noqa: E402
    LOOPBACK_HOSTS,
    MAX_BODY_BYTES,
    ROUTES,
    create_server,
    open_table,
    serve_in_background,
)
from apps.roulette_web.table import (  # noqa: E402
    BETS_ACCEPTED_IN,
    CLIENT_AUTHORITY_FIELDS,
    HOUSE_ACCOUNT,
    NOTICE as PROTOTYPE_NOTICE,
    PLAYER_ACCOUNT,
    TableConfig,
)
from studio_core.durable_state import DurableRoundStore  # noqa: E402
from studio_core.integrity import hash_file  # noqa: E402
from studio_core.rng import (  # noqa: E402
    PROHIBITED_RECORD_FIELDS,
    DrawRequest,
    OsCsprngEntropySource,
    RngDenied,
    verify_audit_chain,
)

__all__ = [
    "ALLOWED_TARGET_HOSTS",
    "CONTRACT_REF",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_WALL_SECONDS",
    "DIMENSIONS",
    "ENTROPY_MATERIAL_PATTERNS",
    "ENVIRONMENT_KEYS",
    "FINDING_SEVERITY_BY_DIMENSION",
    "MALFORMED_CASES",
    "MAX_CASES",
    "MAX_HTTP_REQUESTS",
    "MAX_PAYLOAD_BYTES",
    "MAX_WALL_SECONDS",
    "NOTICE",
    "OUTPUT_TOP_LEVEL_KEYS",
    "PLANNED_CASE_COUNT",
    "PLANNED_HTTP_REQUEST_COUNT",
    "PROHIBITED_RESPONSE_MARKERS",
    "REMEDIATION_TASK_CANDIDATE_PREFIX",
    "RESPONSE_PROHIBITED_FIELDS",
    "RESPONSE_STATE_ENVELOPE_PATH",
    "SANITIZATION_SCAN_TARGETS",
    "SCHEMA_VERSION",
    "SEED_REFERENCE_PATTERN",
    "TASK_ID",
    "SecurityVerificationError",
    "VerificationConfig",
    "main",
    "run_verification",
]

SCHEMA_VERSION = "1.0.0"
TASK_ID = "R2-SEC-0005"

#: Repository-relative on purpose. An absolute path would name the operator's filesystem.
CONTRACT_REF = "games/roulette/security-verification-contract.yaml"

#: The repository root, used only to read declared repository files. It is never emitted.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------------------
# safety bounds -- bounded local execution only
# ---------------------------------------------------------------------------------------
# The four approved hard ceilings of AC-002. They exist so a local defensive run cannot grow
# without limit. They are not security maturity targets and not pass/fail thresholds: "64
# cases passed" is not a statement that the surface is safe, and no document may cite them
# as one.

MAX_CASES = 64
MAX_HTTP_REQUESTS = 128
MAX_WALL_SECONDS = 60
#: Held at or below the transport's own limit, so the harness can never be the component that
#: introduces a larger body than the observed server already accepts.
MAX_PAYLOAD_BYTES = 8192

DEFAULT_WALL_SECONDS = 30
DEFAULT_HOST = "127.0.0.1"
#: Always ephemeral. A fixed port is refused in preflight rather than bound and regretted.
DEFAULT_PORT = 0

#: Loopback IP literals only. Deliberately narrower than the slice's own allowlist: the two
#: name strings that allowlist also carries (``localhost`` and ``ip6-localhost``) are refused
#: here, because accepting a name is the first step towards resolving one.
ALLOWED_TARGET_HOSTS: tuple[str, ...] = ("127.0.0.1", "::1")

DEFAULT_STAKE_UNITS = 5
DEFAULT_OPENING_PLAYER_UNITS = 10_000
DEFAULT_OPENING_HOUSE_UNITS = 1_000_000

#: An even-money outside bet: the worst pocket returns twice the stake, which keeps the house
#: exposure check satisfiable and the reconciliation arithmetic easy to follow.
VERIFIED_BET_TYPE = "red"

#: The five verification dimensions, in contract order.
DIMENSIONS: tuple[str, ...] = (
    "client_authority_forgery_denial",
    "betting_phase_lock_bypass_denial",
    "idempotency_and_settlement_replay_safety",
    "audit_event_tamper_and_delete_detection_on_copy",
    "seed_reference_confidentiality",
)

#: Malformed-request handling is a sixth reported group. It is not a fifth *verification
#: dimension*: the contract lists five, and this one exists to show the refusals stay
#: deterministic and non-destructive rather than to make a security claim of its own.
MALFORMED_GROUP = "malformed_request_safety"

#: Severity a failure in each dimension would carry, declared up front so a discovered defect
#: cannot be quietly re-graded after the fact.
FINDING_SEVERITY_BY_DIMENSION: dict[str, str] = {
    "client_authority_forgery_denial": "BLOCKER",
    "betting_phase_lock_bypass_denial": "BLOCKER",
    "idempotency_and_settlement_replay_safety": "BLOCKER",
    "audit_event_tamper_and_delete_detection_on_copy": "HIGH",
    "seed_reference_confidentiality": "HIGH",
    MALFORMED_GROUP: "MEDIUM",
}

#: A finding names a *candidate* for a separate remediation Task Contract. This unit does not
#: issue that contract and does not perform the remediation; the identifier is a placeholder
#: an approver can adopt, never an authorisation to edit runtime code here.
REMEDIATION_TASK_CANDIDATE_PREFIX = "R2-SECFIX-CANDIDATE"

# ---------------------------------------------------------------------------------------
# sanitisation rules
# ---------------------------------------------------------------------------------------

#: Text a response body may never contain. Checked case-insensitively against every malformed
#: case response, so a refusal that leaked a path or an exception name would be a finding.
PROHIBITED_RESPONSE_MARKERS: tuple[str, ...] = (
    "traceback",
    "sqlite",
    "sqlite3",
    "no such table",
    "site-packages",
    "file \"",
    "line ",
    ".py",
    "c:\\",
    "/home/",
    "/users/",
    "exception",
)

#: ``seed_reference`` names the entropy authority. It is a reference, never a seed: the OS
#: CSPRNG holds no application-visible seed to reference in the first place.
SEED_REFERENCE_PATTERN = r"^entropy-ref://[a-z0-9-]{2,31}/[A-Z0-9-]{3,48}$"

#: Shapes that would indicate raw entropy material had reached a document. Long hexadecimal
#: runs are excluded when they are the body of a ``sha256:`` digest, which is a published
#: tamper-evidence value and not entropy.
ENTROPY_MATERIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("unlabelled_long_hex_run", r"(?<!sha256:)\b[0-9a-fA-F]{32,}\b"),
    ("byte_escape_sequence_run", r"(?:\\x[0-9a-fA-F]{2}){4,}"),
    (
        "entropy_material_assigned_to_a_key",
        r"(?i)\b(?:seed|entropy|random)[_-]?(?:value|byte|bytes|state)\b\s*[:=]\s*"
        r"[\"']?[A-Za-z0-9+/=]{16,}",
    ),
)

#: The entropy field names an *API response* may never carry.
#:
#: This is :data:`studio_core.rng.PROHIBITED_RECORD_FIELDS` minus the single generic name
#: ``state``, and the subtraction is deliberate rather than a convenience. In a draw record
#: ``state`` means internal entropy state and is rightly forbidden; in a response envelope
#: ``state`` is the published round snapshot that ``games/roulette/playable-slice-contract.yaml``
#: requires ``GET /api/state`` to return. Matching the bare name across both would report a
#: required field as a leak, and a check that cries wolf on a required field is a check that
#: gets switched off. The name is not simply dropped: :func:`_check_confidentiality` asserts
#: that ``state`` appears in a response only as that top-level envelope and nowhere deeper,
#: so an entropy state smuggled into a nested object is still caught. Draw records and audit
#: events are held to the full set, because neither has an envelope to confuse it with.
RESPONSE_PROHIBITED_FIELDS: tuple[str, ...] = tuple(
    name for name in PROHIBITED_RECORD_FIELDS if name != "state"
)

#: The one path at which the published round snapshot envelope may appear in a response body.
RESPONSE_STATE_ENVELOPE_PATH = "$.state"

#: Documents this unit writes, scanned for entropy material once they exist. A target that is
#: absent is reported as absent rather than silently skipped.
SANITIZATION_SCAN_TARGETS: tuple[str, ...] = (
    "games/roulette/security-verification-contract.yaml",
    "scripts/verify_r2_security.py",
    "tests/test_security_verification.py",
    "docs/games/R2-security-verification.md",
    "docs/approvals/R2-SEC-0005-validation-report.md",
    "audit/events/R2-SEC-0005-events.json",
    "artifacts/R2-SEC-0005-artifact.json",
    "handoffs/R2-SEC-0005-handoff.json",
)

# ---------------------------------------------------------------------------------------
# the execution plan
# ---------------------------------------------------------------------------------------
# Both numbers are checked twice: in preflight, against the configured ceilings, so an
# execution that could not fit is refused before anything exists; and at the end of a run,
# against what actually happened, so a plan that silently drifted away from the code fails
# instead of being believed.

#: 15 client-authority cases (13 declared field names, one top-level placement, one placement
#: nested inside a list), 8 phase and lock cases, 8 idempotency cases, 5 audit-copy cases,
#: 6 confidentiality cases, 13 malformed-request cases.
PLANNED_CASE_COUNT = 55

#: 1 opening read, 15 authority, 8 phase and lock, 6 idempotency (two further idempotency
#: cases go through the store boundary directly and cost no request), 13 malformed, 1 closing
#: read. The five audit-copy cases and the six confidentiality cases issue no request at all.
PLANNED_HTTP_REQUEST_COUNT = 44

ENVIRONMENT_KEYS: tuple[str, ...] = (
    "python_version",
    "python_implementation",
    "system",
    "release",
    "machine",
)

OUTPUT_TOP_LEVEL_KEYS: tuple[str, ...] = (
    "schema_version",
    "task_id",
    "contract_ref",
    "notice",
    "environment",
    "config",
    "bounds",
    "counts",
    "dimensions",
    "cases",
    "evidence",
    "findings",
    "remediation",
    "cleanup",
)

NOTICE: dict[str, Any] = {
    "prototype": dict(PROTOTYPE_NOTICE),
    "verification": {
        "scope": "BOUNDED_LOCAL_DEFENSIVE",
        "target": "loopback reference implementation already present in this repository",
        "remediation_performed": False,
        "production_or_external_target": False,
        "bounds_are_safety_limits_not_maturity_targets": True,
        "timing_thresholds_declared": "NONE",
        "load_or_stress_behaviour": "NONE",
        "text_en": (
            "Bounded local defensive verification of an internal prototype. Execution "
            "bounds are safety limits, not security maturity targets: cases that held are "
            "not evidence that the surface is safe. No remediation is performed by this "
            "unit; findings are handed to a separate remediation Task Contract candidate."
        ),
        "text_ko": (
            "내부 프로토타입에 대한 유계 로컬 방어적 검증이다. 실행 상한은 안전 경계이며 보안 "
            "성숙도 목표가 아니다. 통과한 사례가 표면의 안전을 증명하지 않는다. 이 유닛은 개선을 "
            "수행하지 않고, 발견 사항은 별도의 개선 Task Contract 후보로 넘긴다."
        ),
    },
}


class SecurityVerificationError(RuntimeError):
    """A bounded-verification refusal carrying a stable code.

    Messages carry policy context only: never a filesystem path, a hostname, a database
    detail or a traceback, because an operator may paste this into an evidence file.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------------------
# configuration -- every check below is arithmetic or set membership
# ---------------------------------------------------------------------------------------


def _require_integer(name: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise SecurityVerificationError("CONFIG_INVALID", f"{name} must be an integer")
    return value


def _require_range(name: str, value: int, minimum: int, maximum: int) -> None:
    if value < minimum or value > maximum:
        raise SecurityVerificationError(
            "BOUND_EXCEEDED", f"{name} must be within {minimum}..{maximum}; {value} was requested"
        )


@dataclass(frozen=True)
class VerificationConfig:
    """One bounded verification run, refused before it starts if it exceeds a ceiling."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    max_cases: int = MAX_CASES
    max_http_requests: int = MAX_HTTP_REQUESTS
    wall_timeout_seconds: int = DEFAULT_WALL_SECONDS
    max_payload_bytes: int = MAX_PAYLOAD_BYTES
    stake_units: int = DEFAULT_STAKE_UNITS
    opening_player_units: int = DEFAULT_OPENING_PLAYER_UNITS
    opening_house_units: int = DEFAULT_OPENING_HOUSE_UNITS

    def validate(self) -> "VerificationConfig":
        """Refuse anything above a ceiling or off loopback, and return ``self``.

        Nothing has been opened, bound, copied or started when this runs. That ordering is
        the whole of ``AC-002``'s "enforced before resource creation": a refusal here cannot
        leave a temporary directory, a database, a socket, a thread or a data copy behind,
        because none of them exists yet.
        """

        for name in (
            "port",
            "max_cases",
            "max_http_requests",
            "wall_timeout_seconds",
            "max_payload_bytes",
            "stake_units",
            "opening_player_units",
            "opening_house_units",
        ):
            _require_integer(name, getattr(self, name))

        _require_range("max_cases", self.max_cases, 1, MAX_CASES)
        _require_range("max_http_requests", self.max_http_requests, 1, MAX_HTTP_REQUESTS)
        _require_range("wall_timeout_seconds", self.wall_timeout_seconds, 1, MAX_WALL_SECONDS)
        _require_range("max_payload_bytes", self.max_payload_bytes, 1, MAX_PAYLOAD_BYTES)
        _require_range("stake_units", self.stake_units, 1, 1000)

        if MAX_PAYLOAD_BYTES > MAX_BODY_BYTES:
            raise SecurityVerificationError(
                "PAYLOAD_BOUND_ABOVE_TRANSPORT_LIMIT",
                "the harness payload bound may not exceed the transport's own body limit",
            )
        if not set(ALLOWED_TARGET_HOSTS) <= set(LOOPBACK_HOSTS):
            raise SecurityVerificationError(
                "TARGET_ALLOWLIST_INVALID",
                "the harness target allowlist must be a subset of the slice's loopback hosts",
            )

        # No name is resolved to decide this. An off-loopback literal and every name string
        # are refused by membership, which is a decision this process can make without
        # touching a resolver, a socket or the network stack.
        if not isinstance(self.host, str) or self.host not in ALLOWED_TARGET_HOSTS:
            raise SecurityVerificationError(
                "TARGET_NOT_LOOPBACK",
                f"the verification target must be one of {list(ALLOWED_TARGET_HOSTS)}",
            )
        if self.port != 0:
            raise SecurityVerificationError(
                "PORT_NOT_EPHEMERAL",
                "the listening port must be 0 so the operating system assigns an ephemeral one",
            )

        if PLANNED_CASE_COUNT > self.max_cases:
            raise SecurityVerificationError(
                "CASE_BUDGET_EXCEEDED",
                f"the plan derives {PLANNED_CASE_COUNT} cases, above the bound of {self.max_cases}",
            )
        if PLANNED_HTTP_REQUEST_COUNT > self.max_http_requests:
            raise SecurityVerificationError(
                "REQUEST_BUDGET_EXCEEDED",
                f"the plan derives {PLANNED_HTTP_REQUEST_COUNT} requests, above the bound of "
                f"{self.max_http_requests}",
            )

        worst_case_stake = self.stake_units * 8
        if worst_case_stake > self.opening_player_units:
            raise SecurityVerificationError(
                "CONFIG_INVALID", "the opening player balance cannot fund the planned stakes"
            )
        if worst_case_stake * 2 > self.opening_house_units:
            raise SecurityVerificationError(
                "CONFIG_INVALID", "the opening house bankroll cannot cover the planned liability"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "port_selection": "ephemeral",
            "target_slice": "apps/roulette_web",
            "route_count": len(ROUTES),
            "bet_type": VERIFIED_BET_TYPE,
            "stake_units": self.stake_units,
            "opening_player_units": self.opening_player_units,
            "opening_house_units": self.opening_house_units,
            "max_cases": self.max_cases,
            "max_http_requests": self.max_http_requests,
            "wall_timeout_seconds": self.wall_timeout_seconds,
            "max_payload_bytes": self.max_payload_bytes,
        }


# ---------------------------------------------------------------------------------------
# bounded ledgers, deadlines and metering
# ---------------------------------------------------------------------------------------


class _Deadline:
    """A monotonic wall bound for the whole run.

    Everything that waits in this file waits against this rather than against a fixed sleep.
    A fixed sleep is a false deadline on a slow machine and wasted time on a fast one, and a
    result that depends on one is not deterministic.
    """

    def __init__(self, seconds: float) -> None:
        self._end = time.perf_counter() + float(seconds)

    def remaining(self) -> float:
        return self._end - time.perf_counter()

    def check(self, stage: str) -> None:
        if self.remaining() <= 0.0:
            raise SecurityVerificationError(
                "WALL_DEADLINE_EXCEEDED", f"the verification exceeded its wall bound at {stage}"
            )

    def budget(self, stage: str) -> float:
        self.check(stage)
        return min(max(self.remaining(), 0.001), float(MAX_WALL_SECONDS))


class _CaseLedger:
    """Every case and every request, counted against the configured ceilings.

    The bounds are enforced twice on purpose. Preflight refuses a plan that could not fit;
    this refuses the request that would actually cross the line, so a coding mistake that
    made the run larger than its plan stops at the bound rather than at the plan.
    """

    def __init__(self, config: VerificationConfig) -> None:
        self._config = config
        self.cases: list[dict[str, Any]] = []
        self.http_requests = 0

    def spend_request(self) -> None:
        if self.http_requests + 1 > self._config.max_http_requests:
            raise SecurityVerificationError(
                "REQUEST_BUDGET_EXCEEDED",
                f"the run reached its bound of {self._config.max_http_requests} HTTP requests",
            )
        self.http_requests += 1

    def record(self, case_id: str, group: str, expectation: str, held: bool, detail: str) -> bool:
        if len(self.cases) + 1 > self._config.max_cases:
            raise SecurityVerificationError(
                "CASE_BUDGET_EXCEEDED",
                f"the run reached its bound of {self._config.max_cases} cases",
            )
        self.cases.append(
            {
                "case_id": case_id,
                "group": group,
                "expectation": expectation,
                "held": bool(held),
                "detail": detail,
            }
        )
        return bool(held)

    def group_holds(self, group: str) -> bool:
        entries = [case for case in self.cases if case["group"] == group]
        return bool(entries) and all(case["held"] for case in entries)

    def failed(self) -> list[dict[str, Any]]:
        return [case for case in self.cases if not case["held"]]


class _CountingEntropySource:
    """The OS CSPRNG, counted. Bytes are passed through and never retained.

    Entropy *consumption* is the evidence that a replayed submission never reaches the
    sampler, and the contract forbids instrumenting the observed runtime to obtain it.
    Wrapping the approved source and injecting it through ``open_table``'s existing
    ``entropy_source`` parameter satisfies both: the slice is unmodified, and the only thing
    recorded is how many reads happened and how many bytes they totalled. No byte, seed or
    rejection value is kept, so nothing here can become a leak of the material
    ``studio_core.rng`` never records in the first place.
    """

    source_id = OsCsprngEntropySource.source_id
    is_deterministic = OsCsprngEntropySource.is_deterministic

    def __init__(self) -> None:
        self._inner = OsCsprngEntropySource()
        self._lock = threading.Lock()
        self._reads = 0
        self._bytes = 0

    def read(self, size: int) -> bytes:
        data = self._inner.read(size)
        with self._lock:
            self._reads += 1
            self._bytes += len(data)
        return data

    def meter(self) -> tuple[int, int]:
        """Return ``(reads, bytes)`` consumed so far. Counts only; never the material."""

        with self._lock:
            return self._reads, self._bytes


class _WorkerThreads:
    """The request-serving threads the observed server started, so they can be joined.

    ``ThreadingHTTPServer`` serves every accepted connection on its own thread and the slice
    sets ``daemon_threads``, so ``socketserver`` keeps no list of them and ``server_close``
    joins none. That is the right trade for a launcher that exits with the process and the
    wrong one for a harness that has to know the last worker has finished before it closes
    the store and deletes the directory the database lives in.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def enrol(self) -> None:
        with self._lock:
            self._threads.append(threading.current_thread())

    def snapshot(self) -> tuple[threading.Thread, ...]:
        with self._lock:
            return tuple(self._threads)

    def started(self) -> int:
        with self._lock:
            return len(self._threads)


def _releasing_handler(handler_class: type, store: Any, workers: _WorkerThreads) -> type:
    """Return ``handler_class`` with worker enrolment and a per-thread connection release.

    Two lines of behaviour, both about resource ownership and neither about the request.
    ``setup`` is the first thing the server runs on a worker thread, so a worker cannot exist
    without being on the list the shutdown path joins. ``handle`` returns when the worker is
    done with the table, and by then that worker may hold a connection to the verification
    database that only it is allowed to close; releasing it in a ``finally`` covers the
    refusal and exception paths as well as the successful one, and is a no-op for a worker
    that never touched the store.

    Nothing here reads or writes a request, a response, a header or a status, and no file in
    the observed slice is modified: the subclass is assembled here and installed through
    ``socketserver``'s published ``RequestHandlerClass`` attribute.
    """

    class _ReleasingHandler(handler_class):  # type: ignore[misc, valid-type]
        def setup(self) -> None:
            workers.enrol()
            super().setup()

        def handle(self) -> None:
            try:
                super().handle()
            finally:
                store.release_thread_connection()

    return _ReleasingHandler


# ---------------------------------------------------------------------------------------
# request execution
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Response:
    """One completed response, reduced to what a security assertion may look at."""

    status: int
    body: dict[str, Any]
    text: str

    @property
    def error_code(self) -> str:
        error = self.body.get("error")
        if isinstance(error, Mapping) and isinstance(error.get("code"), str):
            return str(error["code"])
        return "NONE"


class _Client:
    """A bounded loopback client. Every request it issues is counted before it is sent."""

    def __init__(self, host: str, port: int, ledger: _CaseLedger, deadline: _Deadline, limit: int) -> None:
        self._host = host
        self._port = port
        self._ledger = ledger
        self._deadline = deadline
        self._limit = limit
        #: Every response this client received, so the confidentiality scan runs over what was
        #: actually returned rather than over the subset an author remembered to collect.
        self.responses: list[_Response] = []

    def json_call(
        self, method: str, path: str, body: Mapping[str, Any] | None, stage: str
    ) -> _Response:
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"Accept": "application/json", "Connection": "close"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        return self.raw_call(method, path, headers, payload, stage)

    def raw_call(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        payload: bytes | None,
        stage: str,
        *,
        declared_length: int | None = None,
    ) -> _Response:
        """Issue one request on its own connection and return the response.

        A fresh connection per request, and ``Connection: close`` on every one of them: a
        kept-alive socket would leave a handler thread parked on a read after the run is
        over, and on Windows that thread's SQLite handle is what keeps the temporary database
        file locked. The response body is read to exhaustion and the response is closed
        explicitly, ahead of the connection that owns it.

        ``declared_length`` exists for the single malformed case that declares a
        ``Content-Length`` larger than the transport accepts. The declared value is a header,
        not a body: the bytes actually put on the wire stay inside the configured payload
        bound, which is what makes an oversize refusal observable without ever sending an
        oversize payload.
        """

        if payload is not None and len(payload) > self._limit:
            raise SecurityVerificationError(
                "PAYLOAD_BOUND_EXCEEDED",
                f"{stage} would send {len(payload)} bytes, above the bound of {self._limit}",
            )
        self._ledger.spend_request()
        timeout = self._deadline.budget(stage)

        connection = http.client.HTTPConnection(self._host, self._port, timeout=timeout)
        try:
            connection.putrequest(method, path, skip_accept_encoding=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            if declared_length is not None:
                connection.putheader("Content-Length", str(declared_length))
            elif payload is not None:
                connection.putheader("Content-Length", str(len(payload)))
            connection.endheaders()
            if payload:
                connection.send(payload)
            response = connection.getresponse()
            try:
                raw = response.read()
                status = int(response.status)
            finally:
                response.close()
        finally:
            connection.close()

        text = raw.decode("utf-8", errors="replace")
        try:
            decoded = json.loads(text) if text else {}
        except json.JSONDecodeError:
            decoded = {}
        if not isinstance(decoded, dict):
            decoded = {}
        response = _Response(status=status, body=decoded, text=text)
        self.responses.append(response)
        return response


# ---------------------------------------------------------------------------------------
# snapshots and small inspectors
# ---------------------------------------------------------------------------------------


def _mutation_snapshot(table: Any, store: DurableRoundStore) -> dict[str, Any]:
    """Return exactly the authoritative values AC-004 requires to be unchanged by a refusal.

    Round identifier and phase, the integer player balance, the house bankroll, the bet list,
    the committed draw record count, the committed ledger transaction count and the committed
    audit event count. Taken through the table's own reader and the store's own counter, so
    the snapshot is the authoritative state and not a client's view of it.
    """

    state = table.state()
    round_state = state["round"]
    return {
        "round_id": round_state["round_id"],
        "phase": round_state["phase"],
        "balance_units": state["balance_units"],
        "house_bankroll_units": state["house_bankroll_units"],
        "bets": json.dumps(round_state["bets"], ensure_ascii=False, sort_keys=True),
        "draw_records": store.count("draw_record"),
        "ledger_transactions": store.count("ledger_transaction"),
        "audit_events": store.count("audit_event"),
    }


def _find_floats(value: Any, path: str = "$") -> list[str]:
    """Return the JSON paths of every float inside ``value``.

    Currency is integer minimum units everywhere in this system, so the useful check is not
    "the balance is an int" but "no float exists anywhere in this payload", which keeps
    working when a field nobody thought to check is added.
    """

    found: list[str] = []
    if isinstance(value, float):
        found.append(path)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            found.extend(_find_floats(item, f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(_find_floats(item, f"{path}[{index}]"))
    return found


def _keys_present(value: Any, names: Iterable[str]) -> list[str]:
    """Return which of ``names`` appear as an object key anywhere inside ``value``.

    Keys are matched, never the serialised text. A substring search would report the audit
    event's ``rng-entropy://`` resource reference -- which names the entropy *authority* and
    is required by ``games/roulette/rng-contract.yaml`` -- as a leak, and a check that cries
    wolf on a required field is a check that gets switched off.
    """

    wanted = {name.lower() for name in names}
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            found.update(key for key in node if isinstance(key, str) and key.lower() in wanted)
            for item in node.values():
                walk(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)

    walk(value)
    return sorted(found)


def _key_paths(value: Any, name: str, path: str = "$") -> list[str]:
    """Return the JSON paths at which ``name`` appears as an object key inside ``value``."""

    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}"
            if key == name:
                found.append(child)
            found.extend(_key_paths(item, name, child))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(_key_paths(item, name, f"{path}[{index}]"))
    return found


def _entropy_material_hits(text: str) -> list[str]:
    """Return the names of the entropy-material shapes found in ``text``, never the matches."""

    return sorted(
        name for name, pattern in ENTROPY_MATERIAL_PATTERNS if re.search(pattern, text) is not None
    )


def _prohibited_markers(text: str) -> list[str]:
    lowered = text.lower()
    return sorted(marker for marker in PROHIBITED_RESPONSE_MARKERS if marker in lowered)


# ---------------------------------------------------------------------------------------
# case tables -- fixed, finite, deterministic, non-destructive
# ---------------------------------------------------------------------------------------

#: A synthetic value for each server-authoritative field name, chosen only so the forged
#: request is well formed. None of these is a real balance, result or secret.
_FORGED_VALUES: dict[str, Any] = {
    "balance_units": 999_999,
    "color": "red",
    "color_label": "빨강",
    "house_bankroll_units": 999_999,
    "net_change_units": 4242,
    "payout_units": 4242,
    "pocket": 17,
    "pocket_label": "17",
    "proof_hash": "sha256:" + "0" * 64,
    "recent_results": [],
    "result": {"pocket": 17},
    "total_return_units": 4242,
    "won": True,
}


def _forged_value(field: str) -> Any:
    return _FORGED_VALUES.get(field, "forged")


#: Every malformed case, declared as data. Fixed inputs only: nothing here is generated at
#: random, derived from a clock, or repeated to produce load. Each entry is
#: ``(case_id, method, path, headers, body bytes, declared length, expected code)``.
MALFORMED_CASES: tuple[dict[str, Any], ...] = (
    {
        "case_id": "SEC-MAL-01",
        "description": "body is a JSON array rather than an object",
        "method": "POST",
        "path": "/api/bets",
        "body": b'[1, 2, 3]',
        "expected": "BAD_JSON",
    },
    {
        "case_id": "SEC-MAL-02",
        "description": "body is not valid UTF-8",
        "method": "POST",
        "path": "/api/bets",
        "body": b"\xff\xfe{}",
        "expected": "BAD_JSON",
    },
    {
        "case_id": "SEC-MAL-03",
        "description": "body is truncated JSON",
        "method": "POST",
        "path": "/api/spin",
        "body": b'{"request_id":',
        "expected": "BAD_JSON",
    },
    {
        "case_id": "SEC-MAL-04",
        "description": "a fractional stake is offered where integer minimum units are required",
        "method": "POST",
        "path": "/api/bets",
        "body": b'{"request_id":"R2SEC-MALFORMED-0004","bet":{"type":"red","selections":[],"stake_units":1.5}}',
        "expected": "BAD_JSON",
    },
    {
        "case_id": "SEC-MAL-05",
        "description": "an undeclared body length is offered as chunked transfer encoding",
        "method": "POST",
        "path": "/api/spin",
        "headers": {"Transfer-Encoding": "chunked"},
        "body": None,
        "expected": "LENGTH_REQUIRED",
    },
    {
        "case_id": "SEC-MAL-06",
        "description": "a declared body length above the transport limit, with no oversize body sent",
        "method": "POST",
        "path": "/api/spin",
        "body": b"{}",
        "declared_length": MAX_BODY_BYTES + 1,
        "expected": "PAYLOAD_TOO_LARGE",
    },
    {
        "case_id": "SEC-MAL-07",
        "description": "an unknown top-level field on a bet request",
        "method": "POST",
        "path": "/api/bets",
        "body": b'{"request_id":"R2SEC-MALFORMED-0007","bet":{"type":"red","selections":[],"stake_units":1},"wager":1}',
        "expected": "BAD_REQUEST",
    },
    {
        "case_id": "SEC-MAL-08",
        "description": "a request identifier below the accepted shape",
        "method": "POST",
        "path": "/api/spin",
        "body": b'{"request_id":"short"}',
        "expected": "REQUEST_ID_INVALID",
    },
    {
        "case_id": "SEC-MAL-09",
        "description": "a method the route does not accept",
        "method": "PUT",
        "path": "/api/state",
        "body": None,
        "expected": "METHOD_NOT_ALLOWED",
    },
    {
        "case_id": "SEC-MAL-10",
        "description": "a percent-encoded traversal attempt against the static surface",
        "method": "GET",
        "path": "/%2e%2e/%2e%2e/pyproject.toml",
        "body": None,
        "expected": "NOT_FOUND",
    },
    {
        "case_id": "SEC-MAL-11",
        "description": "a plain traversal attempt against the static surface",
        "method": "GET",
        "path": "/../../pyproject.toml",
        "body": None,
        "expected": "NOT_FOUND",
    },
    {
        "case_id": "SEC-MAL-12",
        "description": "an unknown route",
        "method": "GET",
        "path": "/api/not-a-route",
        "body": None,
        "expected": "NOT_FOUND",
    },
    {
        "case_id": "SEC-MAL-13",
        "description": "a normal read after every malformed case, showing the surface still works",
        "method": "GET",
        "path": "/api/state",
        "body": None,
        "expected": "NONE",
        "expect_ok": True,
    },
)


# ---------------------------------------------------------------------------------------
# dimension 1: client authority forgery
# ---------------------------------------------------------------------------------------


def _bet_body(request_id: str, stake: int, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    bet: dict[str, Any] = {"type": VERIFIED_BET_TYPE, "selections": [], "stake_units": stake}
    if extra:
        bet.update(extra)
    return {"request_id": request_id, "bet": bet}


def _check_client_authority(
    client: _Client, table: Any, store: DurableRoundStore, ledger: _CaseLedger, config: VerificationConfig
) -> dict[str, Any]:
    """Every declared authority field, at a nested position, refused without moving state."""

    group = "client_authority_forgery_denial"
    covered: list[str] = []
    for index, field in enumerate(sorted(CLIENT_AUTHORITY_FIELDS), start=1):
        before = _mutation_snapshot(table, store)
        body = _bet_body(
            f"R2SEC-AUTHORITY-{index:04d}", config.stake_units, {field: _forged_value(field)}
        )
        response = client.json_call("POST", "/api/bets", body, f"authority[{index}]")
        after = _mutation_snapshot(table, store)
        held = (
            response.status == 400
            and response.error_code == "CLIENT_AUTHORITY_DENIED"
            and before == after
        )
        covered.append(field)
        ledger.record(
            f"SEC-AUTH-{index:02d}",
            group,
            f"a nested {field!r} is refused with CLIENT_AUTHORITY_DENIED and moves nothing",
            held,
            f"status={response.status} code={response.error_code} snapshot_unchanged={before == after}",
        )

    # Top-level placement, and a placement buried inside a list inside a mapping. The server's
    # walk is supposed to be position-independent; these two say so out loud.
    before = _mutation_snapshot(table, store)
    response = client.json_call(
        "POST",
        "/api/spin",
        {"request_id": "R2SEC-AUTHORITY-TOPLEVEL", "pocket": 17},
        "authority[top-level]",
    )
    after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-AUTH-14",
        group,
        "a top-level authority field is refused with CLIENT_AUTHORITY_DENIED and moves nothing",
        response.status == 400 and response.error_code == "CLIENT_AUTHORITY_DENIED" and before == after,
        f"status={response.status} code={response.error_code} snapshot_unchanged={before == after}",
    )

    before = _mutation_snapshot(table, store)
    response = client.json_call(
        "POST",
        "/api/bets",
        {
            "request_id": "R2SEC-AUTHORITY-DEEPNEST",
            "bet": {"type": VERIFIED_BET_TYPE, "selections": [], "stake_units": config.stake_units},
            "context": {"history": [{"depth": 3, "payout_units": 4242}]},
        },
        "authority[deep-nested]",
    )
    after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-AUTH-15",
        group,
        "an authority field nested inside a list inside a mapping is refused and moves nothing",
        response.status == 400 and response.error_code == "CLIENT_AUTHORITY_DENIED" and before == after,
        f"status={response.status} code={response.error_code} snapshot_unchanged={before == after}",
    )

    return {
        "declared_authority_fields": len(CLIENT_AUTHORITY_FIELDS),
        "authority_fields_covered": len(covered),
        "every_declared_field_covered": sorted(covered) == sorted(CLIENT_AUTHORITY_FIELDS),
        "nested_placement_covered": True,
        "top_level_placement_covered": True,
        "list_nested_placement_covered": True,
    }


# ---------------------------------------------------------------------------------------
# dimension 2: betting phase and lock bypass
# ---------------------------------------------------------------------------------------


def _check_phase_and_lock(
    client: _Client, table: Any, store: DurableRoundStore, ledger: _CaseLedger, config: VerificationConfig
) -> dict[str, Any]:
    """Bets are accepted only in the declared phase, and no body field may change the phase."""

    group = "betting_phase_lock_bypass_denial"

    # A bet in the declared phase is accepted. Without this the whole dimension could be
    # satisfied by a surface that refuses everything.
    before = _mutation_snapshot(table, store)
    accepted = client.json_call(
        "POST", "/api/bets", _bet_body("R2SEC-PHASE-OPEN-0001", config.stake_units), "phase[open]"
    )
    ledger.record(
        "SEC-PHASE-01",
        group,
        f"a bet in {BETS_ACCEPTED_IN.value} is accepted",
        accepted.status == 200 and accepted.body.get("accepted") is True,
        f"status={accepted.status} phase_before={before['phase']}",
    )

    # Two attempts to name a phase or a closing instant in the body. Both are refused as
    # protocol faults, and neither is quietly dropped: a field that is silently ignored is a
    # field a later refactor might start honouring.
    for index, (case_id, field, value) in enumerate(
        (
            ("SEC-PHASE-02", "phase", "OPEN"),
            ("SEC-PHASE-03", "betting_closes_at", "2999-01-01T00:00:00Z"),
        ),
        start=1,
    ):
        snapshot_before = _mutation_snapshot(table, store)
        response = client.json_call(
            "POST",
            "/api/bets",
            {
                "request_id": f"R2SEC-PHASEFIELD-{index:04d}",
                "bet": {"type": VERIFIED_BET_TYPE, "selections": [], "stake_units": config.stake_units},
                field: value,
            },
            f"phase[field-{index}]",
        )
        snapshot_after = _mutation_snapshot(table, store)
        ledger.record(
            case_id,
            group,
            f"a top-level {field!r} is refused with BAD_REQUEST and moves nothing",
            response.status == 400
            and response.error_code == "BAD_REQUEST"
            and snapshot_before == snapshot_after,
            f"status={response.status} code={response.error_code} "
            f"snapshot_unchanged={snapshot_before == snapshot_after}",
        )

    snapshot_before = _mutation_snapshot(table, store)
    response = client.json_call(
        "POST",
        "/api/bets",
        _bet_body("R2SEC-PHASEBET-0001", config.stake_units, {"phase": "OPEN"}),
        "phase[bet-field]",
    )
    snapshot_after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-PHASE-04",
        group,
        "a phase field inside the bet object is refused with BET_INVALID and moves nothing",
        response.status == 400
        and response.error_code == "BET_INVALID"
        and snapshot_before == snapshot_after,
        f"status={response.status} code={response.error_code} "
        f"snapshot_unchanged={snapshot_before == snapshot_after}",
    )

    # A new round while the current one is still open is refused: the client may not skip a
    # round to escape a phase it dislikes.
    snapshot_before = _mutation_snapshot(table, store)
    response = client.json_call(
        "POST", "/api/new-round", {"request_id": "R2SEC-PHASENEW-0001"}, "phase[new-round]"
    )
    snapshot_after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-PHASE-05",
        group,
        "a new round is refused with ROUND_IN_PROGRESS while the current round is not terminal",
        response.status == 409
        and response.error_code == "ROUND_IN_PROGRESS"
        and snapshot_before == snapshot_after,
        f"status={response.status} code={response.error_code} "
        f"snapshot_unchanged={snapshot_before == snapshot_after}",
    )

    # Drive the round to a terminal phase, then try to bet and spin into it.
    settled = client.json_call(
        "POST", "/api/spin", {"request_id": "R2SEC-PHASESPIN-0001"}, "phase[spin]"
    )
    ledger.record(
        "SEC-PHASE-06",
        group,
        "the open round settles once so a terminal phase exists to be tested against",
        settled.status == 200 and settled.body.get("accepted") is True,
        f"status={settled.status} code={settled.error_code}",
    )

    snapshot_before = _mutation_snapshot(table, store)
    response = client.json_call(
        "POST", "/api/bets", _bet_body("R2SEC-PHASELATE-0001", config.stake_units), "phase[late-bet]"
    )
    snapshot_after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-PHASE-07",
        group,
        "a bet after the round left the accepting phase is refused with PHASE_DENIED and moves nothing",
        response.status == 409
        and response.error_code == "PHASE_DENIED"
        and snapshot_before == snapshot_after,
        f"status={response.status} code={response.error_code} "
        f"snapshot_unchanged={snapshot_before == snapshot_after}",
    )

    snapshot_before = _mutation_snapshot(table, store)
    response = client.json_call(
        "POST", "/api/spin", {"request_id": "R2SEC-PHASERESPIN-0001"}, "phase[respin]"
    )
    snapshot_after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-PHASE-08",
        group,
        "a second spin of a settled round is refused with PHASE_DENIED and moves nothing",
        response.status == 409
        and response.error_code == "PHASE_DENIED"
        and snapshot_before == snapshot_after,
        f"status={response.status} code={response.error_code} "
        f"snapshot_unchanged={snapshot_before == snapshot_after}",
    )

    return {
        "bets_accepted_in": BETS_ACCEPTED_IN.value,
        "phase_named_in_body_refused": True,
        "closing_instant_named_in_body_refused": True,
        "late_bet_refused": True,
        "second_spin_refused": True,
    }


# ---------------------------------------------------------------------------------------
# dimension 3: idempotency and settlement replay
# ---------------------------------------------------------------------------------------


def _spin_identity(body: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    result = body.get("result")
    if not isinstance(result, Mapping):
        return (None, None, None)
    return (
        result.get("settlement_transaction_id"),
        result.get("pocket"),
        result.get("round_id"),
    )


def _check_idempotency(
    client: _Client,
    table: Any,
    store: DurableRoundStore,
    ledger: _CaseLedger,
    entropy: _CountingEntropySource,
    config: VerificationConfig,
) -> dict[str, Any]:
    """A repeated identifier commits once; a conflicting one commits nothing."""

    group = "idempotency_and_settlement_replay_safety"

    opened = client.json_call(
        "POST", "/api/new-round", {"request_id": "R2SEC-IDEMNEW-0001"}, "idempotency[new-round]"
    )
    ledger.record(
        "SEC-IDEM-01",
        group,
        "a fresh round opens once the previous one is terminal",
        opened.status == 200 and opened.body.get("accepted") is True,
        f"status={opened.status} code={opened.error_code}",
    )

    bet = client.json_call(
        "POST", "/api/bets", _bet_body("R2SEC-IDEMBET-0001", config.stake_units), "idempotency[bet]"
    )
    ledger.record(
        "SEC-IDEM-02",
        group,
        "one bet is placed on the fresh round",
        bet.status == 200 and bet.body.get("accepted") is True,
        f"status={bet.status} code={bet.error_code}",
    )

    before_reads, before_bytes = entropy.meter()
    before = _mutation_snapshot(table, store)
    spin_request_id = "R2SEC-IDEMSPIN-0001"
    first = client.json_call(
        "POST", "/api/spin", {"request_id": spin_request_id}, "idempotency[spin-1]"
    )
    after_first = _mutation_snapshot(table, store)
    first_reads, first_bytes = entropy.meter()
    ledger.record(
        "SEC-IDEM-03",
        group,
        "the first submission commits exactly one draw and one settlement",
        first.status == 200
        and first.body.get("replayed") is False
        and after_first["draw_records"] == before["draw_records"] + 1
        and after_first["ledger_transactions"] == before["ledger_transactions"] + 1
        and first_reads > before_reads,
        f"status={first.status} draw_delta={after_first['draw_records'] - before['draw_records']} "
        f"ledger_delta={after_first['ledger_transactions'] - before['ledger_transactions']} "
        f"entropy_read_delta={first_reads - before_reads}",
    )

    repeats: list[_Response] = []
    for attempt in (2, 3):
        repeats.append(
            client.json_call(
                "POST", "/api/spin", {"request_id": spin_request_id}, f"idempotency[spin-{attempt}]"
            )
        )
    after_repeat = _mutation_snapshot(table, store)
    repeat_reads, repeat_bytes = entropy.meter()
    identities = sorted(
        {_spin_identity(first.body)} | {_spin_identity(item.body) for item in repeats},
        key=repr,
    )
    ledger.record(
        "SEC-IDEM-04",
        group,
        "repeating the identifier draws nothing further, consumes no entropy and commits nothing further",
        all(item.status == 200 and item.body.get("replayed") is True for item in repeats)
        and after_repeat["draw_records"] == after_first["draw_records"]
        and after_repeat["ledger_transactions"] == after_first["ledger_transactions"]
        and after_repeat["balance_units"] == after_first["balance_units"]
        and after_repeat["audit_events"] == after_first["audit_events"]
        and repeat_reads == first_reads
        and repeat_bytes == first_bytes,
        f"replays={sum(1 for item in repeats if item.body.get('replayed') is True)} "
        f"draw_delta={after_repeat['draw_records'] - after_first['draw_records']} "
        f"ledger_delta={after_repeat['ledger_transactions'] - after_first['ledger_transactions']} "
        f"balance_delta={after_repeat['balance_units'] - after_first['balance_units']} "
        f"audit_delta={after_repeat['audit_events'] - after_first['audit_events']} "
        f"entropy_read_delta={repeat_reads - first_reads}",
    )
    ledger.record(
        "SEC-IDEM-05",
        group,
        "every caller of the repeated identifier observes one identical commit",
        len(identities) == 1 and None not in identities[0],
        f"distinct_commit_identities={len(identities)}",
    )

    # A reused identifier carrying different parameters. The journal fingerprint covers the
    # route and the payload, so the same key on a different route is a genuine conflict.
    snapshot_before = _mutation_snapshot(table, store)
    conflict = client.json_call(
        "POST", "/api/spin", {"request_id": "R2SEC-IDEMBET-0001"}, "idempotency[conflict-route]"
    )
    snapshot_after = _mutation_snapshot(table, store)
    ledger.record(
        "SEC-IDEM-06",
        group,
        "a reused identifier with different parameters is refused with REQUEST_ID_CONFLICT and commits nothing",
        conflict.status == 409
        and conflict.error_code == "REQUEST_ID_CONFLICT"
        and snapshot_before == snapshot_after,
        f"status={conflict.status} code={conflict.error_code} "
        f"commits_unchanged={snapshot_before == snapshot_after}",
    )

    # Two direct store-boundary cases. The HTTP journal answers a duplicate from memory, so
    # the durable replay path is only reachable from the boundary itself -- and that path is
    # the one that has to survive a restart.
    record = store.draw_record(spin_request_id)
    boundary_before = _mutation_snapshot(table, store)
    boundary_reads, boundary_bytes = entropy.meter()
    replayed = store.submit_round(
        DrawRequest(request_id=spin_request_id, round_id=record.round_id if record else "RR-SEC-MISSING")
    )
    boundary_after = _mutation_snapshot(table, store)
    after_reads, after_bytes = entropy.meter()
    ledger.record(
        "SEC-IDEM-07",
        group,
        "the durable boundary replays a committed submission without drawing or settling again",
        replayed.replayed is True
        and record is not None
        and replayed.record.pocket == record.pocket
        and boundary_after["draw_records"] == boundary_before["draw_records"]
        and boundary_after["ledger_transactions"] == boundary_before["ledger_transactions"]
        and after_reads == boundary_reads
        and after_bytes == boundary_bytes,
        f"replayed={replayed.replayed} draw_delta="
        f"{boundary_after['draw_records'] - boundary_before['draw_records']} "
        f"ledger_delta={boundary_after['ledger_transactions'] - boundary_before['ledger_transactions']} "
        f"entropy_read_delta={after_reads - boundary_reads}",
    )

    conflict_before = _mutation_snapshot(table, store)
    conflict_reads, _ = entropy.meter()
    denied_code = "NONE"
    try:
        store.submit_round(DrawRequest(request_id=spin_request_id, round_id="RR-SEC-BOUNDARY-0001"))
    except RngDenied as denied:
        denied_code = denied.code
    conflict_after = _mutation_snapshot(table, store)
    conflict_after_reads, _ = entropy.meter()
    ledger.record(
        "SEC-IDEM-08",
        group,
        "the durable boundary refuses a reused identifier with different parameters and commits nothing",
        denied_code == "DUPLICATE_REQUEST_CONFLICT"
        and conflict_after["draw_records"] == conflict_before["draw_records"]
        and conflict_after["ledger_transactions"] == conflict_before["ledger_transactions"]
        and conflict_after["balance_units"] == conflict_before["balance_units"]
        and conflict_after_reads == conflict_reads,
        f"code={denied_code} draw_delta="
        f"{conflict_after['draw_records'] - conflict_before['draw_records']} "
        f"ledger_delta={conflict_after['ledger_transactions'] - conflict_before['ledger_transactions']} "
        f"entropy_read_delta={conflict_after_reads - conflict_reads}",
    )

    return {
        "spin_submissions": 3,
        "fresh_commits": 1,
        "replays": 2,
        "distinct_commit_identities": len(identities),
        "conflicting_submissions_refused": 2,
        "entropy_reads_during_replay": repeat_reads - first_reads,
        "entropy_bytes_during_replay": repeat_bytes - first_bytes,
        "entropy_material_recorded": False,
        "committed_spin_request_id_recorded": False,
    }


# ---------------------------------------------------------------------------------------
# dimension 4: audit tamper and deletion detection, on a disposable copy
# ---------------------------------------------------------------------------------------


def _repository_audit_records() -> list[str]:
    """Return the repository-relative audit records whose immutability this run evidences."""

    found = ["audit/audit-event.schema.json"]
    events_dir = _REPO_ROOT / "audit" / "events"
    if events_dir.is_dir():
        found.extend(
            f"audit/events/{path.name}" for path in sorted(events_dir.glob("*.json")) if path.is_file()
        )
    return [relative for relative in found if (_REPO_ROOT / relative).is_file()]


def _hash_repository_audit_records(relatives: Sequence[str]) -> dict[str, str]:
    return {relative: hash_file(_REPO_ROOT / relative) for relative in relatives}


def _copy_database(database: str, destination_dir: str) -> str:
    """Copy the run's own database, and its sidecars if any, into a disposable directory."""

    os.makedirs(destination_dir, exist_ok=True)
    target = os.path.join(destination_dir, "audit-copy.sqlite3")
    shutil.copy2(database, target)
    for suffix in ("-wal", "-shm"):
        sidecar = database + suffix
        if os.path.exists(sidecar):
            shutil.copy2(sidecar, target + suffix)
    return target


def _events_from(path: str) -> list[dict[str, Any]]:
    with contextlib.closing(sqlite3.connect(path, uri=False)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT body_json FROM audit_event ORDER BY event_seq").fetchall()
    return [json.loads(row["body_json"]) for row in rows]


def _check_audit_tamper(
    workspace: str, database: str, ledger: _CaseLedger, original_events: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Forge and delete audit events -- on a copy, always on a copy, and never on the original.

    Two things are established here and they are different claims. The first is that the
    stored chain refuses to be edited at all: the append-only triggers abort an ``UPDATE`` and
    a ``DELETE`` on the copy, so tampering is not merely detectable but blocked. The second is
    that if the triggers were gone -- which is what an attacker with file access would arrange
    -- the chain still gives the edit away, because ``verify_audit_chain`` recomputes every
    event hash and every link. Only the second needs the triggers dropped, and it is done on a
    second, separate copy so the first copy's evidence stays intact.
    """

    group = "audit_event_tamper_and_delete_detection_on_copy"
    copy_root = os.path.join(workspace, "audit-copies")
    original_hash_before = hash_file(database)
    repository_records = _repository_audit_records()
    repository_before = _hash_repository_audit_records(repository_records)

    # -- the copy is a faithful, verifying chain before anything is done to it --------------
    guard_copy = _copy_database(database, os.path.join(copy_root, "guard"))
    copied_events = _events_from(guard_copy)
    ledger.record(
        "SEC-AUDIT-01",
        group,
        "the disposable copy holds the same chain as the original and verifies clean",
        len(copied_events) == len(original_events)
        and verify_audit_chain(copied_events) == []
        and len(copied_events) >= 3,
        f"events={len(copied_events)} problems={len(verify_audit_chain(copied_events))}",
    )

    # -- append-only enforcement, exercised on the copy -------------------------------------
    update_refused = False
    delete_refused = False
    with contextlib.closing(sqlite3.connect(guard_copy, uri=False)) as connection:
        try:
            connection.execute("UPDATE audit_event SET action = 'FORGED' WHERE event_seq = 1")
        except sqlite3.DatabaseError:
            update_refused = True
        try:
            connection.execute("DELETE FROM audit_event WHERE event_seq = 1")
        except sqlite3.DatabaseError:
            delete_refused = True
        connection.rollback()
    ledger.record(
        "SEC-AUDIT-02",
        group,
        "an UPDATE against a stored audit event is refused by the append-only guard",
        update_refused,
        f"update_refused={update_refused}",
    )
    ledger.record(
        "SEC-AUDIT-03",
        group,
        "a DELETE against a stored audit event is refused by the append-only guard",
        delete_refused,
        f"delete_refused={delete_refused}",
    )

    # -- detection when the guard itself is gone --------------------------------------------
    forged_copy = _copy_database(database, os.path.join(copy_root, "forged"))
    with contextlib.closing(sqlite3.connect(forged_copy, uri=False)) as connection:
        connection.execute("DROP TRIGGER audit_event_is_append_only_update")
        connection.execute("DROP TRIGGER audit_event_is_append_only_delete")
        row = connection.execute(
            "SELECT event_seq, body_json FROM audit_event ORDER BY event_seq LIMIT 1"
        ).fetchone()
        body = json.loads(row[1])
        body["action"] = "ROULETTE_RNG_DRAW_FORGED"
        connection.execute(
            "UPDATE audit_event SET body_json = ? WHERE event_seq = ?", (json.dumps(body), row[0])
        )
        connection.commit()
    forged_problems = verify_audit_chain(_events_from(forged_copy))
    ledger.record(
        "SEC-AUDIT-04",
        group,
        "a forged event body is reported by verify_audit_chain on the copy",
        len(forged_problems) > 0,
        f"problems={len(forged_problems)}",
    )

    deleted_copy = _copy_database(database, os.path.join(copy_root, "deleted"))
    with contextlib.closing(sqlite3.connect(deleted_copy, uri=False)) as connection:
        connection.execute("DROP TRIGGER audit_event_is_append_only_update")
        connection.execute("DROP TRIGGER audit_event_is_append_only_delete")
        # A middle event, so the deletion breaks a link rather than truncating the chain.
        connection.execute(
            "DELETE FROM audit_event WHERE event_seq = "
            "(SELECT event_seq FROM audit_event ORDER BY event_seq LIMIT 1 OFFSET 1)"
        )
        connection.commit()
    deleted_events = _events_from(deleted_copy)
    deleted_problems = verify_audit_chain(deleted_events)
    ledger.record(
        "SEC-AUDIT-05",
        group,
        "a deleted event is reported by verify_audit_chain on the copy",
        len(deleted_problems) > 0 and len(deleted_events) == len(original_events) - 1,
        f"problems={len(deleted_problems)} remaining_events={len(deleted_events)}",
    )

    original_hash_after = hash_file(database)
    repository_after = _hash_repository_audit_records(repository_records)
    manipulated = [
        os.path.relpath(path, workspace).replace("\\", "/")
        for path in (guard_copy, forged_copy, deleted_copy)
    ]
    return {
        "manipulation_performed_on": "disposable_copies_inside_the_temporary_workspace",
        "manipulated_paths_relative_to_workspace": manipulated,
        "every_manipulated_path_is_inside_the_workspace": all(
            not entry.startswith("..") and not os.path.isabs(entry) for entry in manipulated
        ),
        "original_database_hash_unchanged": original_hash_before == original_hash_after,
        "repository_audit_records_checked": len(repository_records),
        "repository_audit_records_unchanged": repository_before == repository_after,
        "append_only_guard_refuses_update": update_refused,
        "append_only_guard_refuses_delete": delete_refused,
        "forged_copy_problems": len(forged_problems),
        "deleted_copy_problems": len(deleted_problems),
    }


# ---------------------------------------------------------------------------------------
# dimension 5: seed reference confidentiality
# ---------------------------------------------------------------------------------------


def _check_confidentiality(
    ledger: _CaseLedger,
    responses: Sequence[_Response],
    draw_records: Sequence[Mapping[str, Any]],
    audit_events: Sequence[Mapping[str, Any]],
    partial_record: Mapping[str, Any],
) -> dict[str, Any]:
    """No entropy material anywhere: responses, records, events, this output, the documents."""

    group = "seed_reference_confidentiality"
    prohibited = tuple(PROHIBITED_RECORD_FIELDS)

    response_bodies = [response.body for response in responses]
    response_keys = _keys_present(response_bodies, RESPONSE_PROHIBITED_FIELDS)
    response_text = json.dumps(response_bodies, ensure_ascii=False)
    # ``state`` is the published envelope at the top of a response and internal entropy state
    # anywhere else, so the name is not banned outright but pinned to the one path it may
    # legitimately occupy.
    misplaced_state = [
        path
        for index in range(len(response_bodies))
        for path in _key_paths(response_bodies[index], "state")
        if path != RESPONSE_STATE_ENVELOPE_PATH
    ]
    ledger.record(
        "SEC-SEED-01",
        group,
        "no API response carries a prohibited entropy field, a misplaced state object or "
        "entropy-shaped material",
        not response_keys and not misplaced_state and not _entropy_material_hits(response_text),
        f"prohibited_keys={len(response_keys)} misplaced_state_paths={len(misplaced_state)} "
        f"material_shapes={len(_entropy_material_hits(response_text))}",
    )

    record_keys = _keys_present(list(draw_records), prohibited)
    record_text = json.dumps(list(draw_records), ensure_ascii=False)
    ledger.record(
        "SEC-SEED-02",
        group,
        "no committed draw record carries a prohibited entropy field or entropy-shaped material",
        not record_keys and not _entropy_material_hits(record_text) and len(draw_records) >= 1,
        f"records={len(draw_records)} prohibited_keys={len(record_keys)} "
        f"material_shapes={len(_entropy_material_hits(record_text))}",
    )

    event_keys = _keys_present(list(audit_events), prohibited)
    event_text = json.dumps(list(audit_events), ensure_ascii=False)
    ledger.record(
        "SEC-SEED-03",
        group,
        "no audit event carries a prohibited entropy field or entropy-shaped material",
        not event_keys and not _entropy_material_hits(event_text) and len(audit_events) >= 3,
        f"events={len(audit_events)} prohibited_keys={len(event_keys)} "
        f"material_shapes={len(_entropy_material_hits(event_text))}",
    )

    seed_references = sorted(
        {str(record.get("seed_reference")) for record in draw_records if record.get("seed_reference")}
    )
    ledger.record(
        "SEC-SEED-04",
        group,
        "every seed_reference is a reference to the entropy authority and nothing more",
        bool(seed_references)
        and all(re.fullmatch(SEED_REFERENCE_PATTERN, value) is not None for value in seed_references),
        f"distinct_seed_references={len(seed_references)}",
    )

    output_keys = _keys_present(partial_record, prohibited)
    output_text = json.dumps(partial_record, ensure_ascii=False)
    ledger.record(
        "SEC-SEED-05",
        group,
        "this harness's own output carries counts only, never entropy material",
        not output_keys and not _entropy_material_hits(output_text),
        f"prohibited_keys={len(output_keys)} material_shapes={len(_entropy_material_hits(output_text))}",
    )

    scanned: list[str] = []
    absent: list[str] = []
    document_hits: dict[str, list[str]] = {}
    for relative in SANITIZATION_SCAN_TARGETS:
        path = _REPO_ROOT / relative
        if not path.is_file():
            absent.append(relative)
            continue
        scanned.append(relative)
        hits = _entropy_material_hits(path.read_text(encoding="utf-8"))
        if hits:
            document_hits[relative] = hits
    ledger.record(
        "SEC-SEED-06",
        group,
        "no document written by this unit carries entropy-shaped material",
        not document_hits,
        f"scanned={len(scanned)} absent={len(absent)} documents_with_material={len(document_hits)}",
    )

    return {
        "prohibited_field_names_checked": len(prohibited),
        "response_prohibited_field_names_checked": len(RESPONSE_PROHIBITED_FIELDS),
        "state_key_pinned_to_the_published_envelope_path": True,
        "responses_inspected": len(responses),
        "draw_records_inspected": len(draw_records),
        "audit_events_inspected": len(audit_events),
        "distinct_seed_references": len(seed_references),
        "seed_reference_form": "entropy-ref://<source-id>/<algorithm-id>",
        "seed_value_recorded": False,
        "rejection_count_recorded": False,
        "entropy_bytes_recorded": False,
        "documents_scanned": len(scanned),
        "documents_absent_at_scan_time": len(absent),
        "documents_with_entropy_material": len(document_hits),
    }


# ---------------------------------------------------------------------------------------
# malformed requests -- deterministic and non-destructive
# ---------------------------------------------------------------------------------------


def _check_malformed(client: _Client, ledger: _CaseLedger) -> dict[str, Any]:
    leaking = 0
    for case in MALFORMED_CASES:
        headers = {"Accept": "application/json", "Connection": "close"}
        headers.update(case.get("headers", {}))
        body = case.get("body")
        if body is not None:
            headers.setdefault("Content-Type", "application/json")
        response = client.raw_call(
            case["method"],
            case["path"],
            headers,
            body,
            f"malformed[{case['case_id']}]",
            declared_length=case.get("declared_length"),
        )
        markers = _prohibited_markers(response.text)
        if markers:
            leaking += 1
        if case.get("expect_ok"):
            held = response.status == 200 and not markers
        else:
            held = (
                response.status >= 400
                and response.error_code == case["expected"]
                and not markers
            )
        ledger.record(
            case["case_id"],
            MALFORMED_GROUP,
            f"{case['description']} is refused deterministically without leaking internals"
            if not case.get("expect_ok")
            else f"{case['description']}",
            held,
            f"status={response.status} code={response.error_code} leaked_markers={len(markers)}",
        )
    return {
        "cases": len(MALFORMED_CASES),
        "fixed_input_set": True,
        "random_generation": False,
        "time_based_mutation": False,
        "repetition_storm": False,
        "destructive_on_source_data": False,
        "responses_leaking_internal_detail": leaking,
    }


# ---------------------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------------------


def _environment() -> dict[str, Any]:
    """Return the execution facts a reader needs, and none that name the operator.

    Deliberately no ``platform.node()``, no ``getpass.getuser()`` and no working directory:
    the machine's *kind* is context, its *name* is only a way to put an operator's hostname
    into an evidence file.
    """

    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    }


def _shutdown(server: Any, thread: threading.Thread, workers: _WorkerThreads, store: Any) -> bool:
    """Stop serving, close the listener, join every worker, then close the store.

    Never the other order: closing the store first would take the database out from under a
    handler still entitled to answer. ``shutdown`` stops the accept loop, so the enrolled list
    stops growing once it returns, and every worker already on it releases its own connection
    before its thread ends -- which is what turns "the handles will be closed" into "the
    handles are closed". The store is closed even when a join runs out of budget, because a
    refusal is not a reason to leave the main thread's connection open.
    """

    deadline = _Deadline(MAX_WALL_SECONDS)
    stopped = False
    try:
        server.shutdown()
        server.server_close()
        thread.join(timeout=deadline.budget("shutdown[serving]"))
        if thread.is_alive():
            raise SecurityVerificationError(
                "SERVER_THREAD_DEADLINE_EXCEEDED",
                "the serving thread did not stop within the shutdown bound",
            )
        for worker in workers.snapshot():
            worker.join(timeout=deadline.budget("shutdown[worker]"))
            if worker.is_alive():
                raise SecurityVerificationError(
                    "SERVER_WORKER_DEADLINE_EXCEEDED",
                    "a request-serving worker did not stop within the shutdown bound",
                )
        stopped = True
    finally:
        store.close()
    return stopped


def _execute(
    config: VerificationConfig,
    workspace: str,
    ledger: _CaseLedger,
    entropy: _CountingEntropySource,
) -> dict[str, Any]:
    """Drive the slice over loopback and return the raw evidence of every live case."""

    database = os.path.join(workspace, "security.sqlite3")
    store, table = open_table(
        database,
        config=TableConfig(
            opening_player_units=config.opening_player_units,
            opening_house_units=config.opening_house_units,
        ),
        entropy_source=entropy,
    )
    try:
        server = create_server(table, host=config.host, port=config.port, quiet=True)
    except BaseException:
        store.close()
        raise

    workers = _WorkerThreads()
    try:
        server.RequestHandlerClass = _releasing_handler(server.RequestHandlerClass, store, workers)
    except BaseException:
        server.server_close()
        store.close()
        raise

    host, port = server.server_address[0], int(server.server_address[1])
    thread = serve_in_background(server)
    deadline = _Deadline(config.wall_timeout_seconds)
    client = _Client(host, port, ledger, deadline, config.max_payload_bytes)

    dimensions: dict[str, Any] = {}
    workers_stopped = False
    opening_balance = 0
    closing_balance = 0
    try:
        opening = client.json_call("GET", "/api/state", None, "opening[state]")
        opening_balance = int(opening.body["state"]["balance_units"])

        dimensions["client_authority_forgery_denial"] = _check_client_authority(
            client, table, store, ledger, config
        )
        dimensions["betting_phase_lock_bypass_denial"] = _check_phase_and_lock(
            client, table, store, ledger, config
        )
        dimensions["idempotency_and_settlement_replay_safety"] = _check_idempotency(
            client, table, store, ledger, entropy, config
        )
        dimensions[MALFORMED_GROUP] = _check_malformed(client, ledger)

        closing = client.json_call("GET", "/api/state", None, "closing[state]")
        closing_balance = int(closing.body["state"]["balance_units"])
    finally:
        workers_stopped = _shutdown(server, thread, workers, store)

    return {
        "database": database,
        "dimensions": dimensions,
        "responses": list(client.responses),
        "opening_balance_units": opening_balance,
        "closing_balance_units": closing_balance,
        "worker_threads_started": workers.started(),
        "worker_threads_stopped": workers_stopped,
        "server_thread_stopped": not thread.is_alive(),
    }


def _inspect(config: VerificationConfig, database: str) -> dict[str, Any]:
    """Reopen the closed database and read the committed state every later claim rests on."""

    store, _table = open_table(
        database,
        config=TableConfig(
            opening_player_units=config.opening_player_units,
            opening_house_units=config.opening_house_units,
        ),
    )
    try:
        events = store.audit_events()
        chain_problems = store.verify_chain()
        draw_records: list[dict[str, Any]] = []
        transactions: list[dict[str, Any]] = []
        for event in events:
            if event.get("action") != "ROULETTE_RNG_DRAW":
                continue
            for reference in event.get("resource_refs", []):
                if isinstance(reference, str) and reference.startswith("rng-request://"):
                    record = store.draw_record(reference[len("rng-request://") :])
                    if record is not None:
                        draw_records.append(record.to_dict())
        for event in events:
            if event.get("action") != "ROULETTE_ROUND_SETTLED":
                continue
            for reference in event.get("resource_refs", []):
                if isinstance(reference, str) and reference.startswith("ledger-transaction://"):
                    stored = store.ledger_transaction(reference[len("ledger-transaction://") :])
                    if stored is not None:
                        transactions.append(stored)
        balances = store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT])
        counts = {
            "draw_record": store.count("draw_record"),
            "ledger_transaction": store.count("ledger_transaction"),
            "audit_event": store.count("audit_event"),
        }
    finally:
        store.close()
    return {
        "events": events,
        "chain_problems": list(chain_problems),
        "draw_records": draw_records,
        "transactions": transactions,
        "balances": {key: int(value) for key, value in balances.items()},
        "counts": counts,
    }


def _settlement_evidence(
    config: VerificationConfig, inspection: Mapping[str, Any], responses: Sequence[_Response]
) -> dict[str, Any]:
    """Reconcile the closing balance against the ledger, in integer minimum units only."""

    player_balance = int(inspection["balances"].get(PLAYER_ACCOUNT, 0))
    balance_delta = player_balance - config.opening_player_units
    ledger_delta = 0
    entries_sum_to_zero = True
    for transaction in inspection["transactions"]:
        entries = transaction.get("entries", [])
        if sum(int(entry["amount_units"]) for entry in entries) != 0:
            entries_sum_to_zero = False
        ledger_delta += sum(
            int(entry["amount_units"]) for entry in entries if entry["account_id"] == PLAYER_ACCOUNT
        )
    float_paths = _find_floats([response.body for response in responses]) + _find_floats(
        inspection["transactions"]
    )
    return {
        "opening_player_units": config.opening_player_units,
        "closing_player_units": player_balance,
        "player_balance_delta_units": balance_delta,
        "ledger_player_delta_units": ledger_delta,
        "balance_delta_matches_ledger": balance_delta == ledger_delta,
        "ledger_entries_sum_to_zero": entries_sum_to_zero,
        "float_values_found": len(float_paths),
        "currency_is_integer_only": not float_paths
        and all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in inspection["balances"].values()
        ),
        "committed_draw_records": inspection["counts"]["draw_record"],
        "committed_ledger_transactions": inspection["counts"]["ledger_transaction"],
        "committed_audit_events": inspection["counts"]["audit_event"],
        "audit_chain_problems_after_reload": len(inspection["chain_problems"]),
    }


def _findings(ledger: _CaseLedger) -> list[dict[str, Any]]:
    """Turn every case that did not hold into one sanitised finding.

    A finding records the dimension, the declared severity, the case, the expectation and the
    codes and counts observed. It never records a reproducible payload, a real credential or
    a personal datum, and it never carries an authorisation to repair anything: the remediation
    identifier names a *candidate* for a separate Task Contract that an approver must issue.
    """

    findings: list[dict[str, Any]] = []
    for index, case in enumerate(ledger.failed(), start=1):
        group = str(case["group"])
        findings.append(
            {
                "finding_id": f"SEC-FINDING-{index:03d}",
                "severity": FINDING_SEVERITY_BY_DIMENSION.get(group, "MEDIUM"),
                "dimension": group,
                "case_id": case["case_id"],
                "expectation": case["expectation"],
                "observed": case["detail"],
                "sanitized": True,
                "reproducible_payload_recorded": False,
                "secret_or_personal_data_recorded": False,
                "remediation_performed_by_this_unit": False,
                "remediation_task_candidate": f"{REMEDIATION_TASK_CANDIDATE_PREFIX}-{index:03d}",
                "remediation_task_candidate_scope": (
                    f"issue a separate Task Contract to repair the {group} defect this case "
                    "observed; this unit records the observation and performs no repair"
                ),
            }
        )
    return findings


def run_verification(config: VerificationConfig | None = None) -> dict[str, Any]:
    """Run one bounded verification and return the sanitised, machine-readable record of it.

    The order is deliberate. Preflight first, before a directory, a database, a socket, a
    thread or a copy exists, so a refused configuration leaves nothing behind. Then the live
    phase against a real loopback server. Then a clean shutdown -- ``shutdown``,
    ``server_close``, both joins, ``store.close`` -- and only then the inspection, over a
    database that has been closed and reopened, because "the chain still verifies" is a claim
    about storage and not about a live object's memory. The audit manipulation comes last, on
    copies of that closed file.

    The workspace is deleted by an ordinary ``TemporaryDirectory`` with no suppression of
    cleanup errors, and the absence check afterwards states the requirement positively: the
    claim is "the workspace is gone", not "deleting it was attempted".
    """

    config = (config or VerificationConfig()).validate()

    ledger = _CaseLedger(config)
    entropy = _CountingEntropySource()
    with tempfile.TemporaryDirectory(prefix="ts-studio-r2-sec-") as workspace:
        execution = _execute(config, workspace, ledger, entropy)
        inspection = _inspect(config, execution["database"])
        audit_evidence = _check_audit_tamper(
            workspace, execution["database"], ledger, inspection["events"]
        )
        settlement = _settlement_evidence(config, inspection, execution["responses"])

        partial = {
            "dimensions": execution["dimensions"],
            "audit": audit_evidence,
            "settlement": settlement,
            "cases": ledger.cases,
        }
        confidentiality = _check_confidentiality(
            ledger,
            execution["responses"],
            inspection["draw_records"],
            inspection["events"],
            partial,
        )

    workspace_released = not os.path.exists(workspace)
    if not workspace_released:
        raise SecurityVerificationError(
            "WORKSPACE_NOT_RELEASED",
            "the temporary verification workspace survived its own cleanup, which means a "
            "database handle outlived the run",
        )

    dimensions = dict(execution["dimensions"])
    dimensions["audit_event_tamper_and_delete_detection_on_copy"] = audit_evidence
    dimensions["seed_reference_confidentiality"] = confidentiality

    entropy_reads, entropy_bytes = entropy.meter()
    findings = _findings(ledger)
    dimension_results = {
        name: ledger.group_holds(name) for name in (*DIMENSIONS, MALFORMED_GROUP)
    }

    record = {
        "schema_version": SCHEMA_VERSION,
        "task_id": TASK_ID,
        "contract_ref": CONTRACT_REF,
        "notice": json.loads(json.dumps(NOTICE, ensure_ascii=False)),
        "environment": _environment(),
        "config": config.to_dict(),
        "bounds": {
            "purpose": "bounded_local_execution_only",
            "are_security_maturity_targets": False,
            "are_pass_fail_thresholds": False,
            "enforced_before_resource_creation": True,
            "max_cases": MAX_CASES,
            "max_http_requests": MAX_HTTP_REQUESTS,
            "max_wall_seconds": MAX_WALL_SECONDS,
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
            "transport_max_body_bytes": MAX_BODY_BYTES,
            "payload_bound_within_transport_limit": MAX_PAYLOAD_BYTES <= MAX_BODY_BYTES,
        },
        "counts": {
            "planned_cases": PLANNED_CASE_COUNT,
            "executed_cases": len(ledger.cases),
            "planned_http_requests": PLANNED_HTTP_REQUEST_COUNT,
            "executed_http_requests": ledger.http_requests,
            "cases_within_bound": len(ledger.cases) <= config.max_cases,
            "http_requests_within_bound": ledger.http_requests <= config.max_http_requests,
            "plan_matches_execution": len(ledger.cases) == PLANNED_CASE_COUNT
            and ledger.http_requests == PLANNED_HTTP_REQUEST_COUNT,
            "entropy_reads_total": entropy_reads,
            "entropy_bytes_total": entropy_bytes,
            "entropy_material_recorded": False,
            "server_worker_threads_started": int(execution["worker_threads_started"]),
        },
        "dimensions": {
            "declared": list(DIMENSIONS),
            "results": dimension_results,
            "all_dimensions_hold": all(dimension_results.values()),
            "evidence": dimensions,
        },
        "cases": ledger.cases,
        "evidence": {
            "settlement": settlement,
            "chain_problems_after_reload": len(inspection["chain_problems"]),
            "routes_observed": sorted(ROUTES),
            "new_http_routes": 0,
            "new_error_codes": 0,
            "new_runtime_modules": 0,
            "new_dependencies": 0,
            "runtime_code_modified": False,
            "remediation_applied": False,
        },
        "findings": findings,
        "remediation": {
            "performed_by_this_unit": False,
            "findings_recorded": len(findings),
            "task_candidate_prefix": REMEDIATION_TASK_CANDIDATE_PREFIX,
            "task_candidates": [item["remediation_task_candidate"] for item in findings],
            "note": (
                "a finding is an observation handed to a separate remediation Task Contract "
                "candidate; discovering a defect grants this unit no authority to repair it"
            ),
        },
        "cleanup": {
            "workspace_released": workspace_released,
            "cleanup_errors_suppressed": False,
            "server_thread_stopped": bool(execution["server_thread_stopped"]),
            "worker_threads_joined": bool(execution["worker_threads_stopped"]),
            "temporary_workspace_inside_repository": False,
            "original_database_hash_unchanged": audit_evidence["original_database_hash_unchanged"],
            "repository_audit_records_unchanged": audit_evidence["repository_audit_records_unchanged"],
        },
    }

    missing = [key for key in OUTPUT_TOP_LEVEL_KEYS if key not in record]
    unexpected = [key for key in record if key not in OUTPUT_TOP_LEVEL_KEYS]
    if missing or unexpected:
        raise SecurityVerificationError(
            "OUTPUT_CONTRACT_VIOLATED",
            f"top-level keys missing {missing!r} and unexpected {unexpected!r}",
        )
    return record


# ---------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python scripts/verify_r2_security.py",
        description=(
            "R2-SEC-0005 bounded local defensive security verification. Loopback only, "
            "fixed deterministic cases, no remediation, no timing threshold."
        ),
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"loopback literal only: {list(ALLOWED_TARGET_HOSTS)}")
    parser.add_argument("--max-cases", type=int, default=MAX_CASES)
    parser.add_argument("--max-requests", type=int, default=MAX_HTTP_REQUESTS)
    parser.add_argument("--wall-seconds", type=int, default=DEFAULT_WALL_SECONDS)
    parser.add_argument("--max-payload-bytes", type=int, default=MAX_PAYLOAD_BYTES)
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one verification, print the sanitised JSON record, and report what held.

    The exit code answers "did every declared dimension hold", never "was it fast enough".
    There is no timing exit path, because attaching one would turn a safety bound into the
    threshold this contract refuses to declare.
    """

    args = _parse_args(argv)
    config = VerificationConfig(
        host=args.host,
        max_cases=args.max_cases,
        max_http_requests=args.max_requests,
        wall_timeout_seconds=args.wall_seconds,
        max_payload_bytes=args.max_payload_bytes,
    )
    try:
        record = run_verification(config)
    except SecurityVerificationError as refusal:
        sys.stderr.write(f"{refusal.code}: {refusal.message}\n")
        return 2
    sys.stdout.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    sys.stdout.flush()
    if not record["dimensions"]["all_dimensions_hold"]:
        failed = sorted(
            name for name, held in record["dimensions"]["results"].items() if not held
        )
        sys.stderr.write("verification dimensions did not hold: " + ", ".join(failed) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
