"""R2-LOAD-0004: bounded local concurrent load observation for the roulette slice.

    python scripts/observe_r2_load.py --concurrency 4 --rounds 3

What this is
------------
A harness that knocks on the already-existing single-user loopback roulette slice from the
outside and writes down two *separately labelled* kinds of fact, exactly as
``games/roulette/load-observation-contract.yaml`` declares them:

* **Correctness properties**, which are judged. One authoritative draw and one settlement
  per round, a duplicate ``request_id`` that commits once and is observed identically by
  every caller, integer-only currency, a player balance delta that reconciles against the
  ledger to the minimum unit, globally unique audit references, and an audit chain that
  still verifies after the database is closed and reloaded. None of these depend on timing,
  so a slow machine cannot change the answer.

* **Observations**, which are *not* judged. Latency minimum, median, p95 and maximum,
  throughput, and ``serialization_wait_proxy_ms``. No threshold, target, service level
  objective or capacity promise is attached to any of them, here or anywhere downstream.
  They are the record of one execution on one machine, and they move with the machine, the
  operating system, the Python build and whatever else was running at the time.

What this deliberately is not
-----------------------------
It adds no HTTP route, no runtime module and no instrumentation inside the observed code.
It drives ``apps.roulette_web.server`` through its published entry points --
:func:`~apps.roulette_web.server.open_table`, :func:`~apps.roulette_web.server.create_server`
and :func:`~apps.roulette_web.server.serve_in_background` -- and talks to it over a real
loopback socket with :mod:`http.client`, because a race that is proved against a handler stub
is not a race that was proved. It injects exactly two adapters, both assembled here and both
riding a parameter or an attribute the observed code already publishes:

* :class:`_CountingEntropySource`, a counting wrapper around the same
  :class:`~studio_core.rng.OsCsprngEntropySource` the store would have built for itself. It
  is passed through ``open_table``'s existing ``entropy_source`` parameter, it counts reads
  and byte lengths and never retains a byte.
* :func:`_releasing_handler`, a subclass of the handler the server already built, installed
  on the server object through ``socketserver``'s published ``RequestHandlerClass``
  attribute. It measures nothing and touches no request, response, header or status: it
  enrols its worker thread so the shutdown path can join it, and releases that thread's own
  database connection in a ``finally``. The next section is why.

No file in the observed slice is modified to accommodate either of them.

Closing a worker's connection
-----------------------------
``sqlite3`` binds a connection to the thread that opened it. ``ThreadingHTTPServer`` serves
every accepted connection on its own thread, so every worker opens its own connection to the
observation database -- and the store's ``close``, which runs on this harness's main thread,
physically *cannot* shut those down: ``connection.close()`` from another thread raises
``sqlite3.ProgrammingError``, a subclass of ``sqlite3.Error``, which the store's close path
treats as the harmless double-close it is designed to tolerate. The handles stay open. On
Windows an open handle keeps ``observation.sqlite3`` and its write-ahead log locked, so the
temporary workspace cannot be deleted afterwards.

The thread that opened a connection is the only one allowed to close it, so that is where the
release happens: the handler subclass calls the store's published
:meth:`~studio_core.durable_state.DurableRoundStore.release_thread_connection` in a
``finally``. And because the slice sets ``daemon_threads``, ``socketserver`` keeps no list of
its workers and ``server_close`` joins none of them, so the harness keeps the list the server
does not and joins every worker -- against a bounded deadline -- before the store is closed
and the workspace is deleted. Joining is what turns "the release will happen" into "the
release has happened".

Why the proxy is called a proxy
-------------------------------
``serialization_wait_proxy_ms`` is measured from one instant shared by a whole barrier-
released group -- recorded once by the barrier's action callback, when the last worker
arrives and before any is released -- to the moment ``getresponse()`` returns for each
request. That is the earliest "you have been served" signal available from outside the
process. It therefore *combines* operating-system scheduler wake-up order, client thread
dispatch order, loopback connection setup and the effect of serialized service, and it
includes the service time itself, which makes it an upper bound on queueing rather than a
lower one. It is **not** a measurement of internal lock acquisition wait. This harness does
not measure that, and does not adopt the one technique that would -- instrumenting the
observed runtime -- because production instrumentation is prohibited by the contract.

Total latency is a different observation, not a differently rounded one: its origin is each
request's own send instant, and its end is the moment the response body has been fully read.
Different origin, different end, reported under a different key.

Safety bounds
-------------
:data:`MAX_CONCURRENCY`, :data:`MAX_TOTAL_REQUESTS`, :data:`MAX_ROUNDS` and
:data:`MAX_WALL_SECONDS` exist so a local run cannot grow without limit. They are not
performance expectations, not service level objectives and not pass/fail thresholds, and no
observed number is ever compared against them. :meth:`ObservationConfig.validate` refuses a
configuration that exceeds them *before* any temporary directory, store, server or thread is
created, so a refusal leaves nothing behind to clean up.

Nothing in the emitted JSON names a host, a user, an account, a credential or an absolute
path belonging to the operator, and no entropy material is recorded -- only counts.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import platform
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import (  # noqa: E402
    LOOPBACK_HOSTS,
    ROUTES,
    create_server,
    open_table,
    serve_in_background,
)
from apps.roulette_web.table import (  # noqa: E402
    HOUSE_ACCOUNT,
    NOTICE as PROTOTYPE_NOTICE,
    PLAYER_ACCOUNT,
    TableConfig,
)
from studio_core.rng import OsCsprngEntropySource  # noqa: E402

__all__ = [
    "CONTRACT_REF",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_HOST",
    "DEFAULT_OPENING_HOUSE_UNITS",
    "DEFAULT_OPENING_PLAYER_UNITS",
    "DEFAULT_PORT",
    "DEFAULT_ROUNDS",
    "DEFAULT_STAKE_UNITS_PER_BET",
    "DEFAULT_WALL_SECONDS",
    "DEFAULT_WARMUP_REQUESTS",
    "ENVIRONMENT_KEYS",
    "MAX_CONCURRENCY",
    "MAX_ROUNDS",
    "MAX_TOTAL_REQUESTS",
    "MAX_WALL_SECONDS",
    "MEASUREMENT_IS_OBSERVATION_ONLY",
    "NOTICE",
    "OBSERVED_BET_TYPE",
    "OBSERVED_METRIC_NAMES",
    "OUTPUT_TOP_LEVEL_KEYS",
    "PERCENTILE_METHOD",
    "ROUNDING_DECIMALS",
    "SCHEMA_VERSION",
    "SERIALIZATION_PROXY_METRIC",
    "STATISTICS_CLOCK_SOURCE",
    "STATISTICS_UNIT",
    "TASK_ID",
    "WARMUP_INCLUDED_IN_STATISTICS",
    "LoadObservationError",
    "ObservationConfig",
    "main",
    "nearest_rank_percentile",
    "run_observation",
    "summarize_samples",
]

SCHEMA_VERSION = "1.0.0"
TASK_ID = "R2-LOAD-0004"

#: Repository-relative on purpose. An absolute path would name the operator's filesystem.
CONTRACT_REF = "games/roulette/load-observation-contract.yaml"

# ---------------------------------------------------------------------------------------
# safety bounds -- bounded local execution only
# ---------------------------------------------------------------------------------------
# These four are the approved hard ceilings of AC-002. They are not performance
# expectations, not service level objectives and not pass/fail thresholds, and no observed
# value in the output is ever compared against them. A later document citing them as a
# capacity target is the reinterpretation the contract explicitly refuses.

MAX_CONCURRENCY = 16
MAX_TOTAL_REQUESTS = 128
MAX_ROUNDS = 32
MAX_WALL_SECONDS = 60

# Implementation defaults sit below the ceilings. Lower is allowed; above is not.
DEFAULT_CONCURRENCY = 4
DEFAULT_ROUNDS = 3
DEFAULT_WARMUP_REQUESTS = 2
DEFAULT_WALL_SECONDS = 30
DEFAULT_STAKE_UNITS_PER_BET = 5
DEFAULT_OPENING_PLAYER_UNITS = 10_000
DEFAULT_OPENING_HOUSE_UNITS = 1_000_000

DEFAULT_HOST = "127.0.0.1"
#: Port 0 asks the operating system for a free ephemeral port, so an observation run can
#: never collide with a slice a developer already has open.
DEFAULT_PORT = 0

#: An even-money outside bet. The worst pocket returns twice the stake, which keeps the
#: house exposure check satisfiable with a modest opening bankroll and keeps the arithmetic
#: of the reconciliation easy for a reviewer to follow. ``selections`` is empty for it.
OBSERVED_BET_TYPE = "red"

# ---------------------------------------------------------------------------------------
# statistics definitions -- restated as data so the contract and the code can be compared
# ---------------------------------------------------------------------------------------

STATISTICS_UNIT = "milliseconds"
STATISTICS_CLOCK_SOURCE = "time.perf_counter"
PERCENTILE_METHOD = "nearest_rank_percentile"
ROUNDING_DECIMALS = 4
WARMUP_INCLUDED_IN_STATISTICS = False
MEASUREMENT_IS_OBSERVATION_ONLY = True

SERIALIZATION_PROXY_METRIC = "serialization_wait_proxy_ms"

#: Every observed -- that is, unjudged -- number this harness emits.
OBSERVED_METRIC_NAMES: tuple[str, ...] = (
    "latency_ms.min",
    "latency_ms.median",
    "latency_ms.p95",
    "latency_ms.max",
    "throughput.requests_per_second",
    "throughput.rounds_per_second",
    "serialization_wait_proxy_ms.min",
    "serialization_wait_proxy_ms.median",
    "serialization_wait_proxy_ms.p95",
    "serialization_wait_proxy_ms.max",
)

OUTPUT_TOP_LEVEL_KEYS: tuple[str, ...] = (
    "schema_version",
    "task_id",
    "contract_ref",
    "notice",
    "environment",
    "config",
    "counts",
    "elapsed",
    "throughput",
    "latency_ms",
    SERIALIZATION_PROXY_METRIC,
    "correctness",
)

ENVIRONMENT_KEYS: tuple[str, ...] = (
    "python_version",
    "python_implementation",
    "system",
    "release",
    "machine",
    "cpu_count",
    "clock_source",
    "clock_resolution_ns",
)

#: Restated in every output. The prototype half is the slice's own notice; the measurement
#: half is what ``observed_metrics.citation_requirement`` asks any citing document to carry.
NOTICE: dict[str, Any] = {
    "prototype": dict(PROTOTYPE_NOTICE),
    "measurement": {
        "measurement_is_observation_only": MEASUREMENT_IS_OBSERVATION_ONLY,
        "asserted_by_tests": False,
        "environment_dependent": True,
        "portable_performance_characteristic": False,
        "service_level_objective_declared": "NONE",
        "latency_threshold_declared": "NONE",
        "throughput_target_declared": "NONE",
        "capacity_promise": "NONE",
        "text_en": (
            "Observation record of one execution on one machine. No threshold, target, "
            "service level objective or capacity promise is declared or implied. Values "
            "vary with machine, operating system, Python build and concurrent load."
        ),
        "text_ko": (
            "특정 실행 환경의 관측 기록이다. 임계값, 목표치, SLO, 용량 약속을 선언하지도 "
            "함의하지도 않는다. 값은 기계, 운영체제, 파이썬 빌드, 동시 부하에 따라 달라진다."
        ),
    },
}


class LoadObservationError(RuntimeError):
    """A bounded-observation refusal carrying a stable code.

    Messages carry policy context only: never a filesystem path, a hostname, a database
    detail or a traceback, because the operator may paste this into an evidence file.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------------------


def _require_integer(name: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LoadObservationError("CONFIG_INVALID", f"{name} must be an integer")
    return value


def _require_range(name: str, value: int, minimum: int, maximum: int) -> None:
    if value < minimum or value > maximum:
        raise LoadObservationError(
            "BOUND_EXCEEDED",
            f"{name} must be within {minimum}..{maximum}; {value} was requested",
        )


@dataclass(frozen=True)
class ObservationConfig:
    """One bounded observation run, refused before it starts if it exceeds a ceiling."""

    concurrency: int = DEFAULT_CONCURRENCY
    rounds: int = DEFAULT_ROUNDS
    warmup_requests: int = DEFAULT_WARMUP_REQUESTS
    wall_timeout_seconds: int = DEFAULT_WALL_SECONDS
    stake_units_per_bet: int = DEFAULT_STAKE_UNITS_PER_BET
    opening_player_units: int = DEFAULT_OPENING_PLAYER_UNITS
    opening_house_units: int = DEFAULT_OPENING_HOUSE_UNITS
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT

    # -- derived ------------------------------------------------------------------------

    def planned_requests(self) -> int:
        """Return ``warmup + rounds * (2 * concurrency + 1)``.

        The per-round plan is ``concurrency`` bets with distinct identifiers, ``concurrency``
        spins with one *identical* identifier, and a single new-round request. The identical
        spin identifier is the whole point of the exercise: it is the duplicate submission
        whose idempotency has to survive a genuine race.
        """

        return int(self.warmup_requests) + int(self.rounds) * (2 * int(self.concurrency) + 1)

    def measured_requests(self) -> int:
        """Requests whose outcomes enter the statistics. Warm-up is counted but not measured."""

        return int(self.rounds) * (2 * int(self.concurrency) + 1)

    def concurrent_requests(self) -> int:
        """Requests released by a barrier, which are the only ones the proxy is measured for."""

        return int(self.rounds) * 2 * int(self.concurrency)

    # -- validation ---------------------------------------------------------------------

    def validate(self) -> "ObservationConfig":
        """Refuse anything above a ceiling or off loopback, and return ``self``.

        Every check here is arithmetic on the configuration. Nothing has been opened, bound
        or started when it runs, so a refusal cannot leave a half-executed run behind -- which
        is what ``safety_bounds.enforcement`` requires.
        """

        for name in (
            "concurrency",
            "rounds",
            "warmup_requests",
            "wall_timeout_seconds",
            "stake_units_per_bet",
            "opening_player_units",
            "opening_house_units",
            "port",
        ):
            _require_integer(name, getattr(self, name))

        _require_range("concurrency", self.concurrency, 1, MAX_CONCURRENCY)
        _require_range("rounds", self.rounds, 1, MAX_ROUNDS)
        _require_range("warmup_requests", self.warmup_requests, 0, MAX_TOTAL_REQUESTS)
        _require_range("wall_timeout_seconds", self.wall_timeout_seconds, 1, MAX_WALL_SECONDS)
        _require_range("stake_units_per_bet", self.stake_units_per_bet, 1, 1000)
        _require_range("port", self.port, 0, 65535)

        # The binding is checked against the server's own allowlist rather than a copy of it,
        # so a hostname this harness would accept but the slice would refuse cannot exist.
        # No name resolution is attempted for a rejected host: an off-loopback target is not
        # something to look up, it is something to refuse.
        if not isinstance(self.host, str) or self.host not in LOOPBACK_HOSTS:
            raise LoadObservationError(
                "TARGET_NOT_LOOPBACK",
                f"the observation target must be one of {sorted(LOOPBACK_HOSTS)}",
            )

        planned = self.planned_requests()
        if planned > MAX_TOTAL_REQUESTS:
            raise LoadObservationError(
                "REQUEST_BUDGET_EXCEEDED",
                f"the plan derives {planned} requests, above the bound of {MAX_TOTAL_REQUESTS}",
            )

        # Affordability is part of being bounded: a run that runs the player out of chips
        # halfway through would abort mid-round and leave a partial observation, so it is
        # refused here instead. The worst case is every round losing its whole stake.
        worst_case_stake = self.rounds * self.concurrency * self.stake_units_per_bet
        if worst_case_stake > self.opening_player_units:
            raise LoadObservationError(
                "CONFIG_INVALID",
                f"the opening player balance of {self.opening_player_units} cannot fund the "
                f"planned worst-case stake of {worst_case_stake}",
            )
        # An even-money bet's worst pocket returns twice the stake, so the bankroll has to
        # cover the stake again on every round of the plan.
        worst_case_liability = worst_case_stake * 2
        if worst_case_liability > self.opening_house_units:
            raise LoadObservationError(
                "CONFIG_INVALID",
                f"the opening house bankroll of {self.opening_house_units} cannot cover the "
                f"planned worst-case liability of {worst_case_liability}",
            )
        return self

    # -- output -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "concurrency": self.concurrency,
            "rounds": self.rounds,
            "warmup_requests": self.warmup_requests,
            "wall_timeout_seconds": self.wall_timeout_seconds,
            "stake_units_per_bet": self.stake_units_per_bet,
            "opening_player_units": self.opening_player_units,
            "opening_house_units": self.opening_house_units,
            "bet_type": OBSERVED_BET_TYPE,
            "host": self.host,
            "port": self.port,
            "port_selection": "ephemeral" if self.port == 0 else "fixed",
            "target_slice": "apps/roulette_web",
            "route_count": len(ROUTES),
            "request_plan_formula": "warmup_requests + rounds * (2 * concurrency + 1)",
            "planned_requests": self.planned_requests(),
            "safety_bounds": {
                "purpose": "bounded_local_execution_only",
                "are_performance_expectations": False,
                "are_service_level_objectives": False,
                "are_pass_fail_thresholds": False,
                "compared_against_observed_values": False,
                "max_concurrency": MAX_CONCURRENCY,
                "max_total_requests": MAX_TOTAL_REQUESTS,
                "max_rounds": MAX_ROUNDS,
                "max_wall_seconds": MAX_WALL_SECONDS,
            },
        }


# ---------------------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------------------


def nearest_rank_percentile(samples: Sequence[float], percentile: int) -> float:
    """Return the nearest-rank percentile of ``samples``, with no interpolation.

    ``index = ceil(percentile * n / 100) - 1`` over the ascending sorted sample, computed in
    integer arithmetic. Nearest rank is chosen over an interpolating definition because an
    interpolated p95 is a value that was never observed, and the whole point of this file is
    to write down what actually happened. The sample is sorted here rather than trusted to
    arrive sorted, so the result depends only on the multiset of values.
    """

    if not isinstance(percentile, int) or isinstance(percentile, bool) or not 1 <= percentile <= 100:
        raise LoadObservationError("PERCENTILE_INVALID", "a percentile must be an integer in 1..100")
    ordered = sorted(float(value) for value in samples)
    count = len(ordered)
    if count == 0:
        raise LoadObservationError("NO_SAMPLES", "a percentile is undefined over an empty sample")
    # Integer ceiling division: ceil(a / b) == -((-a) // b).
    index = -((-percentile * count) // 100) - 1
    if index < 0:
        index = 0
    elif index >= count:
        index = count - 1
    return ordered[index]


def summarize_samples(samples: Sequence[float]) -> dict[str, Any]:
    """Return ``samples``/``min``/``median``/``p95``/``max`` for one observed metric.

    Deterministic on a fixed sample: the same multiset always produces the same five values,
    which is what makes the statistics themselves testable without asserting anything about
    how fast the machine under them happens to be.
    """

    ordered = sorted(float(value) for value in samples)
    if not ordered:
        raise LoadObservationError("NO_SAMPLES", "an observed metric requires at least one sample")
    return {
        "samples": len(ordered),
        "min": round(ordered[0], ROUNDING_DECIMALS),
        "median": round(nearest_rank_percentile(ordered, 50), ROUNDING_DECIMALS),
        "p95": round(nearest_rank_percentile(ordered, 95), ROUNDING_DECIMALS),
        "max": round(ordered[-1], ROUNDING_DECIMALS),
    }


# ---------------------------------------------------------------------------------------
# entropy metering
# ---------------------------------------------------------------------------------------


class _CountingEntropySource:
    """The OS CSPRNG, counted. Bytes are passed through and never retained.

    The contract wants entropy *consumption* as evidence that a duplicate submission does not
    reach the sampler, and it forbids instrumenting the observed runtime to get it. Wrapping
    the approved source and injecting it through ``open_table``'s existing ``entropy_source``
    parameter satisfies both: the slice is unmodified, and the only thing recorded is how many
    reads happened and how many bytes they totalled. No byte, seed or rejection value is kept,
    so nothing here can become a leak of the material ``studio_core.rng`` never records.

    ``source_id`` and ``is_deterministic`` are those of the wrapped source because they
    describe the entropy actually used, and a draw record that claimed otherwise would be
    false. That also keeps the source acceptable to a ``PRODUCTION`` engine, which refuses a
    deterministic adapter outright.
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


# ---------------------------------------------------------------------------------------
# server-side worker accounting
# ---------------------------------------------------------------------------------------


class _WorkerThreads:
    """The request-serving threads the observed server started, so they can be joined.

    ``ThreadingHTTPServer`` runs every accepted connection on its own thread. The slice sets
    ``daemon_threads``, and ``socketserver`` deliberately keeps no list of daemon workers, so
    ``server_close`` joins none of them. That is the right trade for a launcher that exits
    with the process, and the wrong one for a harness that has to know the last worker has
    finished before it closes the store and deletes the directory the database lives in --
    so the harness keeps the list the server does not.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def enrol(self) -> None:
        """Record the calling thread. Called once per worker, by that worker, before it serves."""

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

    Two lines of behaviour, both about resource ownership and neither about the request:

    ``setup`` is the first thing the server runs on a worker thread, so enrolling there means
    a worker cannot exist without being on the list the shutdown path joins -- there is no
    window in which a thread is serving and unaccounted for.

    ``handle`` returns when the worker is done with the table, and by then that worker may
    have opened a connection to the observation database that only it is allowed to close.
    Releasing it in a ``finally`` covers the refusal and exception paths as well as the
    successful one. The call is a no-op for a worker that never touched the store.

    Nothing here reads or writes a request, a response, a header, a status or a clock, and
    nothing in the observed slice is modified: the subclass is assembled by the harness and
    installed through ``RequestHandlerClass``, which ``socketserver`` publishes as the way to
    say which handler a server should use.
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
class _Outcome:
    """One completed request and the three instants that describe it."""

    label: str
    status: int
    body: dict[str, Any]
    #: The request's own send instant -- the origin of total latency.
    started: float
    #: ``getresponse()`` returned: the earliest externally visible "serviced" signal, and the
    #: end point of the serialization wait proxy.
    serviced: float
    #: The response body was fully read -- the end of total latency.
    finished: float

    @property
    def latency_ms(self) -> float:
        return (self.finished - self.started) * 1000.0


class _Deadline:
    """A monotonic wall bound for the whole load phase.

    Everything that waits in this file waits against this rather than against a fixed sleep:
    a fixed sleep is both a false deadline on a slow machine and wasted time on a fast one,
    and a test that passes because of one is not deterministic.
    """

    def __init__(self, seconds: float) -> None:
        self._end = time.perf_counter() + float(seconds)

    def remaining(self) -> float:
        return self._end - time.perf_counter()

    def check(self, stage: str) -> None:
        if self.remaining() <= 0.0:
            raise LoadObservationError(
                "WALL_DEADLINE_EXCEEDED", f"the observation exceeded its wall bound at {stage}"
            )

    def budget(self, stage: str) -> float:
        """Return a strictly positive timeout for one blocking wait, or refuse."""

        self.check(stage)
        return min(max(self.remaining(), 0.001), float(MAX_WALL_SECONDS))


def _call(
    host: str, port: int, method: str, path: str, body: Mapping[str, Any] | None, timeout: float
) -> _Outcome:
    """Issue one request on its own connection and return its outcome and instants.

    A fresh connection per request, and ``Connection: close`` on every one of them: a kept
    alive socket would leave a handler thread parked on a read after the run is over, and on
    Windows that thread's SQLite handle is what keeps the temporary database file locked.

    The response body is read to exhaustion and the response is then closed explicitly, ahead
    of the connection that owns it. ``HTTPConnection.close`` would close it too, but a body
    that is closed only as a side effect of closing something else is a body whose lifetime
    nobody stated, and every socket in this file is closed on the way out of the ``try`` that
    opened it rather than left to a finaliser.
    """

    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json", "Connection": "close"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        started = time.perf_counter()
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        serviced = time.perf_counter()
        try:
            raw = response.read()
            finished = time.perf_counter()
            status = int(response.status)
        finally:
            response.close()
    finally:
        connection.close()
    try:
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LoadObservationError(
            "RESPONSE_INVALID", f"{method} {path} returned a body that is not UTF-8 JSON"
        ) from None
    if not isinstance(decoded, dict):
        raise LoadObservationError("RESPONSE_INVALID", f"{method} {path} did not return a JSON object")
    return _Outcome(
        label=f"{method} {path}",
        status=status,
        body=decoded,
        started=started,
        serviced=serviced,
        finished=finished,
    )


def _refusal_code(outcome: _Outcome) -> str:
    error = outcome.body.get("error")
    if isinstance(error, Mapping) and isinstance(error.get("code"), str):
        return error["code"]
    return "UNKNOWN"


def _run_group(
    host: str,
    port: int,
    requests: Sequence[tuple[str, str, Mapping[str, Any] | None]],
    deadline: _Deadline,
    stage: str,
) -> tuple[list[_Outcome], float]:
    """Release ``requests`` together from one barrier and return their outcomes.

    The barrier's ``action`` callback is the whole mechanism behind
    ``serialization_wait_proxy_ms``: it runs once, in the thread of the last worker to
    arrive, *before* any worker is released, so every request in the group shares one origin
    instant recorded by one call to ``perf_counter()``. Recording per-worker release times
    instead would fold each worker's own wake-up into its own origin and hide exactly the
    dispatch ordering the proxy is meant to expose.
    """

    size = len(requests)
    if size == 0:
        raise LoadObservationError("GROUP_EMPTY", "a request group must contain at least one request")

    released: dict[str, float] = {}
    barrier = threading.Barrier(size, action=lambda: released.__setitem__("at", time.perf_counter()))
    outcomes: list[_Outcome | None] = [None] * size
    failures: list[str | None] = [None] * size

    def worker(index: int) -> None:
        method, path, body = requests[index]
        try:
            barrier.wait(timeout=deadline.budget(f"{stage}[barrier]"))
            outcomes[index] = _call(
                host, port, method, path, body, deadline.budget(f"{stage}[request]")
            )
        except BaseException as exc:  # noqa: BLE001 - reported by type only, never by message
            failures[index] = type(exc).__name__

    threads = [
        threading.Thread(target=worker, args=(index,), name=f"r2-load-{stage}-{index}", daemon=True)
        for index in range(size)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        # A bounded join, never an unbounded one: the wall bound is the only thing allowed to
        # decide how long this run may take.
        thread.join(timeout=max(deadline.remaining(), 0.0))
        if thread.is_alive():
            raise LoadObservationError(
                "WORKER_DEADLINE_EXCEEDED", f"a {stage} worker did not finish within the wall bound"
            )

    reported = sorted({name for name in failures if name is not None})
    if reported:
        raise LoadObservationError("REQUEST_FAILED", f"{stage} raised {', '.join(reported)}")

    completed = [outcome for outcome in outcomes if outcome is not None]
    refused = [outcome for outcome in completed if outcome.status != 200]
    if refused:
        codes = sorted({_refusal_code(outcome) for outcome in refused})
        raise LoadObservationError(
            "REQUEST_REFUSED", f"{stage} was refused with {', '.join(codes)}"
        )
    if "at" not in released:
        raise LoadObservationError("BARRIER_NOT_RELEASED", f"the {stage} barrier never released")
    return completed, released["at"]


# ---------------------------------------------------------------------------------------
# correctness inspection
# ---------------------------------------------------------------------------------------


def _find_floats(value: Any, path: str = "$") -> list[str]:
    """Return the JSON paths of every float inside ``value``.

    Currency is integer minimum units everywhere in this system, so the useful check is not
    "the balance is an int" but "no float exists anywhere in this payload" -- which keeps
    working when a field is added that nobody thought to check.
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


def _reference_after(references: Any, prefix: str) -> str | None:
    if not isinstance(references, (list, tuple)):
        return None
    for reference in references:
        if isinstance(reference, str) and reference.startswith(prefix):
            return reference[len(prefix) :]
    return None


def _spin_commit_identity(body: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    """Return the three fields every caller of one committed spin must agree on."""

    result = body.get("result")
    if not isinstance(result, Mapping):
        return (None, None, None)
    return (
        result.get("settlement_transaction_id"),
        result.get("pocket"),
        result.get("round_id"),
    )


# ---------------------------------------------------------------------------------------
# the observation
# ---------------------------------------------------------------------------------------


def run_observation(config: ObservationConfig | None = None) -> dict[str, Any]:
    """Run one bounded observation and return the machine-readable record of it.

    The order is deliberate. Validation first, before a directory, a store, a socket or a
    thread exists, so a refused configuration leaves nothing behind. Then the load phase
    against a real loopback server. Then a clean shutdown -- ``shutdown``, ``server_close``,
    both joins, ``store.close`` -- and only then the correctness inspection, over a database
    that has been closed and reopened, because "the audit chain still verifies" is a claim
    about storage and not about a live object's memory.

    The workspace is deleted by an ordinary ``TemporaryDirectory``, with no suppression of
    cleanup errors. That is deliberate and it is the point: a failed delete means a database
    handle outlived the run, and suppressing the error would turn the one signal that a
    handle leaked into silence. The existence check afterwards states the same requirement
    positively, so the claim is "the workspace is gone" and not "deleting it was attempted".
    """

    config = (config or ObservationConfig()).validate()

    entropy = _CountingEntropySource()
    with tempfile.TemporaryDirectory(prefix="ts-studio-r2-load-") as workspace:
        database = os.path.join(workspace, "observation.sqlite3")
        load = _execute_load(config, database, entropy)
        inspection_started = time.perf_counter()
        correctness = _inspect(config, database, load, entropy)
        inspection_seconds = time.perf_counter() - inspection_started

    if os.path.exists(workspace):
        raise LoadObservationError(
            "WORKSPACE_NOT_RELEASED",
            "the temporary observation workspace survived its own cleanup, which means a "
            "database handle outlived the run",
        )

    latency = summarize_samples(load["latency_samples"])
    proxy = summarize_samples(load["proxy_samples"])
    measured_seconds = load["measured_seconds"]

    record = {
        "schema_version": SCHEMA_VERSION,
        "task_id": TASK_ID,
        "contract_ref": CONTRACT_REF,
        "notice": json.loads(json.dumps(NOTICE)),
        "environment": _environment(),
        "config": config.to_dict(),
        "counts": {
            "planned_requests": config.planned_requests(),
            "total_requests": load["total_requests"],
            "warmup_requests": load["warmup_requests"],
            "measured_requests": load["measured_requests"],
            "concurrent_requests": load["concurrent_requests"],
            "rounds": config.rounds,
            "concurrency": config.concurrency,
            "warmup_requests_included_in_statistics": WARMUP_INCLUDED_IN_STATISTICS,
            "warmup_requests_counted_in_total_requests": True,
        },
        "elapsed": {
            "clock_source": STATISTICS_CLOCK_SOURCE,
            "wall_seconds": round(load["wall_seconds"], ROUNDING_DECIMALS),
            "warmup_seconds": round(load["warmup_seconds"], ROUNDING_DECIMALS),
            "measured_seconds": round(measured_seconds, ROUNDING_DECIMALS),
            "inspection_seconds": round(inspection_seconds, ROUNDING_DECIMALS),
            "wall_bound_seconds": config.wall_timeout_seconds,
        },
        "throughput": {
            "unit": "per_second",
            "basis": "measured requests over measured seconds; warm-up excluded",
            "requests_per_second": round(
                load["measured_requests"] / measured_seconds, ROUNDING_DECIMALS
            )
            if measured_seconds > 0
            else None,
            "rounds_per_second": round(config.rounds / measured_seconds, ROUNDING_DECIMALS)
            if measured_seconds > 0
            else None,
        },
        "latency_ms": {
            "unit": STATISTICS_UNIT,
            "method": PERCENTILE_METHOD,
            "interpolation": "none",
            "clock_source": STATISTICS_CLOCK_SOURCE,
            "observation_start": "the request's own send instant",
            "observation_end": "the response body has been fully read",
            "sample_population": "measured request outcomes",
            "warmup_requests_included": WARMUP_INCLUDED_IN_STATISTICS,
            "asserted_by_tests": False,
            "threshold": "none",
            **latency,
        },
        SERIALIZATION_PROXY_METRIC: {
            "unit": STATISTICS_UNIT,
            "method": PERCENTILE_METHOD,
            "interpolation": "none",
            "clock_source": STATISTICS_CLOCK_SOURCE,
            "is_proxy": True,
            "reported_separately_from_total_latency": True,
            "measures_internal_lock_acquisition_wait": False,
            "harness_instruments_internal_locks": False,
            "runtime_instrumentation_added_to_observed_code": False,
            "observation_start": (
                "the instant the synchronisation barrier released, recorded once by the "
                "barrier action when the last worker arrived and shared by the whole group"
            ),
            "observation_end": "http.client.getresponse() returned for that request",
            "measured_only_for": "barrier_released_concurrent_groups",
            "combines": [
                "operating_system_scheduler_wakeup_effects",
                "client_thread_dispatch_order",
                "loopback_connection_setup_and_transmission",
                "serialized_service_effects",
            ],
            "does_not_isolate": [
                "internal_lock_acquisition_wait",
                "database_write_lock_wait",
                "entropy_sampling_duration",
            ],
            "upper_bound_semantics": (
                "the observation end is a service-completion signal, so this is an upper "
                "bound on queueing and not a lower one; service time is inside the value"
            ),
            "asserted_by_tests": False,
            "threshold": "none",
            **proxy,
        },
        "correctness": correctness,
    }

    missing = [key for key in OUTPUT_TOP_LEVEL_KEYS if key not in record]
    unexpected = [key for key in record if key not in OUTPUT_TOP_LEVEL_KEYS]
    if missing or unexpected:
        raise LoadObservationError(
            "OUTPUT_CONTRACT_VIOLATED",
            f"top-level keys missing {missing!r} and unexpected {unexpected!r}",
        )
    return record


def _environment() -> dict[str, Any]:
    """Return the execution facts a reader needs to interpret an observation.

    Deliberately no ``platform.node()``, no ``getpass.getuser()``, no working directory: the
    machine's *kind* is what makes a latency number readable, and its *name* is only a way to
    put an operator's hostname in an evidence file.
    """

    info = time.get_clock_info("perf_counter")
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": int(os.cpu_count() or 0),
        "clock_source": STATISTICS_CLOCK_SOURCE,
        "clock_resolution_ns": int(round(info.resolution * 1_000_000_000)),
    }


def _execute_load(
    config: ObservationConfig, database: str, entropy: _CountingEntropySource
) -> dict[str, Any]:
    """Drive the slice over loopback and return the raw samples and per-round evidence."""

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

    # The handler the server built is subclassed rather than replaced, so every refusal,
    # header and route it implements is still the slice's own. All the subclass adds is the
    # ownership bookkeeping the module docstring explains, and it is installed before the
    # server is started so no request can be served by the unwrapped class.
    workers = _WorkerThreads()
    try:
        server.RequestHandlerClass = _releasing_handler(
            server.RequestHandlerClass, store, workers
        )
    except BaseException:
        server.server_close()
        store.close()
        raise

    # ``create_server`` has already bound and listened by the time it returns, so there is
    # nothing to poll for and no readiness sleep to justify.
    host, port = server.server_address[0], int(server.server_address[1])
    thread = serve_in_background(server)

    latency_samples: list[float] = []
    proxy_samples: list[float] = []
    bodies: list[dict[str, Any]] = []
    rounds: list[dict[str, Any]] = []
    warmup_seconds = 0.0
    measured_seconds = 0.0
    total_requests = 0
    concurrent_requests = 0
    workers_stopped = False

    deadline = _Deadline(config.wall_timeout_seconds)
    started_at = time.perf_counter()
    try:
        # -- warm-up: sequential, counted in the totals, excluded from the statistics ------
        # The first request through a fresh process pays for imports, the first connection
        # and the first SQLite read. Leaving that in the sample would not make the median
        # wrong so much as make it a measurement of start-up.
        warmup_started = time.perf_counter()
        for index in range(config.warmup_requests):
            deadline.check(f"warmup[{index}]")
            outcome = _call(host, port, "GET", "/api/state", None, deadline.budget("warmup"))
            if outcome.status != 200:
                raise LoadObservationError(
                    "REQUEST_REFUSED", f"warm-up was refused with {_refusal_code(outcome)}"
                )
            bodies.append(outcome.body)
            total_requests += 1
        warmup_seconds = time.perf_counter() - warmup_started

        measured_started = time.perf_counter()
        for round_index in range(1, config.rounds + 1):
            deadline.check(f"round[{round_index}]")
            before_reads, before_bytes = entropy.meter()

            # -- bets: concurrent, distinct request identifiers ---------------------------
            bet_requests = [
                (
                    "POST",
                    "/api/bets",
                    {
                        "request_id": f"R2LOAD-BET-{round_index:04d}-{worker:04d}",
                        "bet": {
                            "type": OBSERVED_BET_TYPE,
                            "selections": [],
                            "stake_units": config.stake_units_per_bet,
                        },
                    },
                )
                for worker in range(1, config.concurrency + 1)
            ]
            bets, bets_released = _run_group(
                host, port, bet_requests, deadline, f"bets[{round_index}]"
            )
            after_bets_reads, after_bets_bytes = entropy.meter()

            # -- spin: concurrent, one identical request identifier -----------------------
            # This is the race. Every worker submits the same ``request_id`` at the same
            # released instant; exactly one may draw and settle, and every other must be
            # handed the identical committed result rather than a second one.
            spin_request_id = f"R2LOAD-SPIN-{round_index:04d}"
            spin_requests = [
                ("POST", "/api/spin", {"request_id": spin_request_id})
                for _ in range(config.concurrency)
            ]
            spins, spins_released = _run_group(
                host, port, spin_requests, deadline, f"spin[{round_index}]"
            )
            after_spin_reads, after_spin_bytes = entropy.meter()

            # -- new round: one request, not a concurrent group ---------------------------
            new_round, _ = _run_group(
                host,
                port,
                [("POST", "/api/new-round", {"request_id": f"R2LOAD-NEWROUND-{round_index:04d}"})],
                deadline,
                f"new_round[{round_index}]",
            )
            after_round_reads, after_round_bytes = entropy.meter()

            for outcome in (*bets, *spins, *new_round):
                latency_samples.append(outcome.latency_ms)
                bodies.append(outcome.body)
                total_requests += 1
            # Only barrier-released concurrent groups get a proxy sample. The single
            # new-round request has no group to be dispatched within, so measuring a
            # "queue delay" for it would be measuring nothing.
            for outcome in bets:
                proxy_samples.append((outcome.serviced - bets_released) * 1000.0)
                concurrent_requests += 1
            for outcome in spins:
                proxy_samples.append((outcome.serviced - spins_released) * 1000.0)
                concurrent_requests += 1

            identities = {_spin_commit_identity(outcome.body) for outcome in spins}
            rounds.append(
                {
                    "round_index": round_index,
                    "spin_request_id": spin_request_id,
                    "submissions": len(spins),
                    "fresh_commits": sum(
                        1 for outcome in spins if outcome.body.get("replayed") is False
                    ),
                    "replays": sum(1 for outcome in spins if outcome.body.get("replayed") is True),
                    "distinct_commit_identities": len(identities),
                    "settlement_transaction_id": next(iter(identities))[0] if identities else None,
                    "round_id": next(iter(identities))[2] if identities else None,
                    "stake_units": config.concurrency * config.stake_units_per_bet,
                    "entropy_reads_bets_phase": after_bets_reads - before_reads,
                    "entropy_bytes_bets_phase": after_bets_bytes - before_bytes,
                    "entropy_reads_spin_phase": after_spin_reads - after_bets_reads,
                    "entropy_bytes_spin_phase": after_spin_bytes - after_bets_bytes,
                    "entropy_reads_new_round_phase": after_round_reads - after_spin_reads,
                    "entropy_bytes_new_round_phase": after_round_bytes - after_spin_bytes,
                }
            )
        measured_seconds = time.perf_counter() - measured_started
        wall_seconds = time.perf_counter() - started_at
    finally:
        # Shut down the way the slice's own ``main`` does -- stop serving, close the
        # listening socket, then close the store, never the other order, which would close a
        # database out from under a handler still allowed to answer -- with the second join
        # a harness needs and a launcher does not. ``shutdown`` stops the accept loop, so no
        # worker can be started after it returns and the enrolled list stops growing; every
        # worker already on it has released its own connection by the time its thread ends,
        # so joining them all is what makes "the handles are closed" a fact rather than an
        # expectation. The store is closed even if a join runs out of budget, because a
        # refusal is not a reason to leave the main thread's own connection open.
        shutdown = _Deadline(MAX_WALL_SECONDS)
        try:
            server.shutdown()
            server.server_close()
            thread.join(timeout=shutdown.budget("shutdown[serving]"))
            if thread.is_alive():
                raise LoadObservationError(
                    "SERVER_THREAD_DEADLINE_EXCEEDED",
                    "the serving thread did not stop within the shutdown bound",
                )
            for worker in workers.snapshot():
                worker.join(timeout=shutdown.budget("shutdown[worker]"))
                if worker.is_alive():
                    raise LoadObservationError(
                        # Distinct from the client-side ``WORKER_DEADLINE_EXCEEDED``: this
                        # one is a thread inside the observed server, not one of ours.
                        "SERVER_WORKER_DEADLINE_EXCEEDED",
                        "a request-serving worker did not stop within the shutdown bound",
                    )
            workers_stopped = True
        finally:
            store.close()

    return {
        "latency_samples": latency_samples,
        "proxy_samples": proxy_samples,
        "bodies": bodies,
        "rounds": rounds,
        "warmup_requests": config.warmup_requests,
        "measured_requests": len(latency_samples),
        "concurrent_requests": concurrent_requests,
        "total_requests": total_requests,
        "warmup_seconds": warmup_seconds,
        "measured_seconds": measured_seconds,
        "wall_seconds": wall_seconds,
        "server_thread_stopped": not thread.is_alive(),
        "worker_threads_started": workers.started(),
        "worker_threads_stopped": workers_stopped
        and not any(worker.is_alive() for worker in workers.snapshot()),
    }


def _inspect(
    config: ObservationConfig,
    database: str,
    load: Mapping[str, Any],
    entropy: _CountingEntropySource,
) -> dict[str, Any]:
    """Reopen the closed database and record every judged property over committed state.

    Everything here is read from storage after a full shutdown and a fresh open. That is the
    difference between "the process believes it settled once" and "the database says it
    settled once", and only the second survives a restart.
    """

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
        draw_records = store.count("draw_record")
        ledger_transactions = store.count("ledger_transaction")
        balances = store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT])

        transaction_ids = [
            entry["settlement_transaction_id"]
            for entry in load["rounds"]
            if entry["settlement_transaction_id"] is not None
        ]
        transactions = []
        for transaction_id in transaction_ids:
            stored = store.ledger_transaction(transaction_id)
            if stored is None:
                raise LoadObservationError(
                    "SETTLEMENT_MISSING", "a settlement reported by the slice is not in storage"
                )
            transactions.append(stored)
    finally:
        store.close()

    # -- draws and settlements ---------------------------------------------------------
    committed_round_ids = [entry["round_id"] for entry in load["rounds"]]
    single_draw_per_round = draw_records == config.rounds
    single_settlement_per_round = ledger_transactions == config.rounds
    unique_round_ids = len(set(committed_round_ids)) == config.rounds and None not in committed_round_ids
    unique_settlement_ids = len(set(transaction_ids)) == config.rounds

    # -- duplicate submission ----------------------------------------------------------
    duplicate_submissions = sum(entry["submissions"] - 1 for entry in load["rounds"])
    fresh_commits = sum(entry["fresh_commits"] for entry in load["rounds"])
    replays = sum(entry["replays"] for entry in load["rounds"])
    one_commit_per_group = all(entry["fresh_commits"] == 1 for entry in load["rounds"])
    all_callers_agree = all(entry["distinct_commit_identities"] == 1 for entry in load["rounds"])

    # -- entropy -----------------------------------------------------------------------
    # Rejection sampling makes the number of reads per draw variable, so no exact byte total
    # is claimed. What is claimed is where entropy was and was not spent: only inside a spin
    # group, at least once per group, and never in a phase that commits no draw.
    reads_total, bytes_total = entropy.meter()
    reads_outside_spin = sum(
        entry["entropy_reads_bets_phase"] + entry["entropy_reads_new_round_phase"]
        for entry in load["rounds"]
    )
    bytes_outside_spin = sum(
        entry["entropy_bytes_bets_phase"] + entry["entropy_bytes_new_round_phase"]
        for entry in load["rounds"]
    )
    spin_groups_that_drew = sum(1 for entry in load["rounds"] if entry["entropy_reads_spin_phase"] >= 1)

    # -- currency ----------------------------------------------------------------------
    float_paths = _find_floats(list(load["bodies"])) + _find_floats(transactions)
    currency_is_integer_only = not float_paths and all(
        isinstance(value, int) and not isinstance(value, bool) for value in balances.values()
    )

    # -- reconciliation ----------------------------------------------------------------
    player_balance = int(balances.get(PLAYER_ACCOUNT, 0))
    player_balance_delta = player_balance - config.opening_player_units
    ledger_player_delta = 0
    entries_sum_to_zero = True
    for transaction in transactions:
        entries = transaction.get("entries", [])
        if sum(int(entry["amount_units"]) for entry in entries) != 0:
            entries_sum_to_zero = False
        ledger_player_delta += sum(
            int(entry["amount_units"]) for entry in entries if entry["account_id"] == PLAYER_ACCOUNT
        )
    balance_delta_matches_ledger = player_balance_delta == ledger_player_delta

    # -- audit -------------------------------------------------------------------------
    event_ids = [event.get("event_id") for event in events]
    event_hashes = [event.get("event_hash") for event in events]
    actions = [event.get("action") for event in events]
    draw_events = actions.count("ROULETTE_RNG_DRAW")
    settled_events = actions.count("ROULETTE_ROUND_SETTLED")
    denial_events = actions.count("ROULETTE_DURABLE_SUBMIT_DENIED")
    void_events = actions.count("ROULETTE_ROUND_VOIDED")
    audited_round_ids = {
        _reference_after(event.get("resource_refs", []), "round://")
        for event in events
        if event.get("action") in ("ROULETTE_RNG_DRAW", "ROULETTE_ROUND_SETTLED")
    }
    audit_refs_globally_unique = (
        len(set(event_ids)) == len(events)
        and len(set(event_hashes)) == len(events)
        and None not in event_ids
        and None not in event_hashes
    )
    audit_events_match_committed_rounds = (
        draw_events == config.rounds
        and settled_events == config.rounds
        and denial_events == 0
        and void_events == 0
        and audited_round_ids == set(committed_round_ids)
    )
    audit_chain_verified_after_reload = list(chain_problems) == []

    properties = {
        "single_authoritative_draw_per_round": single_draw_per_round and unique_round_ids,
        "single_settlement_per_round": single_settlement_per_round and unique_settlement_ids,
        "balance_delta_matches_ledger": balance_delta_matches_ledger and entries_sum_to_zero,
        "currency_is_integer_only": currency_is_integer_only,
        "duplicate_request_id_commits_once": (
            one_commit_per_group
            and fresh_commits == config.rounds
            and replays == duplicate_submissions
            and reads_outside_spin == 0
            and bytes_outside_spin == 0
            and spin_groups_that_drew == config.rounds
        ),
        "duplicate_callers_observe_same_commit": all_callers_agree,
        "audit_refs_globally_unique": audit_refs_globally_unique,
        "audit_events_match_committed_rounds": audit_events_match_committed_rounds,
        "audit_chain_verified_after_reload": audit_chain_verified_after_reload,
        "bounded_execution": (
            load["total_requests"] == config.planned_requests()
            and load["total_requests"] <= MAX_TOTAL_REQUESTS
            and config.concurrency <= MAX_CONCURRENCY
            and config.rounds <= MAX_ROUNDS
            and config.wall_timeout_seconds <= MAX_WALL_SECONDS
            and bool(load["server_thread_stopped"])
            and bool(load["worker_threads_stopped"])
        ),
    }

    correctness = {
        "asserted": True,
        "timing_dependent": False,
        "inspected_after_reload": True,
        "properties": properties,
        "all_properties_hold": all(properties.values()),
        "failed_properties": sorted(name for name, held in properties.items() if not held),
        "evidence": {
            "draw_records": draw_records,
            "ledger_transactions": ledger_transactions,
            "committed_rounds": len(committed_round_ids),
            "distinct_round_ids": len(set(committed_round_ids)),
            "distinct_settlement_transaction_ids": len(set(transaction_ids)),
            "spin_submissions": sum(entry["submissions"] for entry in load["rounds"]),
            "duplicate_spin_submissions": duplicate_submissions,
            "spin_fresh_commits": fresh_commits,
            "spin_replays": replays,
            "rounds_with_one_fresh_commit": sum(
                1 for entry in load["rounds"] if entry["fresh_commits"] == 1
            ),
            "rounds_with_one_commit_identity": sum(
                1 for entry in load["rounds"] if entry["distinct_commit_identities"] == 1
            ),
            "entropy_reads_total": reads_total,
            "entropy_bytes_total": bytes_total,
            "entropy_reads_outside_spin_groups": reads_outside_spin,
            "entropy_bytes_outside_spin_groups": bytes_outside_spin,
            "spin_groups_that_consumed_entropy": spin_groups_that_drew,
            "entropy_material_recorded": False,
            "entropy_note": (
                "counts only; rejection sampling makes reads per draw variable, so no exact "
                "byte total is claimed and none is asserted"
            ),
            "float_values_found": len(float_paths),
            "opening_player_units": config.opening_player_units,
            "closing_player_units": player_balance,
            "player_balance_delta_units": player_balance_delta,
            "ledger_player_delta_units": ledger_player_delta,
            "closing_house_units": int(balances.get(HOUSE_ACCOUNT, 0)),
            "ledger_entries_sum_to_zero": entries_sum_to_zero,
            "audit_events_total": len(events),
            "audit_draw_events": draw_events,
            "audit_settled_events": settled_events,
            "audit_denial_events": denial_events,
            "audit_void_events": void_events,
            "distinct_audit_event_ids": len(set(event_ids)),
            "distinct_audit_event_hashes": len(set(event_hashes)),
            "audit_chain_problems_after_reload": len(list(chain_problems)),
            "server_worker_threads_started": int(load["worker_threads_started"]),
            "server_worker_threads_joined": bool(load["worker_threads_stopped"]),
        },
    }
    return correctness


# ---------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python scripts/observe_r2_load.py",
        description=(
            "R2-LOAD-0004 bounded local concurrent load observation. Correctness properties "
            "are asserted; latency and throughput are recorded as observations only and are "
            "never compared against a threshold, target or capacity promise."
        ),
    )
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--warmup-requests", type=int, default=DEFAULT_WARMUP_REQUESTS)
    parser.add_argument("--wall-seconds", type=int, default=DEFAULT_WALL_SECONDS)
    parser.add_argument("--stake-units", type=int, default=DEFAULT_STAKE_UNITS_PER_BET)
    parser.add_argument(
        "--host", default=DEFAULT_HOST, help=f"loopback only: {sorted(LOOPBACK_HOSTS)}"
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="0 picks a free port")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one observation, print the JSON record, and report only correctness in the code.

    The exit code answers "did the judged properties hold", never "was it fast enough".
    There is no timing exit path, because attaching one would turn an observation into the
    threshold this contract refuses to declare.
    """

    args = _parse_args(argv)
    config = ObservationConfig(
        concurrency=args.concurrency,
        rounds=args.rounds,
        warmup_requests=args.warmup_requests,
        wall_timeout_seconds=args.wall_seconds,
        stake_units_per_bet=args.stake_units,
        host=args.host,
        port=args.port,
    )
    try:
        record = run_observation(config)
    except LoadObservationError as refusal:
        sys.stderr.write(f"{refusal.code}: {refusal.message}\n")
        return 2
    sys.stdout.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    sys.stdout.flush()
    if not record["correctness"]["all_properties_hold"]:
        sys.stderr.write(
            "correctness properties did not hold: "
            + ", ".join(record["correctness"]["failed_properties"])
            + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
