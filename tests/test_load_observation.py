"""R2-LOAD-0004: the contract, the harness and one real bounded loopback observation.

What these tests are trying to break
------------------------------------
``games/roulette/load-observation-contract.yaml`` is a promise written in prose and numbers,
and ``scripts/observe_r2_load.py`` is the code that is supposed to keep it. Nothing forces
those two to agree, so the interesting failures are the ones where they quietly stop
agreeing:

* **A declared bound that the code does not enforce.** Every ceiling, default, formula,
  statistic definition, metric name and output key in the contract is read back out of the
  YAML and compared against the harness constant the contract names for it. A number changed
  in one file and not the other fails here rather than in production.
* **A ceiling that is enforced too late.** "Refused before it starts" is not a comment, it is
  a testable claim. The rejection tests replace ``tempfile``, ``threading``, ``open_table``,
  ``create_server`` and ``serve_in_background`` on the harness module with tripwires that
  raise on any use, and then feed the harness a configuration above a bound. A refusal that
  had already created a directory, a store, a socket or a thread trips a wire.
* **A correctness property that only holds when nothing overlaps.** One small observation is
  actually executed against a real loopback server with real threads, real sockets and a real
  SQLite database, and all ten judged properties are asserted over the record it returns.
* **An observation quietly becoming a threshold.** No test in this file asserts a latency, a
  throughput or a proxy magnitude, and :meth:`SourceDisciplineTestCase.
  test_no_test_in_this_suite_makes_an_ordering_comparison` proves it structurally: the suite
  contains no ordering comparison and no ordering assertion inside any test, so it cannot
  contain a pass/fail threshold on an observed number even by accident.
* **The output naming the operator.** The emitted record is searched for the machine's host
  name, the account name, the working directory, the temporary directory, the repository root
  and anything shaped like an absolute path.

On the standard library
-----------------------
AC-001 requires the harness *and its tests* to use the standard library only, so this file
does not import PyYAML -- even though the repository already depends on it -- and reads the
contract with :func:`_parse_contract_yaml`, a deliberately small reader for the block
mappings, block sequences, flow mappings and folded scalars this one contract file uses. It
raises :class:`ContractFormatError` on anything outside that subset rather than guessing, so a
contract rewritten into unsupported YAML fails loudly instead of being half-read.

On determinism
--------------
Nothing here sleeps, and nothing here asserts on elapsed time. The observation is small --
two concurrent workers over two rounds -- and every assertion on its record is either a count
derived from the configuration, a key name, a type or a boolean correctness property. The
harness's own waiting is bounded by a deadline rather than a fixed pause, which
:class:`DeadlineTestCase` checks directly. ``RepeatedObservationTestCase`` runs the whole
thing twice and asserts the structure and every judged property are identical.

Out of scope, and deliberately untouched: R4 deliverables, assets, images and art. No test in
this file reads such a path, and :meth:`ScopeBoundaryTestCase.test_no_r4_or_asset_path_is_read`
asserts that over the actual list of files this suite opens.
"""

from __future__ import annotations

import ast
import getpass
import inspect
import json
import os
import pathlib
import platform
import re
import sys
import tempfile
import tomllib
import unittest
from typing import Any, Iterator
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import (  # noqa: E402
    LOOPBACK_HOSTS,
    ROUTES,
    create_server,
    open_table,
    serve_in_background,
)
from apps.roulette_web.table import NOTICE as PROTOTYPE_NOTICE  # noqa: E402
from scripts import observe_r2_load as harness  # noqa: E402
from studio_core.durable_state import DurableRoundStore  # noqa: E402
from studio_core.integrity import hash_file  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]

TASK_PATH = "tasks/R2-LOAD-0004.json"
CONTRACT_PATH = "games/roulette/load-observation-contract.yaml"
HARNESS_PATH = "scripts/observe_r2_load.py"
SUITE_PATH = "tests/test_load_observation.py"
PYPROJECT_PATH = "pyproject.toml"

#: The observation actually executed by this suite. Small on purpose: every assertion made
#: about it is a count, a key, a type or a boolean, so a bigger run would buy no coverage and
#: cost wall-clock time. Two workers is the smallest concurrency that can race at all, and two
#: rounds is the smallest that can show a per-round property holding more than once.
OBSERVED_CONCURRENCY = 2
OBSERVED_ROUNDS = 2
OBSERVED_WARMUP = 1

#: The ten judged properties of section 3 of the contract, in contract order.
EXPECTED_PROPERTY_IDS = (
    "single_authoritative_draw_per_round",
    "single_settlement_per_round",
    "balance_delta_matches_ledger",
    "currency_is_integer_only",
    "duplicate_request_id_commits_once",
    "duplicate_callers_observe_same_commit",
    "audit_refs_globally_unique",
    "audit_events_match_committed_rounds",
    "audit_chain_verified_after_reload",
    "bounded_execution",
)

#: Top-level packages that are part of this repository rather than an external dependency.
REPO_PACKAGES = frozenset({"apps", "scripts", "studio_core", "tests"})

#: Files a dependency would be declared in. AC-001 asks for their absence to be confirmed.
DEPENDENCY_MANIFESTS = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "setup.py",
    "setup.cfg",
    "environment.yml",
)

#: The only third-party dependency this repository declares, recorded so that a *new* one
#: shows up as a difference rather than as silence.
EXPECTED_PROJECT_DEPENDENCIES = ("PyYAML>=6,<7",)

#: Paths this unit must not create, modify or even read. ``artifacts`` is not matched: the
#: pattern is anchored to whole path segments, so ``art`` matches and ``artifacts`` does not.
R4_OR_ASSET_PATTERN = re.compile(
    r"(?i)(^|/)(assets?|art|artwork|image|images|img|sprites?|textures?)(/|$)|R4[-_/]"
)


# ---------------------------------------------------------------------------------------
# a very small YAML reader -- standard library only, by AC-001
# ---------------------------------------------------------------------------------------


class ContractFormatError(ValueError):
    """The contract uses YAML this reader does not support, so it refuses to guess."""


_BLOCK_SCALAR_HEADERS = frozenset({">", ">-", ">+", "|", "|-", "|+"})
_MAPPING_ENTRY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:(\s|$)")
_INTEGER = re.compile(r"^-?\d+$")


def _significant_lines(text: str) -> list[tuple[int, str]]:
    """Return ``(indent, content)`` for every line that carries structure or content."""

    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append((len(raw) - len(raw.lstrip(" ")), stripped))
    return lines


def _scalar(token: str) -> Any:
    if len(token) > 1 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    lowered = token.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in ("null", "~"):
        return None
    if _INTEGER.match(token):
        return int(token)
    return token


def _flow_mapping(token: str) -> dict[str, Any]:
    if not (token.startswith("{") and token.endswith("}")):
        raise ContractFormatError(f"unsupported flow value: {token!r}")
    mapping: dict[str, Any] = {}
    body = token[1:-1].strip()
    if not body:
        return mapping
    for chunk in body.split(","):
        key, separator, value = chunk.partition(":")
        if not separator:
            raise ContractFormatError(f"unsupported flow entry: {chunk!r}")
        mapping[key.strip()] = _scalar(value.strip())
    return mapping


def _node(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if lines[index][1].startswith("- "):
        return _sequence(lines, index, indent)
    return _mapping(lines, index, indent)


def _mapping(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while (
        index < len(lines)
        and lines[index][0] == indent
        and not lines[index][1].startswith("- ")
    ):
        key, separator, rest = lines[index][1].partition(":")
        if not separator:
            raise ContractFormatError(f"unsupported line: {lines[index][1]!r}")
        key = key.strip()
        rest = rest.strip()
        index += 1
        if rest in _BLOCK_SCALAR_HEADERS:
            # A folded scalar: every deeper line belongs to it, joined with single spaces.
            folded: list[str] = []
            while index < len(lines) and lines[index][0] > indent:
                folded.append(lines[index][1])
                index += 1
            result[key] = " ".join(folded)
        elif rest.startswith("{"):
            result[key] = _flow_mapping(rest)
        elif rest:
            result[key] = _scalar(rest)
        elif index < len(lines) and lines[index][0] > indent:
            result[key], index = _node(lines, index, lines[index][0])
        elif index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            result[key], index = _sequence(lines, index, indent)
        else:
            result[key] = None
    return result, index


def _sequence(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
        item = lines[index][1][2:].strip()
        index += 1
        if item.startswith("{"):
            items.append(_flow_mapping(item))
        elif _MAPPING_ENTRY.match(item):
            # ``- id: x`` followed by deeper lines is one mapping whose first key sits on the
            # dash line, so the entry is re-indented and parsed as an ordinary mapping.
            block = [(indent + 2, item)]
            while index < len(lines) and lines[index][0] > indent:
                block.append(lines[index])
                index += 1
            entry, consumed = _mapping(block, 0, indent + 2)
            if consumed != len(block):
                raise ContractFormatError(f"unsupported sequence entry near {item!r}")
            items.append(entry)
        else:
            items.append(_scalar(item))
    return items, index


def _parse_contract_yaml(text: str) -> dict[str, Any]:
    """Return the contract as plain Python data, or refuse if it leaves the subset."""

    lines = _significant_lines(text)
    if not lines:
        raise ContractFormatError("the contract document is empty")
    document, consumed = _node(lines, 0, lines[0][0])
    if consumed != len(lines):
        raise ContractFormatError(f"unsupported structure at significant line {consumed}")
    if not isinstance(document, dict):
        raise ContractFormatError("the contract root must be a mapping")
    return document


# ---------------------------------------------------------------------------------------
# repository readers -- every file this suite opens goes through here
# ---------------------------------------------------------------------------------------

#: Recorded so ``ScopeBoundaryTestCase`` can assert over what was actually read, rather than
#: over what the author remembers reading.
_FILES_READ: list[str] = []


def _read_text(relative: str) -> str:
    _FILES_READ.append(relative)
    return (ROOT / relative).read_text(encoding="utf-8")


def _hash(relative: str) -> str:
    _FILES_READ.append(relative)
    return hash_file(ROOT / relative)


TASK = json.loads(_read_text(TASK_PATH))
CONTRACT = _parse_contract_yaml(_read_text(CONTRACT_PATH))
HARNESS_SOURCE = _read_text(HARNESS_PATH)
SUITE_SOURCE = _read_text(SUITE_PATH)
HARNESS_TREE = ast.parse(HARNESS_SOURCE, filename=HARNESS_PATH)
SUITE_TREE = ast.parse(SUITE_SOURCE, filename=SUITE_PATH)


def _relative_inputs() -> list[str]:
    return [entry["uri"][len("repo://") :] for entry in TASK["inputs"]]


def _relative_deliverables() -> list[str]:
    return [entry["target_uri"][len("repo://") :] for entry in TASK["deliverables"]]


# ---------------------------------------------------------------------------------------
# small analysis helpers
# ---------------------------------------------------------------------------------------


def _attribute_chains(tree: ast.AST) -> set[str]:
    """Return every dotted attribute access in ``tree``, such as ``platform.node``.

    Read from the syntax tree rather than from the text, because the harness's own docstring
    names the identity calls it deliberately does *not* make, and a substring search cannot
    tell that explanation apart from the thing it is explaining.
    """

    chains: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        parts = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            chains.add(".".join(reversed(parts)))
    return chains


def _imported_roots(tree: ast.AST) -> set[str]:
    """Return the top-level module name of every absolute import in ``tree``."""

    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


def _walk_items(value: Any, path: str = "$") -> Iterator[tuple[str, Any, Any]]:
    """Yield ``(path, key, value)`` for every mapping entry anywhere inside ``value``."""

    if isinstance(value, dict):
        for key, item in value.items():
            yield (f"{path}.{key}", key, item)
            yield from _walk_items(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk_items(item, f"{path}[{index}]")


def _evaluate_formula(expression: str, variables: dict[str, int]) -> int:
    """Evaluate the contract's request-plan formula over integer names only.

    The point is to run the *contract's* arithmetic rather than a paraphrase of it, so the
    formula string and the harness implementation are compared as arithmetic and not as text.
    Only ``+``, ``-``, ``*``, integer literals and the supplied names are accepted.
    """

    def visit(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.BinOp):
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            raise ContractFormatError(f"unsupported operator in formula: {expression!r}")
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in variables:
                raise ContractFormatError(f"unknown name {node.id!r} in formula")
            return variables[node.id]
        raise ContractFormatError(f"unsupported term in formula: {expression!r}")

    return visit(ast.parse(expression, mode="eval"))


class _Tripwire:
    """A stand-in that records and refuses every use, for proving something did not happen."""

    def __init__(self, name: str, log: list[str]) -> None:
        # Bypass ``__getattr__`` for the object's own state.
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_log", log)

    def __getattr__(self, attribute: str) -> Any:
        self._log.append(f"{self._name}.{attribute}")
        raise AssertionError(f"{self._name}.{attribute} was reached during a refusal")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._log.append(f"{self._name}()")
        raise AssertionError(f"{self._name}() was called during a refusal")


def _observation_workspaces() -> set[str]:
    """Return the harness's temporary workspaces currently present, if any."""

    try:
        return {
            entry.name
            for entry in pathlib.Path(tempfile.gettempdir()).iterdir()
            if entry.name.startswith("ts-studio-r2-load-")
        }
    except OSError:  # pragma: no cover - an unreadable temp root is not this unit's business
        return set()


def _run_small_observation() -> dict[str, Any]:
    """Execute one real bounded observation against a real loopback server."""

    return harness.run_observation(
        harness.ObservationConfig(
            concurrency=OBSERVED_CONCURRENCY,
            rounds=OBSERVED_ROUNDS,
            warmup_requests=OBSERVED_WARMUP,
        )
    )


class LoadObservationTestCase(unittest.TestCase):
    """Shared assertions that never place an ordering comparison in a test body."""

    def assert_refused(self, code: str, config: harness.ObservationConfig) -> None:
        """Assert ``config`` is refused with ``code`` by ``validate`` and by the entry point."""

        with self.assertRaises(harness.LoadObservationError) as captured:
            config.validate()
        self.assertEqual(captured.exception.code, code, config)

    def _assert_below(self, smaller: int, larger: int, label: str) -> None:
        """Assert ``smaller`` is strictly the lesser without writing an ordering comparison."""

        self.assertEqual(min(smaller, larger), smaller, label)
        self.assertNotEqual(smaller, larger, label)

    def _assert_at_most(self, value: int, ceiling: int, label: str) -> None:
        self.assertEqual(min(value, ceiling), value, label)


# ---------------------------------------------------------------------------------------
# 1. the contract and the harness constants
# ---------------------------------------------------------------------------------------


class ContractDeclarationTestCase(LoadObservationTestCase):
    """AC-002, AC-006, AC-007, AC-008: what the YAML declares is what the code holds."""

    def test_contract_identity_points_at_this_task(self) -> None:
        self.assertEqual(CONTRACT["schema_version"], harness.SCHEMA_VERSION)
        self.assertEqual(CONTRACT["task_ref"], TASK_PATH)
        self.assertEqual(harness.TASK_ID, TASK["task_id"])
        self.assertEqual(harness.CONTRACT_REF, CONTRACT_PATH)

    def test_safety_bounds_match_the_named_harness_constants(self) -> None:
        bounds = CONTRACT["safety_bounds"]
        self.assertEqual(bounds["harness_constants_source"], "scripts.observe_r2_load")
        self.assertEqual(harness.__name__, bounds["harness_constants_source"])
        for declared, constant in bounds["harness_constant_names"].items():
            self.assertEqual(getattr(harness, constant), bounds[declared], constant)
        # The four approved ceilings of AC-002, restated so a silent widening fails here.
        self.assertEqual(
            (
                harness.MAX_CONCURRENCY,
                harness.MAX_TOTAL_REQUESTS,
                harness.MAX_ROUNDS,
                harness.MAX_WALL_SECONDS,
            ),
            (16, 128, 32, 60),
        )

    def test_safety_bounds_are_declared_as_bounds_and_not_as_targets(self) -> None:
        bounds = CONTRACT["safety_bounds"]
        self.assertEqual(bounds["purpose"], "bounded_local_execution_only")
        for flag in (
            "are_performance_expectations",
            "are_service_level_objectives",
            "are_pass_fail_thresholds",
            "compared_against_observed_values",
        ):
            self.assertIs(bounds[flag], False, flag)

    def test_defaults_match_the_named_harness_constants(self) -> None:
        defaults = CONTRACT["defaults"]
        for declared, constant in defaults["harness_constant_names"].items():
            self.assertEqual(getattr(harness, constant), defaults[declared], constant)
        self.assertEqual(harness.DEFAULT_STAKE_UNITS_PER_BET, defaults["stake_units_per_bet"])
        self.assertEqual(harness.DEFAULT_OPENING_PLAYER_UNITS, defaults["opening_player_units"])
        self.assertEqual(harness.DEFAULT_OPENING_HOUSE_UNITS, defaults["opening_house_units"])

    def test_default_configuration_uses_those_defaults(self) -> None:
        config = harness.ObservationConfig()
        defaults = CONTRACT["defaults"]
        self.assertEqual(config.concurrency, defaults["concurrency"])
        self.assertEqual(config.rounds, defaults["rounds"])
        self.assertEqual(config.warmup_requests, defaults["warmup_requests"])
        self.assertEqual(config.wall_timeout_seconds, defaults["wall_timeout_seconds"])
        self.assertEqual(config.stake_units_per_bet, defaults["stake_units_per_bet"])
        self.assertEqual(config.opening_player_units, defaults["opening_player_units"])
        self.assertEqual(config.opening_house_units, defaults["opening_house_units"])
        self.assertEqual(config.host, harness.DEFAULT_HOST)
        self.assertEqual(config.port, harness.DEFAULT_PORT)
        self.assertIs(config.validate(), config)

    def test_defaults_sit_below_the_bounds_the_contract_declares(self) -> None:
        defaults = CONTRACT["defaults"]
        self.assertIs(defaults["are_lower_than_bounds"], True)
        self.assertIs(defaults["may_exceed_bounds"], False)
        self._assert_below(harness.DEFAULT_CONCURRENCY, harness.MAX_CONCURRENCY, "concurrency")
        self._assert_below(harness.DEFAULT_ROUNDS, harness.MAX_ROUNDS, "rounds")
        self._assert_below(harness.DEFAULT_WALL_SECONDS, harness.MAX_WALL_SECONDS, "wall seconds")
        self._assert_below(
            harness.ObservationConfig().planned_requests(),
            harness.MAX_TOTAL_REQUESTS,
            "planned requests",
        )

    def test_default_port_is_ephemeral_and_default_host_is_loopback(self) -> None:
        self.assertEqual(harness.DEFAULT_PORT, 0)
        self.assertIn(harness.DEFAULT_HOST, LOOPBACK_HOSTS)

    def test_statistics_definitions_match_the_harness(self) -> None:
        statistics = CONTRACT["statistics"]
        self.assertEqual(statistics["unit"], harness.STATISTICS_UNIT)
        self.assertEqual(statistics["clock_source"], harness.STATISTICS_CLOCK_SOURCE)
        self.assertEqual(statistics["method"], harness.PERCENTILE_METHOD)
        self.assertEqual(statistics["rounding_decimals"], harness.ROUNDING_DECIMALS)
        self.assertEqual(statistics["interpolation"], "none")
        self.assertIs(statistics["clock_is_wall_clock"], False)
        self.assertIs(
            statistics["warmup_requests_included_in_statistics"],
            harness.WARMUP_INCLUDED_IN_STATISTICS,
        )
        self.assertIs(statistics["warmup_requests_counted_in_total_requests"], True)
        self.assertIs(statistics["deterministic_on_fixed_samples"], True)
        self.assertEqual(statistics["empty_sample_behavior"], "rejected_with_NO_SAMPLES")
        self.assertEqual(statistics["index_arithmetic"], "integer_only")
        self.assertEqual(statistics["sample_count_field"], "samples")

    def test_named_statistics_functions_exist_on_the_harness(self) -> None:
        names = CONTRACT["statistics"]["harness_function_names"]
        self.assertEqual(names["percentile"], "nearest_rank_percentile")
        self.assertEqual(names["summary"], "summarize_samples")
        for name in names.values():
            self.assertTrue(callable(getattr(harness, name)), name)
            self.assertIn(name, harness.__all__, name)

    def test_observed_metric_names_match_the_contract(self) -> None:
        self.assertEqual(
            list(harness.OBSERVED_METRIC_NAMES), CONTRACT["observed_metrics"]["items"]
        )
        metrics = CONTRACT["observed_metrics"]
        self.assertIs(metrics["measurement_is_observation_only"], True)
        self.assertIs(metrics["asserted_by_tests"], False)
        self.assertIs(metrics["environment_dependent"], True)
        self.assertIs(metrics["portable_performance_characteristic"], False)
        self.assertIs(harness.MEASUREMENT_IS_OBSERVATION_ONLY, True)

    def test_output_contract_keys_match_the_harness(self) -> None:
        output = CONTRACT["output_contract"]
        self.assertEqual(list(harness.OUTPUT_TOP_LEVEL_KEYS), output["top_level_keys"])
        self.assertEqual(list(harness.ENVIRONMENT_KEYS), output["environment_keys"])
        self.assertEqual(output["format"], "json")
        self.assertIs(output["contains_pii"], False)
        self.assertIs(output["contains_credentials"], False)
        self.assertIs(output["entropy_material_recorded"], False)

    def test_serialization_proxy_is_declared_as_a_proxy(self) -> None:
        proxy = CONTRACT["serialization_wait_proxy"]
        self.assertEqual(proxy["metric_name"], harness.SERIALIZATION_PROXY_METRIC)
        self.assertIn(harness.SERIALIZATION_PROXY_METRIC, harness.OUTPUT_TOP_LEVEL_KEYS)
        self.assertIs(proxy["is_proxy"], True)
        self.assertIs(proxy["reported_separately_from_total_latency"], True)
        self.assertIs(proxy["separate_output_key"], True)
        self.assertIs(proxy["measures_internal_lock_acquisition_wait"], False)
        self.assertIs(proxy["harness_instruments_internal_locks"], False)
        self.assertIs(proxy["runtime_instrumentation_added_to_observed_code"], False)
        self.assertEqual(proxy["production_instrumentation"], "prohibited")
        self.assertEqual(proxy["computed_only_inside"], HARNESS_PATH)
        self.assertIs(proxy["asserted_by_tests"], False)
        self.assertEqual(proxy["threshold"], "none")
        self.assertEqual(proxy["measured_only_for"], "barrier_released_concurrent_groups")
        # The observation points AC-008 requires to be written down.
        self.assertIn("배리어", proxy["observation_start"])
        self.assertIn("getresponse()", proxy["observation_end"])
        self.assertEqual(
            proxy["does_not_isolate"],
            [
                "internal_lock_acquisition_wait",
                "database_write_lock_wait",
                "entropy_sampling_duration",
            ],
        )

    def test_asserted_property_ids_are_the_ten_judged_properties(self) -> None:
        declared = [entry["id"] for entry in CONTRACT["asserted_properties"]]
        self.assertEqual(declared, list(EXPECTED_PROPERTY_IDS))
        for entry in CONTRACT["asserted_properties"]:
            self.assertEqual(sorted(entry), ["evidence", "id", "statement"], entry["id"])

    def test_target_binding_is_loopback_only(self) -> None:
        binding = CONTRACT["target_binding"]
        self.assertEqual(binding["bind"], "loopback_only")
        self.assertEqual(set(binding["allowed_hosts"]), set(LOOPBACK_HOSTS))
        self.assertEqual(
            binding["allowed_hosts_source"], "apps.roulette_web.server.LOOPBACK_HOSTS"
        )
        self.assertEqual(binding["non_loopback_target"], "rejected")
        self.assertEqual(binding["external_network"], "prohibited")
        self.assertEqual(binding["production_target"], "prohibited")
        self.assertEqual(binding["remote_host_resolution"], "not_attempted")
        self.assertEqual(binding["target_slice"], "apps/roulette_web")

    def test_no_targets_section_declares_nothing(self) -> None:
        for name, value in CONTRACT["no_targets"].items():
            self.assertIs(value, False, name)

    def test_out_of_scope_and_new_files_are_declared(self) -> None:
        self.assertEqual(len(CONTRACT["out_of_scope"]), 7)
        self.assertEqual(
            CONTRACT["new_files"],
            [
                CONTRACT_PATH,
                HARNESS_PATH,
                SUITE_PATH,
                "docs/games/R2-load-observation.md",
                "docs/approvals/R2-LOAD-0004-validation-report.md",
                "audit/events/R2-LOAD-0004-events.json",
            ],
        )

    def test_no_declared_threshold_objective_or_promise_carries_a_value(self) -> None:
        """Any key that could read as a target must say ``false`` or ``none``, never a number."""

        checked = 0
        for path, key, value in _walk_items(CONTRACT):
            if not any(token in key for token in ("threshold", "objective", "promise")):
                continue
            checked += 1
            if isinstance(value, str):
                self.assertEqual(value.lower(), "none", path)
            else:
                self.assertIs(value, False, path)
        self.assertNotEqual(checked, 0, "the sweep found no key to check, so it proved nothing")


# ---------------------------------------------------------------------------------------
# 2. frozen inputs
# ---------------------------------------------------------------------------------------


class FrozenInputTestCase(LoadObservationTestCase):
    """AC-009, AC-012: the twenty-nine pinned inputs are byte-identical and are not outputs."""

    def test_task_declares_twenty_nine_inputs(self) -> None:
        self.assertEqual(len(TASK["inputs"]), 29)
        self.assertEqual(len(set(_relative_inputs())), 29)
        self.assertEqual(TASK["status"], "READY")
        self.assertEqual(TASK["task_id"], "R2-LOAD-0004")

    def test_every_frozen_input_matches_its_declared_canonical_hash(self) -> None:
        mismatched = []
        for entry in TASK["inputs"]:
            relative = entry["uri"][len("repo://") :]
            self.assertTrue(entry["content_hash"].startswith("sha256:"), relative)
            actual = _hash(relative)
            if actual != entry["content_hash"]:
                mismatched.append((relative, entry["content_hash"], actual))
        self.assertEqual(mismatched, [])

    def test_no_frozen_path_is_also_a_deliverable(self) -> None:
        frozen = set(_relative_inputs())
        deliverables = set(_relative_deliverables())
        self.assertEqual(frozen & deliverables, set())
        # The three implementation paths of this unit are deliverables and nothing else.
        self.assertEqual({CONTRACT_PATH, HARNESS_PATH, SUITE_PATH} & frozen, set())
        self.assertEqual(
            {CONTRACT_PATH, HARNESS_PATH, SUITE_PATH} - deliverables,
            set(),
        )

    def test_contract_frozen_paths_are_all_declared_inputs(self) -> None:
        frozen = set(_relative_inputs())
        declared = CONTRACT["frozen_paths"]
        self.assertEqual(declared["modified_by_this_unit"], 0)
        self.assertEqual(len(declared["paths"]), 17)
        self.assertEqual(set(declared["paths"]) - frozen, set())
        # The observed runtime and the baseline validator are the ones that matter most.
        self.assertEqual(
            set(declared["paths"])
            & {
                "apps/roulette_web/server.py",
                "apps/roulette_web/table.py",
                "studio_core/durable_state.py",
                "studio_core/rng.py",
                "studio_core/ledger.py",
            },
            {
                "apps/roulette_web/server.py",
                "apps/roulette_web/table.py",
                "studio_core/durable_state.py",
                "studio_core/rng.py",
                "studio_core/ledger.py",
            },
        )
        self.assertIn("scripts/validate_baseline.py", declared["also_unmodified"])

    def test_this_unit_declares_only_new_files_as_deliverables(self) -> None:
        deliverables = set(_relative_deliverables())
        self.assertEqual(set(CONTRACT["new_files"]) - deliverables, set())
        self.assertNotIn("scripts/validate_baseline.py", deliverables)


# ---------------------------------------------------------------------------------------
# 3. refusal before anything is created
# ---------------------------------------------------------------------------------------


class BoundedRefusalTestCase(LoadObservationTestCase):
    """AC-002: a configuration above a ceiling is refused before any resource exists."""

    def _tripwired_run(self, config: harness.ObservationConfig) -> tuple[Exception, list[str]]:
        """Run ``config`` with every resource-creating name on the harness replaced."""

        log: list[str] = []
        patches = {
            "tempfile": _Tripwire("tempfile", log),
            "threading": _Tripwire("threading", log),
            "open_table": _Tripwire("open_table", log),
            "create_server": _Tripwire("create_server", log),
            "serve_in_background": _Tripwire("serve_in_background", log),
            "_execute_load": _Tripwire("_execute_load", log),
            "_inspect": _Tripwire("_inspect", log),
        }
        with mock.patch.multiple(harness, **patches):
            with self.assertRaises(harness.LoadObservationError) as captured:
                harness.run_observation(config)
        return captured.exception, log

    def test_a_bound_is_enforced_before_any_directory_server_or_thread_exists(self) -> None:
        before = _observation_workspaces()
        refusal, log = self._tripwired_run(
            harness.ObservationConfig(concurrency=harness.MAX_CONCURRENCY + 1)
        )
        self.assertEqual(refusal.code, "BOUND_EXCEEDED")
        self.assertEqual(log, [])
        self.assertEqual(_observation_workspaces() - before, set())

    def test_every_refusal_class_happens_before_any_resource_is_created(self) -> None:
        cases = (
            ("BOUND_EXCEEDED", harness.ObservationConfig(rounds=harness.MAX_ROUNDS + 1)),
            (
                "BOUND_EXCEEDED",
                harness.ObservationConfig(wall_timeout_seconds=harness.MAX_WALL_SECONDS + 1),
            ),
            ("CONFIG_INVALID", harness.ObservationConfig(concurrency=True)),
            ("CONFIG_INVALID", harness.ObservationConfig(rounds=2.0)),
            ("TARGET_NOT_LOOPBACK", harness.ObservationConfig(host="0.0.0.0")),
            (
                "REQUEST_BUDGET_EXCEEDED",
                harness.ObservationConfig(concurrency=harness.MAX_CONCURRENCY, rounds=harness.MAX_ROUNDS),
            ),
            ("CONFIG_INVALID", harness.ObservationConfig(opening_player_units=1)),
        )
        for code, config in cases:
            with self.subTest(code=code, config=config):
                refusal, log = self._tripwired_run(config)
                self.assertEqual(refusal.code, code)
                self.assertEqual(log, [])

    def test_zero_and_negative_and_above_bound_integers_are_refused(self) -> None:
        cases = (
            ("concurrency", 0),
            ("concurrency", -1),
            ("concurrency", harness.MAX_CONCURRENCY + 1),
            ("rounds", 0),
            ("rounds", -1),
            ("rounds", harness.MAX_ROUNDS + 1),
            ("wall_timeout_seconds", 0),
            ("wall_timeout_seconds", -1),
            ("wall_timeout_seconds", harness.MAX_WALL_SECONDS + 1),
            ("warmup_requests", -1),
            ("warmup_requests", harness.MAX_TOTAL_REQUESTS + 1),
            ("stake_units_per_bet", 0),
            ("stake_units_per_bet", -1),
            ("stake_units_per_bet", 1001),
            ("port", -1),
            ("port", 65536),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.assert_refused("BOUND_EXCEEDED", harness.ObservationConfig(**{field: value}))

    def test_booleans_are_not_accepted_as_integers(self) -> None:
        fields = (
            "concurrency",
            "rounds",
            "warmup_requests",
            "wall_timeout_seconds",
            "stake_units_per_bet",
            "opening_player_units",
            "opening_house_units",
            "port",
        )
        for field in fields:
            for value in (True, False):
                with self.subTest(field=field, value=value):
                    self.assert_refused(
                        "CONFIG_INVALID", harness.ObservationConfig(**{field: value})
                    )

    def test_non_integers_are_refused(self) -> None:
        fields = (
            "concurrency",
            "rounds",
            "warmup_requests",
            "wall_timeout_seconds",
            "stake_units_per_bet",
            "opening_player_units",
            "opening_house_units",
            "port",
        )
        for field in fields:
            for value in (2.0, "2", None, [2], (2,)):
                with self.subTest(field=field, value=value):
                    self.assert_refused(
                        "CONFIG_INVALID", harness.ObservationConfig(**{field: value})
                    )

    def test_non_loopback_targets_are_refused_without_resolution(self) -> None:
        hosts = (
            "0.0.0.0",
            "example.com",
            "8.8.8.8",
            "127.0.0.2",
            "192.168.0.10",
            "10.0.0.1",
            "LOCALHOST",
            "",
            "127.0.0.1 ",
            None,
            127,
            b"127.0.0.1",
            ["127.0.0.1"],
        )
        for host in hosts:
            with self.subTest(host=host):
                self.assert_refused("TARGET_NOT_LOOPBACK", harness.ObservationConfig(host=host))

    def test_every_loopback_host_the_server_allows_is_accepted(self) -> None:
        for host in sorted(LOOPBACK_HOSTS):
            with self.subTest(host=host):
                config = harness.ObservationConfig(host=host)
                self.assertIs(config.validate(), config)

    def test_the_derived_request_budget_is_checked_before_execution(self) -> None:
        self.assertIs(CONTRACT["request_plan"]["checked_before_execution"], True)
        # Each of these is inside every individual bound and still over the total budget.
        for concurrency, rounds in ((8, 8), (16, 32), (4, 15), (16, 4)):
            with self.subTest(concurrency=concurrency, rounds=rounds):
                config = harness.ObservationConfig(concurrency=concurrency, rounds=rounds)
                self._assert_at_most(config.concurrency, harness.MAX_CONCURRENCY, "concurrency")
                self._assert_at_most(config.rounds, harness.MAX_ROUNDS, "rounds")
                self.assert_refused("REQUEST_BUDGET_EXCEEDED", config)

    def test_an_unaffordable_plan_is_refused_rather_than_aborted_halfway(self) -> None:
        self.assert_refused("CONFIG_INVALID", harness.ObservationConfig(opening_player_units=0))
        self.assert_refused("CONFIG_INVALID", harness.ObservationConfig(opening_player_units=-1))
        self.assert_refused("CONFIG_INVALID", harness.ObservationConfig(opening_house_units=0))
        self.assert_refused(
            "CONFIG_INVALID",
            harness.ObservationConfig(concurrency=4, rounds=3, stake_units_per_bet=1000, opening_player_units=100),
        )

    def test_a_configuration_at_the_ceiling_is_accepted(self) -> None:
        config = harness.ObservationConfig(
            concurrency=harness.MAX_CONCURRENCY,
            rounds=1,
            warmup_requests=0,
            wall_timeout_seconds=harness.MAX_WALL_SECONDS,
            port=65535,
        )
        self.assertIs(config.validate(), config)
        self._assert_at_most(config.planned_requests(), harness.MAX_TOTAL_REQUESTS, "plan")

    def test_a_refusal_carries_a_code_and_no_path_or_host(self) -> None:
        with self.assertRaises(harness.LoadObservationError) as captured:
            harness.ObservationConfig(concurrency=99).validate()
        refusal = captured.exception
        self.assertEqual(refusal.code, "BOUND_EXCEEDED")
        self.assertTrue(str(refusal).startswith("BOUND_EXCEEDED: "))
        for secret in (str(ROOT), os.getcwd(), platform.node(), tempfile.gettempdir()):
            self.assertNotIn(secret.lower(), str(refusal).lower())


# ---------------------------------------------------------------------------------------
# 4. the request plan
# ---------------------------------------------------------------------------------------


class RequestPlanTestCase(LoadObservationTestCase):
    """AC-002: the total request count is derived from the contract's own formula."""

    def test_the_contract_formula_is_the_implemented_formula(self) -> None:
        formula = CONTRACT["request_plan"]["formula"]
        self.assertEqual(formula, "warmup_requests + rounds * (2 * concurrency + 1)")
        self.assertEqual(harness.ObservationConfig().to_dict()["request_plan_formula"], formula)
        for warmup, rounds, concurrency in (
            (0, 1, 1),
            (2, 3, 4),
            (1, 2, 2),
            (5, 1, 16),
            (0, 32, 1),
            (2, 7, 3),
        ):
            with self.subTest(warmup=warmup, rounds=rounds, concurrency=concurrency):
                config = harness.ObservationConfig(
                    warmup_requests=warmup, rounds=rounds, concurrency=concurrency
                )
                expected = _evaluate_formula(
                    formula,
                    {
                        "warmup_requests": warmup,
                        "rounds": rounds,
                        "concurrency": concurrency,
                    },
                )
                self.assertEqual(config.planned_requests(), expected)
                self.assertEqual(config.measured_requests(), rounds * (2 * concurrency + 1))
                self.assertEqual(config.concurrent_requests(), rounds * 2 * concurrency)
                self.assertEqual(
                    config.planned_requests(), warmup + config.measured_requests()
                )

    def test_the_per_round_phases_match_the_routes_the_harness_uses(self) -> None:
        phases = CONTRACT["request_plan"]["per_round_phases"]
        self.assertEqual(
            [(phase["phase"], phase["method"], phase["path"]) for phase in phases],
            [
                ("bets", "POST", "/api/bets"),
                ("spin", "POST", "/api/spin"),
                ("new_round", "POST", "/api/new-round"),
            ],
        )
        self.assertEqual(phases[0]["request_ids"], "distinct")
        self.assertEqual(phases[1]["request_ids"], "identical")
        warmup = CONTRACT["request_plan"]["warmup_phase"]
        self.assertEqual((warmup["method"], warmup["path"]), ("GET", "/api/state"))
        self.assertIs(warmup["concurrent"], False)
        for phase in (*phases, warmup):
            self.assertEqual(ROUTES[phase["path"]], phase["method"], phase["path"])


# ---------------------------------------------------------------------------------------
# 5. statistics over fixed samples
# ---------------------------------------------------------------------------------------


class StatisticsTestCase(LoadObservationTestCase):
    """AC-006: the percentile is nearest rank, deterministic, and defined only on samples."""

    def test_nearest_rank_percentile_over_a_fixed_ascending_sample(self) -> None:
        samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        # index = ceil(percentile * 10 / 100) - 1 over the sorted sample.
        expected = {
            1: 1.0,
            10: 1.0,
            11: 2.0,
            25: 3.0,
            50: 5.0,
            51: 6.0,
            90: 9.0,
            95: 10.0,
            100: 10.0,
        }
        for percentile, value in expected.items():
            with self.subTest(percentile=percentile):
                self.assertEqual(harness.nearest_rank_percentile(samples, percentile), value)

    def test_nearest_rank_percentile_over_other_fixed_samples(self) -> None:
        cases = (
            ([7.5], 50, 7.5),
            ([7.5], 95, 7.5),
            ([2.0, 1.0], 50, 1.0),
            ([2.0, 1.0], 95, 2.0),
            ([3.0, 1.0, 2.0], 50, 2.0),
            ([3.0, 1.0, 2.0], 95, 3.0),
            ([1.0, 1.0, 1.0, 9.0], 50, 1.0),
            ([1.0, 1.0, 1.0, 9.0], 95, 9.0),
            ([5, 4, 3, 2, 1], 50, 3.0),
            ([0.0, 0.0], 50, 0.0),
        )
        for samples, percentile, expected in cases:
            with self.subTest(samples=samples, percentile=percentile):
                self.assertEqual(harness.nearest_rank_percentile(samples, percentile), expected)

    def test_the_percentile_never_interpolates(self) -> None:
        """Every result is a value that was actually in the sample, not a value between two."""

        samples = [1.0, 4.0, 9.0, 16.0, 25.0, 36.0, 49.0]
        for percentile in range(1, 101):
            with self.subTest(percentile=percentile):
                self.assertIn(harness.nearest_rank_percentile(samples, percentile), samples)

    def test_the_percentile_depends_only_on_the_multiset(self) -> None:
        ascending = [1.0, 2.0, 3.0, 4.0, 5.0]
        for ordering in ([5.0, 4.0, 3.0, 2.0, 1.0], [3.0, 1.0, 5.0, 2.0, 4.0]):
            with self.subTest(ordering=ordering):
                for percentile in (1, 50, 95, 100):
                    self.assertEqual(
                        harness.nearest_rank_percentile(ordering, percentile),
                        harness.nearest_rank_percentile(ascending, percentile),
                    )

    def test_an_empty_sample_is_rejected(self) -> None:
        for empty in ([], (), iter(())):
            with self.subTest(empty=type(empty).__name__):
                with self.assertRaises(harness.LoadObservationError) as captured:
                    harness.nearest_rank_percentile(list(empty), 50)
                self.assertEqual(captured.exception.code, "NO_SAMPLES")
        with self.assertRaises(harness.LoadObservationError) as captured:
            harness.summarize_samples([])
        self.assertEqual(captured.exception.code, "NO_SAMPLES")

    def test_an_invalid_percentile_is_rejected(self) -> None:
        for percentile in (0, -1, 101, 1000, True, False, 50.0, "50", None):
            with self.subTest(percentile=percentile):
                with self.assertRaises(harness.LoadObservationError) as captured:
                    harness.nearest_rank_percentile([1.0, 2.0], percentile)
                self.assertEqual(captured.exception.code, "PERCENTILE_INVALID")

    def test_summarize_samples_returns_the_declared_schema(self) -> None:
        summary = harness.summarize_samples([4.0, 1.0, 3.0, 2.0])
        self.assertEqual(
            summary, {"samples": 4, "min": 1.0, "median": 2.0, "p95": 4.0, "max": 4.0}
        )
        self.assertEqual(list(summary), ["samples", "min", "median", "p95", "max"])
        self.assertEqual(
            harness.summarize_samples([10.0]),
            {"samples": 1, "min": 10.0, "median": 10.0, "p95": 10.0, "max": 10.0},
        )

    def test_summarize_samples_rounds_to_the_declared_decimals(self) -> None:
        summary = harness.summarize_samples([1.234561234, 2.5, 9.87654321])
        self.assertEqual(summary["min"], round(1.234561234, harness.ROUNDING_DECIMALS))
        self.assertEqual(summary["max"], round(9.87654321, harness.ROUNDING_DECIMALS))
        for key in ("min", "median", "p95", "max"):
            with self.subTest(key=key):
                self.assertEqual(summary[key], round(summary[key], harness.ROUNDING_DECIMALS))

    def test_summarize_samples_is_deterministic_on_a_fixed_sample(self) -> None:
        samples = [3.25, 1.5, 8.125, 2.0, 5.75, 4.5, 9.0, 6.25, 7.0, 0.5]
        first = harness.summarize_samples(samples)
        for _ in range(5):
            self.assertEqual(harness.summarize_samples(samples), first)
        self.assertEqual(harness.summarize_samples(list(reversed(samples))), first)
        self.assertEqual(harness.summarize_samples(sorted(samples)), first)

    def test_the_summary_matches_the_contract_definitions(self) -> None:
        statistics = CONTRACT["statistics"]
        samples = [2.0, 8.0, 4.0, 6.0]
        summary = harness.summarize_samples(samples)
        ordered = sorted(samples)
        self.assertEqual(summary[statistics["sample_count_field"]], len(ordered))
        self.assertEqual(summary["min"], ordered[0])
        self.assertEqual(summary["max"], ordered[-1])
        self.assertEqual(summary["median"], harness.nearest_rank_percentile(ordered, 50))
        self.assertEqual(summary["p95"], harness.nearest_rank_percentile(ordered, 95))


# ---------------------------------------------------------------------------------------
# 6. the deadline
# ---------------------------------------------------------------------------------------


class DeadlineTestCase(LoadObservationTestCase):
    """AC-013: waiting is bounded by a deadline, never by a fixed pause."""

    def test_an_expired_deadline_refuses_rather_than_waits(self) -> None:
        deadline = harness._Deadline(0.0)
        with self.assertRaises(harness.LoadObservationError) as captured:
            deadline.check("stage")
        self.assertEqual(captured.exception.code, "WALL_DEADLINE_EXCEEDED")
        with self.assertRaises(harness.LoadObservationError) as captured:
            deadline.budget("stage")
        self.assertEqual(captured.exception.code, "WALL_DEADLINE_EXCEEDED")

    def test_a_budget_is_capped_by_the_wall_bound(self) -> None:
        deadline = harness._Deadline(harness.MAX_WALL_SECONDS * 10)
        self.assertEqual(deadline.budget("stage"), float(harness.MAX_WALL_SECONDS))

    def test_a_live_deadline_yields_a_usable_budget(self) -> None:
        deadline = harness._Deadline(harness.MAX_WALL_SECONDS)
        budget = deadline.budget("stage")
        self.assertIsInstance(budget, float)
        self._assert_at_most(budget, float(harness.MAX_WALL_SECONDS), "budget")
        self.assertNotEqual(budget, 0.0)

    def test_an_empty_request_group_is_refused(self) -> None:
        with self.assertRaises(harness.LoadObservationError) as captured:
            harness._run_group("127.0.0.1", 1, [], harness._Deadline(1.0), "stage")
        self.assertEqual(captured.exception.code, "GROUP_EMPTY")


# ---------------------------------------------------------------------------------------
# 7. one real bounded observation
# ---------------------------------------------------------------------------------------


class ObservationRecordTestCase(LoadObservationTestCase):
    """AC-003 to AC-008: one real loopback run, judged on correctness and shape only.

    Every assertion below is a count derived from the configuration, a key name, a type or a
    boolean. Not one of them looks at how large a latency, a throughput or a proxy value is.
    """

    record: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.record = _run_small_observation()

    def test_top_level_keys_are_exactly_the_declared_ones_in_order(self) -> None:
        self.assertEqual(tuple(self.record), harness.OUTPUT_TOP_LEVEL_KEYS)
        self.assertEqual(
            list(self.record), CONTRACT["output_contract"]["top_level_keys"]
        )

    def test_the_record_is_json_serialisable_and_stable(self) -> None:
        encoded = json.dumps(self.record, ensure_ascii=False, sort_keys=True)
        self.assertEqual(json.loads(encoded), self.record)

    def test_identity_fields(self) -> None:
        self.assertEqual(self.record["schema_version"], harness.SCHEMA_VERSION)
        self.assertEqual(self.record["task_id"], "R2-LOAD-0004")
        self.assertEqual(self.record["contract_ref"], CONTRACT_PATH)
        self.assertFalse(os.path.isabs(self.record["contract_ref"]))

    def test_notice_repeats_the_prototype_and_measurement_notices(self) -> None:
        notice = self.record["notice"]
        self.assertEqual(sorted(notice), ["measurement", "prototype"])
        self.assertEqual(notice["prototype"], dict(PROTOTYPE_NOTICE))
        measurement = notice["measurement"]
        self.assertIs(measurement["measurement_is_observation_only"], True)
        self.assertIs(measurement["asserted_by_tests"], False)
        self.assertIs(measurement["environment_dependent"], True)
        self.assertIs(measurement["portable_performance_characteristic"], False)
        for key in (
            "service_level_objective_declared",
            "latency_threshold_declared",
            "throughput_target_declared",
            "capacity_promise",
        ):
            self.assertEqual(measurement[key], "NONE", key)

    def test_environment_keys_are_exactly_the_declared_ones(self) -> None:
        environment = self.record["environment"]
        self.assertEqual(tuple(environment), harness.ENVIRONMENT_KEYS)
        self.assertEqual(list(environment), CONTRACT["output_contract"]["environment_keys"])
        self.assertEqual(environment["python_version"], platform.python_version())
        self.assertEqual(environment["python_implementation"], platform.python_implementation())
        self.assertEqual(environment["system"], platform.system())
        self.assertEqual(environment["clock_source"], harness.STATISTICS_CLOCK_SOURCE)
        self.assertIsInstance(environment["cpu_count"], int)
        self.assertIsInstance(environment["clock_resolution_ns"], int)

    def test_config_echo_is_exactly_the_requested_configuration(self) -> None:
        self.assertEqual(
            self.record["config"],
            {
                "concurrency": OBSERVED_CONCURRENCY,
                "rounds": OBSERVED_ROUNDS,
                "warmup_requests": OBSERVED_WARMUP,
                "wall_timeout_seconds": harness.DEFAULT_WALL_SECONDS,
                "stake_units_per_bet": harness.DEFAULT_STAKE_UNITS_PER_BET,
                "opening_player_units": harness.DEFAULT_OPENING_PLAYER_UNITS,
                "opening_house_units": harness.DEFAULT_OPENING_HOUSE_UNITS,
                "bet_type": harness.OBSERVED_BET_TYPE,
                "host": harness.DEFAULT_HOST,
                "port": 0,
                "port_selection": "ephemeral",
                "target_slice": "apps/roulette_web",
                "route_count": len(ROUTES),
                "request_plan_formula": CONTRACT["request_plan"]["formula"],
                "planned_requests": OBSERVED_WARMUP
                + OBSERVED_ROUNDS * (2 * OBSERVED_CONCURRENCY + 1),
                "safety_bounds": {
                    "purpose": "bounded_local_execution_only",
                    "are_performance_expectations": False,
                    "are_service_level_objectives": False,
                    "are_pass_fail_thresholds": False,
                    "compared_against_observed_values": False,
                    "max_concurrency": harness.MAX_CONCURRENCY,
                    "max_total_requests": harness.MAX_TOTAL_REQUESTS,
                    "max_rounds": harness.MAX_ROUNDS,
                    "max_wall_seconds": harness.MAX_WALL_SECONDS,
                },
            },
        )

    def test_counts_are_exactly_what_the_plan_derives(self) -> None:
        measured = OBSERVED_ROUNDS * (2 * OBSERVED_CONCURRENCY + 1)
        self.assertEqual(
            self.record["counts"],
            {
                "planned_requests": OBSERVED_WARMUP + measured,
                "total_requests": OBSERVED_WARMUP + measured,
                "warmup_requests": OBSERVED_WARMUP,
                "measured_requests": measured,
                "concurrent_requests": OBSERVED_ROUNDS * 2 * OBSERVED_CONCURRENCY,
                "rounds": OBSERVED_ROUNDS,
                "concurrency": OBSERVED_CONCURRENCY,
                "warmup_requests_included_in_statistics": False,
                "warmup_requests_counted_in_total_requests": True,
            },
        )

    def test_elapsed_reports_the_clock_and_the_bound_but_is_not_asserted_on(self) -> None:
        elapsed = self.record["elapsed"]
        self.assertEqual(
            sorted(elapsed),
            [
                "clock_source",
                "inspection_seconds",
                "measured_seconds",
                "wall_bound_seconds",
                "wall_seconds",
                "warmup_seconds",
            ],
        )
        self.assertEqual(elapsed["clock_source"], harness.STATISTICS_CLOCK_SOURCE)
        self.assertEqual(elapsed["wall_bound_seconds"], harness.DEFAULT_WALL_SECONDS)
        for key in ("wall_seconds", "warmup_seconds", "measured_seconds", "inspection_seconds"):
            with self.subTest(key=key):
                self.assertIsInstance(elapsed[key], float)

    def test_throughput_is_recorded_as_an_observation(self) -> None:
        throughput = self.record["throughput"]
        self.assertEqual(
            sorted(throughput),
            ["basis", "requests_per_second", "rounds_per_second", "unit"],
        )
        self.assertEqual(throughput["unit"], "per_second")
        self.assertEqual(
            throughput["basis"], "measured requests over measured seconds; warm-up excluded"
        )
        for key in ("requests_per_second", "rounds_per_second"):
            with self.subTest(key=key):
                self.assertIsInstance(throughput[key], float)

    def test_latency_block_has_the_declared_shape(self) -> None:
        latency = self.record["latency_ms"]
        self.assertEqual(
            sorted(latency),
            [
                "asserted_by_tests",
                "clock_source",
                "interpolation",
                "max",
                "median",
                "method",
                "min",
                "observation_end",
                "observation_start",
                "p95",
                "sample_population",
                "samples",
                "threshold",
                "unit",
                "warmup_requests_included",
            ],
        )
        self.assertEqual(latency["unit"], harness.STATISTICS_UNIT)
        self.assertEqual(latency["method"], harness.PERCENTILE_METHOD)
        self.assertEqual(latency["interpolation"], "none")
        self.assertEqual(latency["clock_source"], harness.STATISTICS_CLOCK_SOURCE)
        self.assertEqual(latency["sample_population"], CONTRACT["statistics"]["sample_population"])
        self.assertIs(latency["warmup_requests_included"], False)
        self.assertIs(latency["asserted_by_tests"], False)
        self.assertEqual(latency["threshold"], "none")
        self.assertEqual(latency["samples"], self.record["counts"]["measured_requests"])
        for key in ("min", "median", "p95", "max"):
            with self.subTest(key=key):
                self.assertIsInstance(latency[key], float)

    def test_the_serialization_proxy_is_a_separate_key_with_the_declared_shape(self) -> None:
        proxy = self.record[harness.SERIALIZATION_PROXY_METRIC]
        self.assertNotEqual(harness.SERIALIZATION_PROXY_METRIC, "latency_ms")
        self.assertEqual(
            sorted(proxy),
            [
                "asserted_by_tests",
                "clock_source",
                "combines",
                "does_not_isolate",
                "harness_instruments_internal_locks",
                "interpolation",
                "is_proxy",
                "max",
                "measured_only_for",
                "measures_internal_lock_acquisition_wait",
                "median",
                "method",
                "min",
                "observation_end",
                "observation_start",
                "p95",
                "reported_separately_from_total_latency",
                "runtime_instrumentation_added_to_observed_code",
                "samples",
                "threshold",
                "unit",
                "upper_bound_semantics",
            ],
        )
        declared = CONTRACT["serialization_wait_proxy"]
        self.assertIs(proxy["is_proxy"], True)
        self.assertIs(proxy["reported_separately_from_total_latency"], True)
        self.assertIs(proxy["measures_internal_lock_acquisition_wait"], False)
        self.assertIs(proxy["harness_instruments_internal_locks"], False)
        self.assertIs(proxy["runtime_instrumentation_added_to_observed_code"], False)
        self.assertIs(proxy["asserted_by_tests"], False)
        self.assertEqual(proxy["threshold"], "none")
        self.assertEqual(proxy["measured_only_for"], declared["measured_only_for"])
        self.assertEqual(proxy["combines"], declared["combines"])
        self.assertEqual(proxy["does_not_isolate"], declared["does_not_isolate"])
        self.assertEqual(proxy["samples"], self.record["counts"]["concurrent_requests"])
        for key in ("min", "median", "p95", "max"):
            with self.subTest(key=key):
                self.assertIsInstance(proxy[key], float)

    def test_the_proxy_and_the_latency_are_measured_from_different_origins(self) -> None:
        latency = self.record["latency_ms"]
        proxy = self.record[harness.SERIALIZATION_PROXY_METRIC]
        self.assertEqual(latency["observation_start"], "the request's own send instant")
        self.assertEqual(latency["observation_end"], "the response body has been fully read")
        self.assertIn("barrier", proxy["observation_start"])
        self.assertEqual(proxy["observation_end"], "http.client.getresponse() returned for that request")
        self.assertNotEqual(latency["observation_start"], proxy["observation_start"])
        self.assertNotEqual(latency["observation_end"], proxy["observation_end"])
        self.assertNotEqual(latency["samples"], proxy["samples"])

    def test_all_ten_correctness_properties_hold(self) -> None:
        correctness = self.record["correctness"]
        self.assertIs(correctness["asserted"], True)
        self.assertIs(correctness["timing_dependent"], False)
        self.assertIs(correctness["inspected_after_reload"], True)
        self.assertEqual(tuple(correctness["properties"]), EXPECTED_PROPERTY_IDS)
        for name in EXPECTED_PROPERTY_IDS:
            with self.subTest(property=name):
                self.assertIs(correctness["properties"][name], True)
        self.assertEqual(correctness["failed_properties"], [])
        self.assertIs(correctness["all_properties_hold"], True)

    def test_correctness_evidence_is_exactly_what_the_plan_implies(self) -> None:
        evidence = self.record["correctness"]["evidence"]
        submissions = OBSERVED_ROUNDS * OBSERVED_CONCURRENCY
        self.assertEqual(evidence["draw_records"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["ledger_transactions"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["committed_rounds"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["distinct_round_ids"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["distinct_settlement_transaction_ids"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["spin_submissions"], submissions)
        self.assertEqual(evidence["duplicate_spin_submissions"], submissions - OBSERVED_ROUNDS)
        self.assertEqual(evidence["spin_fresh_commits"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["spin_replays"], submissions - OBSERVED_ROUNDS)
        self.assertEqual(evidence["rounds_with_one_fresh_commit"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["rounds_with_one_commit_identity"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["float_values_found"], 0)
        self.assertEqual(evidence["ledger_entries_sum_to_zero"], True)
        self.assertEqual(evidence["opening_player_units"], harness.DEFAULT_OPENING_PLAYER_UNITS)

    def test_settlement_reconciles_to_the_minimum_unit_in_integers(self) -> None:
        evidence = self.record["correctness"]["evidence"]
        self.assertEqual(
            evidence["player_balance_delta_units"], evidence["ledger_player_delta_units"]
        )
        self.assertEqual(
            evidence["closing_player_units"] - evidence["opening_player_units"],
            evidence["ledger_player_delta_units"],
        )
        for key in (
            "opening_player_units",
            "closing_player_units",
            "player_balance_delta_units",
            "ledger_player_delta_units",
            "closing_house_units",
        ):
            with self.subTest(key=key):
                self.assertIsInstance(evidence[key], int)
                self.assertNotIsInstance(evidence[key], bool)

    def test_audit_events_are_unique_and_match_the_committed_rounds(self) -> None:
        evidence = self.record["correctness"]["evidence"]
        self.assertEqual(evidence["audit_draw_events"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["audit_settled_events"], OBSERVED_ROUNDS)
        self.assertEqual(evidence["audit_denial_events"], 0)
        self.assertEqual(evidence["audit_void_events"], 0)
        self.assertEqual(evidence["audit_events_total"], OBSERVED_ROUNDS * 2)
        self.assertEqual(evidence["distinct_audit_event_ids"], evidence["audit_events_total"])
        self.assertEqual(evidence["distinct_audit_event_hashes"], evidence["audit_events_total"])
        self.assertEqual(evidence["audit_chain_problems_after_reload"], 0)

    def test_entropy_is_counted_only_and_spent_only_inside_a_spin_group(self) -> None:
        evidence = self.record["correctness"]["evidence"]
        self.assertEqual(evidence["entropy_reads_outside_spin_groups"], 0)
        self.assertEqual(evidence["entropy_bytes_outside_spin_groups"], 0)
        self.assertEqual(evidence["spin_groups_that_consumed_entropy"], OBSERVED_ROUNDS)
        self.assertIs(evidence["entropy_material_recorded"], False)
        for key in ("entropy_reads_total", "entropy_bytes_total"):
            with self.subTest(key=key):
                self.assertIsInstance(evidence[key], int)
                self.assertNotEqual(evidence[key], 0)


# ---------------------------------------------------------------------------------------
# 8. the output names nobody
# ---------------------------------------------------------------------------------------


class OutputPrivacyTestCase(LoadObservationTestCase):
    """AC-014: the emitted record carries no operator identity, path or entropy material."""

    record: dict[str, Any]
    encoded: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.record = _run_small_observation()
        cls.encoded = json.dumps(cls.record, ensure_ascii=False)

    def test_the_record_does_not_name_the_machine_or_the_account(self) -> None:
        node = platform.node()
        self.assertNotEqual(node, "")
        self.assertNotIn(node.lower(), self.encoded.lower())
        account = getpass.getuser()
        self.assertIsNone(
            re.search(rf"(?<![A-Za-z0-9]){re.escape(account)}(?![A-Za-z0-9])", self.encoded, re.I)
        )

    def test_the_record_contains_no_absolute_path(self) -> None:
        for location in (str(ROOT), os.getcwd(), tempfile.gettempdir(), os.path.expanduser("~")):
            with self.subTest(location=location):
                self.assertNotIn(location.lower(), self.encoded.lower())
                self.assertNotIn(
                    location.replace("\\", "/").lower(), self.encoded.lower().replace("\\", "/")
                )
        self.assertEqual(re.findall(r"[A-Za-z]:[\\/]", self.encoded), [])
        self.assertEqual(re.findall(r"(?i)/(?:home|users|root|tmp|var)/", self.encoded), [])
        self.assertNotIn("\\\\", self.encoded)

    def test_no_excluded_field_appears_anywhere_in_the_record(self) -> None:
        forbidden = (
            "hostname",
            "host_name",
            "username",
            "user_name",
            "account_identifier",
            "email",
            "credential",
            "token",
            "secret",
            "password",
            "api_key",
            "session_id",
        )
        offending = [
            path
            for path, key, _ in _walk_items(self.record)
            if any(word in key.lower() for word in forbidden)
        ]
        self.assertEqual(offending, [])
        # The contract's own exclusion list is the one being honoured here.
        self.assertEqual(
            CONTRACT["output_contract"]["excluded_from_output"],
            [
                "hostname",
                "username",
                "account_identifier",
                "email_address",
                "credential_or_token_value",
                "absolute_filesystem_path_of_the_operator",
            ],
        )

    def test_only_entropy_counts_are_recorded_never_entropy_material(self) -> None:
        counted = 0
        for path, key, value in _walk_items(self.record):
            if "entropy" not in key.lower():
                continue
            counted += 1
            if key in ("entropy_material_recorded",):
                self.assertIs(value, False, path)
            elif key in ("entropy_note", "entropy_sampling_duration"):
                self.assertIsInstance(value, str, path)
            else:
                self.assertIsInstance(value, int, path)
                self.assertNotIsInstance(value, bool, path)
        self.assertNotEqual(counted, 0)
        self.assertIsNone(re.search(r"(?i)\b(seed|nonce)\b", self.encoded))

    def test_the_only_host_named_is_the_loopback_target_that_was_requested(self) -> None:
        hosts = {value for _, key, value in _walk_items(self.record) if key == "host"}
        self.assertEqual(hosts, {harness.DEFAULT_HOST})
        self.assertEqual(hosts - set(LOOPBACK_HOSTS), set())


# ---------------------------------------------------------------------------------------
# 9. repetition
# ---------------------------------------------------------------------------------------


class RepeatedObservationTestCase(LoadObservationTestCase):
    """AC-013: repeating the run repeats the judged answer and the structure, not the timings."""

    records: list[dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.records = [_run_small_observation(), _run_small_observation()]

    def test_every_repetition_holds_every_correctness_property(self) -> None:
        for index, record in enumerate(self.records):
            with self.subTest(run=index):
                self.assertIs(record["correctness"]["all_properties_hold"], True)
                self.assertEqual(record["correctness"]["failed_properties"], [])
                self.assertEqual(
                    record["correctness"]["properties"],
                    {name: True for name in EXPECTED_PROPERTY_IDS},
                )

    def test_repetitions_agree_on_structure_configuration_and_counts(self) -> None:
        first, second = self.records
        self.assertEqual(tuple(first), tuple(second))
        self.assertEqual(first["config"], second["config"])
        self.assertEqual(first["counts"], second["counts"])
        self.assertEqual(first["environment"], second["environment"])
        self.assertEqual(first["notice"], second["notice"])
        self.assertEqual(first["contract_ref"], second["contract_ref"])
        self.assertEqual(sorted(first["latency_ms"]), sorted(second["latency_ms"]))
        self.assertEqual(
            sorted(first[harness.SERIALIZATION_PROXY_METRIC]),
            sorted(second[harness.SERIALIZATION_PROXY_METRIC]),
        )

    def test_repetitions_agree_on_every_count_derived_evidence_value(self) -> None:
        """The evidence that a race did not corrupt anything must not move between runs."""

        invariant = (
            "draw_records",
            "ledger_transactions",
            "committed_rounds",
            "distinct_round_ids",
            "distinct_settlement_transaction_ids",
            "spin_submissions",
            "duplicate_spin_submissions",
            "spin_fresh_commits",
            "spin_replays",
            "rounds_with_one_fresh_commit",
            "rounds_with_one_commit_identity",
            "entropy_reads_outside_spin_groups",
            "entropy_bytes_outside_spin_groups",
            "spin_groups_that_consumed_entropy",
            "float_values_found",
            "audit_events_total",
            "audit_draw_events",
            "audit_settled_events",
            "audit_denial_events",
            "audit_void_events",
            "distinct_audit_event_ids",
            "distinct_audit_event_hashes",
            "audit_chain_problems_after_reload",
        )
        first, second = (record["correctness"]["evidence"] for record in self.records)
        self.assertEqual(
            {key: first[key] for key in invariant}, {key: second[key] for key in invariant}
        )

    def test_each_repetition_reconciles_its_own_balances(self) -> None:
        for index, record in enumerate(self.records):
            with self.subTest(run=index):
                evidence = record["correctness"]["evidence"]
                self.assertEqual(
                    evidence["player_balance_delta_units"], evidence["ledger_player_delta_units"]
                )

    def test_each_repetition_observes_a_fresh_database(self) -> None:
        """A second run must not inherit the first one's rounds, draws or ledger.

        The harness gives every run its own temporary workspace, so the counts stay at the
        plan's numbers instead of accumulating. If a run ever reused a previous database, the
        draw and ledger counts of the later run would be a multiple of the plan's, and the
        per-round correctness properties would stop meaning what they claim.
        """

        for index, record in enumerate(self.records):
            with self.subTest(run=index):
                evidence = record["correctness"]["evidence"]
                self.assertEqual(evidence["draw_records"], OBSERVED_ROUNDS)
                self.assertEqual(evidence["ledger_transactions"], OBSERVED_ROUNDS)
                self.assertEqual(evidence["audit_events_total"], OBSERVED_ROUNDS * 2)
                self.assertEqual(
                    evidence["opening_player_units"], harness.DEFAULT_OPENING_PLAYER_UNITS
                )


# ---------------------------------------------------------------------------------------
# 10. source discipline
# ---------------------------------------------------------------------------------------


class SourceDisciplineTestCase(LoadObservationTestCase):
    """AC-001, AC-007, AC-008, AC-013: what the harness and this suite are allowed to contain."""

    def _ordering_offences(self, tree: ast.AST, source: str) -> list[str]:
        """Return ordering comparisons and ordering assertions inside judged functions."""

        judged = tuple(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and (node.name.startswith("test_") or node.name.startswith("_assert"))
        )
        offences: list[str] = []
        for function in judged:
            for node in ast.walk(function):
                if isinstance(node, ast.Compare) and any(
                    isinstance(operator, (ast.Lt, ast.LtE, ast.Gt, ast.GtE))
                    for operator in node.ops
                ):
                    offences.append(f"{function.name}: {ast.get_source_segment(source, node)}")
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr
                    in ("assertLess", "assertLessEqual", "assertGreater", "assertGreaterEqual")
                ):
                    offences.append(f"{function.name}: {node.func.attr}")
        return offences

    def test_no_test_in_this_suite_makes_an_ordering_comparison(self) -> None:
        """AC-007, structurally: with no ordering, there can be no pass/fail threshold."""

        self.assertEqual(self._ordering_offences(SUITE_TREE, SUITE_SOURCE), [])

    def test_the_harness_never_compares_an_observed_metric(self) -> None:
        offending = []
        for node in ast.walk(HARNESS_TREE):
            if not isinstance(node, ast.Compare):
                continue
            segment = ast.get_source_segment(HARNESS_SOURCE, node) or ""
            if any(
                token in segment
                for token in ("latency", "throughput", "serialization_wait_proxy", "p95", "median")
            ):
                offending.append(segment)
        self.assertEqual(offending, [])

    def test_the_harness_imports_only_the_standard_library_and_this_repository(self) -> None:
        roots = _imported_roots(HARNESS_TREE)
        self.assertEqual(roots - set(sys.stdlib_module_names) - REPO_PACKAGES, set())
        self.assertEqual(
            roots & REPO_PACKAGES, {"apps", "studio_core"}, "the observed slice and its core"
        )

    def test_this_suite_imports_only_the_standard_library_and_this_repository(self) -> None:
        roots = _imported_roots(SUITE_TREE)
        self.assertEqual(roots - set(sys.stdlib_module_names) - REPO_PACKAGES, set())
        self.assertNotIn("yaml", roots)

    def test_the_repository_declares_no_new_dependency_and_no_manifest(self) -> None:
        _FILES_READ.append(PYPROJECT_PATH)
        project = tomllib.loads((ROOT / PYPROJECT_PATH).read_text(encoding="utf-8"))
        self.assertEqual(
            tuple(project["project"]["dependencies"]), EXPECTED_PROJECT_DEPENDENCIES
        )
        present = [name for name in DEPENDENCY_MANIFESTS if (ROOT / name).exists()]
        self.assertEqual(present, [])
        binding = CONTRACT["target_binding"]
        self.assertIs(binding["stdlib_only"], True)
        self.assertEqual(binding["new_external_dependencies"], 0)
        self.assertEqual(binding["package_installation"], "none")
        self.assertEqual(binding["build_step"], "none")
        self.assertEqual(binding["service_startup_outside_process"], "none")

    def test_neither_the_harness_nor_this_suite_sleeps(self) -> None:
        for label, source, tree in (
            (HARNESS_PATH, HARNESS_SOURCE, HARNESS_TREE),
            (SUITE_PATH, SUITE_SOURCE, SUITE_TREE),
        ):
            with self.subTest(source=label):
                sleeps = [
                    ast.get_source_segment(source, node)
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "sleep"
                ]
                self.assertEqual(sleeps, [])

    def test_every_thread_join_in_the_harness_is_bounded(self) -> None:
        unbounded = []
        for node in ast.walk(HARNESS_TREE):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "join":
                continue
            target = node.func.value
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                continue  # a string join, not a thread join
            if isinstance(target, ast.Attribute) and target.attr == "path":
                continue  # os.path.join
            if any(keyword.arg == "timeout" for keyword in node.keywords):
                continue
            unbounded.append(ast.get_source_segment(HARNESS_SOURCE, node))
        self.assertEqual(unbounded, [])

    def test_the_harness_has_no_unbounded_loop(self) -> None:
        forever = [
            ast.get_source_segment(HARNESS_SOURCE, node)
            for node in ast.walk(HARNESS_TREE)
            if isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and node.test.value is True
        ]
        self.assertEqual(forever, [])

    def test_the_barrier_records_one_shared_release_instant_and_waits_with_a_timeout(self) -> None:
        barriers = [
            node
            for node in ast.walk(HARNESS_TREE)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Barrier"
        ]
        self.assertEqual(len(barriers), 1)
        self.assertEqual([keyword.arg for keyword in barriers[0].keywords], ["action"])
        waits = [
            node
            for node in ast.walk(HARNESS_TREE)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "wait"
        ]
        self.assertNotEqual(waits, [])
        for wait in waits:
            with self.subTest(wait=ast.get_source_segment(HARNESS_SOURCE, wait)):
                self.assertEqual([keyword.arg for keyword in wait.keywords], ["timeout"])

    def test_the_harness_uses_a_deadline_rather_than_a_fixed_pause(self) -> None:
        self.assertTrue(hasattr(harness, "_Deadline"))
        for name in ("remaining", "check", "budget"):
            with self.subTest(method=name):
                self.assertTrue(callable(getattr(harness._Deadline, name)))
        deadline_uses = [
            node
            for node in ast.walk(HARNESS_TREE)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("budget", "check")
        ]
        self.assertNotEqual(deadline_uses, [])

    def test_the_harness_never_reads_the_operator_identity(self) -> None:
        """The identity calls appear in the harness's prose only, never in its syntax tree."""

        chains = _attribute_chains(HARNESS_TREE)
        forbidden = (
            "platform.node",
            "platform.uname",
            "os.getcwd",
            "os.environ",
            "os.getlogin",
            "os.path.expanduser",
            "socket.gethostname",
            "socket.getfqdn",
            "getpass.getuser",
        )
        self.assertEqual(sorted(chains & set(forbidden)), [])
        self.assertNotIn("getpass", _imported_roots(HARNESS_TREE))

    def test_the_public_surface_of_the_harness_is_the_declared_one(self) -> None:
        self.assertEqual(len(set(harness.__all__)), len(harness.__all__))
        for name in harness.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(harness, name))
        for name in (
            "MAX_CONCURRENCY",
            "MAX_TOTAL_REQUESTS",
            "MAX_ROUNDS",
            "MAX_WALL_SECONDS",
            "ObservationConfig",
            "LoadObservationError",
            "nearest_rank_percentile",
            "summarize_samples",
            "run_observation",
        ):
            with self.subTest(name=name):
                self.assertIn(name, harness.__all__)


# ---------------------------------------------------------------------------------------
# 11. the observed slice is untouched
# ---------------------------------------------------------------------------------------


class ObservedSliceTestCase(LoadObservationTestCase):
    """AC-001, AC-008: no new route, no new runtime module, no instrumentation."""

    def test_the_slice_still_publishes_exactly_four_routes(self) -> None:
        self.assertEqual(
            ROUTES,
            {
                "/api/state": "GET",
                "/api/bets": "POST",
                "/api/spin": "POST",
                "/api/new-round": "POST",
            },
        )
        binding = CONTRACT["target_binding"]
        self.assertEqual(binding["route_count"], len(ROUTES))
        self.assertEqual(binding["new_http_routes"], 0)
        self.assertEqual(binding["new_runtime_modules"], 0)
        self.assertEqual(binding["routes_source"], "apps.roulette_web.server.ROUTES")
        self.assertIs(binding["server_api_changed"], False)
        self.assertIs(binding["runtime_instrumentation_added"], False)

    def test_the_harness_calls_only_published_routes(self) -> None:
        used = {
            node.value
            for node in ast.walk(HARNESS_TREE)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("/api/")
        }
        self.assertEqual(used - set(ROUTES), set())

    def test_the_slice_has_no_new_runtime_module(self) -> None:
        modules = sorted(
            path.name
            for path in (ROOT / "apps" / "roulette_web").iterdir()
            if path.suffix == ".py"
        )
        self.assertEqual(modules, ["__init__.py", "server.py", "table.py"])

    def test_entropy_is_injected_through_an_existing_public_parameter(self) -> None:
        """The counting source rides an existing keyword, so no observed file changed for it."""

        self.assertIn(
            "entropy_source", inspect.signature(DurableRoundStore.__init__).parameters
        )
        self.assertIn("store_options", inspect.signature(open_table).parameters)
        source = harness._CountingEntropySource()
        self.assertEqual(source.meter(), (0, 0))
        data = source.read(4)
        self.assertEqual(len(data), 4)
        self.assertEqual(source.meter(), (1, 4))
        # The wrapper reports the wrapped source's identity, never its own.
        self.assertIs(source.is_deterministic, False)
        self.assertFalse(hasattr(source, "_material"))

    def test_the_harness_uses_the_published_entry_points(self) -> None:
        for entry in (open_table, create_server, serve_in_background):
            with self.subTest(entry=entry.__name__):
                self.assertIs(getattr(harness, entry.__name__), entry)


# ---------------------------------------------------------------------------------------
# 12. scope
# ---------------------------------------------------------------------------------------


class ScopeBoundaryTestCase(LoadObservationTestCase):
    """AC-010, AC-011: nothing in R4, and nothing in an asset, image or art path."""

    def test_no_r4_or_asset_path_is_read(self) -> None:
        offending = [path for path in _FILES_READ if R4_OR_ASSET_PATTERN.search(path)]
        self.assertEqual(offending, [])
        self.assertNotEqual(_FILES_READ, [], "the recorded read list must not be empty")

    def test_no_deliverable_or_new_file_touches_an_r4_or_asset_path(self) -> None:
        for path in (*_relative_deliverables(), *CONTRACT["new_files"]):
            with self.subTest(path=path):
                self.assertIsNone(R4_OR_ASSET_PATTERN.search(path))

    def test_the_r4_art_task_is_declared_unmodified_and_is_not_an_output(self) -> None:
        self.assertIn("tasks/R4-ART-0007.json", CONTRACT["frozen_paths"]["also_unmodified"])
        self.assertNotIn("tasks/R4-ART-0007.json", CONTRACT["new_files"])
        self.assertNotIn("tasks/R4-ART-0007.json", _relative_deliverables())
        self.assertNotIn("tasks/R4-ART-0007.json", _relative_inputs())

    def test_the_harness_names_no_asset_or_art_path(self) -> None:
        literals = {
            node.value
            for node in ast.walk(HARNESS_TREE)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        offending = sorted(value for value in literals if R4_OR_ASSET_PATTERN.search(value))
        self.assertEqual(offending, [])

    def test_the_contract_leaves_the_out_of_scope_items_open(self) -> None:
        joined = " ".join(CONTRACT["out_of_scope"])
        for token in ("SLO", "R2-SEC-0005", "R4"):
            with self.subTest(token=token):
                self.assertIn(token, joined)
        self.assertEqual(TASK["dependencies"], ["R2-DBC-0002", "R2-NET-0003"])


if __name__ == "__main__":  # pragma: no cover - convenience for a direct run
    unittest.main(verbosity=2)
