"""R2-SEC-0005: the contract, the verifier, and one real bounded loopback verification.

What these tests are trying to break
------------------------------------
``games/roulette/security-verification-contract.yaml`` is a promise written in prose and
numbers and ``scripts/verify_r2_security.py`` is the code that is supposed to keep it.
Nothing forces the two to agree, and a security harness that has quietly stopped agreeing
with its own contract is worse than no harness at all, because it still prints a passing
record. The interesting failures are therefore these:

* **A declared bound the code does not enforce.** Every ceiling, default, plan count,
  dimension identifier, snapshot field, output key and constant name in the contract is read
  back out of the YAML and compared against the harness constant the contract names for it.
* **A ceiling enforced too late.** "Refused before anything exists" is a testable claim, not
  a comment. :class:`PreflightRefusalTestCase` replaces ``tempfile``, ``threading``, ``os``,
  ``shutil``, ``sqlite3``, ``http``, ``hash_file``, ``open_table``, ``create_server`` and
  ``serve_in_background`` on the harness module with tripwires that raise on any use, then
  feeds the harness a configuration above a bound. A refusal that had already created a
  directory, a database, a socket, a thread or a copy trips a wire.
* **A scope boundary that is only asserted in prose.** Off-loopback literals, every name
  string, and a fixed port are refused -- and refused *with the resolver broken*, which is
  the only way to show the decision was made without looking anything up.
* **A check that cannot fail.** A verifier whose detectors never fire is a rubber stamp, so
  :class:`DetectorTestCase` plants material each detector is supposed to catch and asserts it
  is caught, and plants clean input and asserts it is not.
* **A case set that drifted.** Every declared client-authority field must have a forged
  value, the malformed table must stay a fixed constant, and the executed case and request
  counts must equal the plan exactly.
* **The output naming the operator.** The emitted record is searched for the host name, the
  account name, the working directory, the temporary directory, the repository root and
  anything shaped like an absolute path.
* **A frozen path that moved.** All thirty-one paths the Task Contract pins are re-hashed.

On the standard library
-----------------------
AC-001 requires the harness *and its tests* to use the standard library only, so this file
does not import PyYAML -- even though the repository already depends on it -- and reads the
contract with :func:`_parse_contract_yaml`, a small reader for the block mappings, block
sequences, flow mappings and folded scalars this one contract file uses. It raises
:class:`ContractFormatError` on anything outside that subset rather than guessing.

On determinism
--------------
Nothing here sleeps and nothing here asserts on elapsed time. One real verification is
executed in :meth:`setUpClass` and shared, and :class:`RepeatedVerificationTestCase` runs a
second one and asserts the case identifiers, the expectations and every held flag are
identical. The harness's own waiting is bounded by a deadline rather than a fixed pause.

Out of scope, and deliberately untouched: R4 deliverables, assets, images and art. No test
here reads such a path, and :meth:`ScopeBoundaryTestCase.test_no_r4_or_asset_path_is_read`
asserts that over the actual list of files this suite opened.
"""

from __future__ import annotations

import ast
import getpass
import json
import os
import pathlib
import platform
import re
import socket
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import LOOPBACK_HOSTS, MAX_BODY_BYTES, ROUTES  # noqa: E402
from apps.roulette_web.table import BETS_ACCEPTED_IN, CLIENT_AUTHORITY_FIELDS  # noqa: E402
from scripts import verify_r2_security as harness  # noqa: E402
from studio_core.integrity import hash_file  # noqa: E402
from studio_core.rng import (  # noqa: E402
    PROHIBITED_RECORD_FIELDS,
    compute_event_hash,
    verify_audit_chain,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]

TASK_PATH = "tasks/R2-SEC-0005.json"
ARTIFACT_PATH = "artifacts/R2-SEC-0005-artifact.json"
HANDOFF_PATH = "handoffs/R2-SEC-0005-handoff.json"
CONTRACT_PATH = "games/roulette/security-verification-contract.yaml"
HARNESS_PATH = "scripts/verify_r2_security.py"
SUITE_PATH = "tests/test_security_verification.py"
DESIGN_PATH = "docs/games/R2-security-verification.md"
REPORT_PATH = "docs/approvals/R2-SEC-0005-validation-report.md"
EVENTS_PATH = "audit/events/R2-SEC-0005-events.json"
SLICE_CONTRACT_PATH = "games/roulette/playable-slice-contract.yaml"
ROUND_STATE_PATH = "games/roulette/round-state.yaml"

#: The exact set of files this unit adds. Nothing else may appear, and every one of these
#: must exist by the time this suite runs.
DECLARED_NEW_FILES = (
    TASK_PATH,
    ARTIFACT_PATH,
    HANDOFF_PATH,
    CONTRACT_PATH,
    HARNESS_PATH,
    SUITE_PATH,
    DESIGN_PATH,
    REPORT_PATH,
    EVENTS_PATH,
)

#: The five judged dimensions of section 4 of the contract, in contract order.
EXPECTED_DIMENSION_IDS = (
    "client_authority_forgery_denial",
    "betting_phase_lock_bypass_denial",
    "idempotency_and_settlement_replay_safety",
    "audit_event_tamper_and_delete_detection_on_copy",
    "seed_reference_confidentiality",
)

#: Top-level packages that are part of this repository rather than an external dependency.
REPO_PACKAGES = frozenset({"apps", "scripts", "studio_core", "tests"})

#: Files a dependency would be declared in. AC-001 asks for their absence to be confirmed.
DEPENDENCY_MANIFESTS = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
    "Pipfile",
    "poetry.lock",
    "setup.py",
    "setup.cfg",
)

#: Call surfaces that would take this unit outside its declared boundary.
PROHIBITED_CALL_CHAINS = frozenset(
    {
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.getaddrinfo",
        "socket.getfqdn",
        "socket.gethostname",
        "socket.create_connection",
        "platform.node",
        "getpass.getuser",
        "os.system",
        "os.getlogin",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "urllib.request.urlopen",
        "time.sleep",
        "random.random",
        "random.randint",
        "random.choice",
        "shutil.rmtree",
    }
)

#: Modules that must never be imported by the harness or this suite.
PROHIBITED_IMPORTS = frozenset({"subprocess", "urllib", "ftplib", "smtplib", "telnetlib", "pip"})

#: Path fragments that would mean this unit read an R4, asset, image or art path. Matched
#: against the *paths* this suite opened, never against file contents: a contract that names
#: ``tasks/R4-ART-0007.json`` in order to declare it unmodified is doing the right thing, and
#: a content search cannot tell that declaration apart from a modification.
R4_AND_ASSET_PATH_FRAGMENTS = ("R4-ART-0007", "assets/", "/images/", "art/")

#: An extension no file of this unit may reference, because referencing one would mean an
#: asset, image or art path had entered the unit's surface.
ASSET_EXTENSION = re.compile(r"\.(?:png|jpe?g|webp|gif|bmp|svg|psd|fbx|glb|mp3|wav)\b")


# ---------------------------------------------------------------------------------------
# a very small YAML reader -- standard library only, by AC-001
# ---------------------------------------------------------------------------------------


class ContractFormatError(ValueError):
    """The contract uses YAML this reader does not support, so it refuses to guess."""


_BLOCK_SCALAR_HEADERS = frozenset({">", ">-", ">+", "|", "|-", "|+"})
_MAPPING_ENTRY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*:(\s|$)")
_INTEGER = re.compile(r"^-?\d+$")


def _significant_lines(text: str) -> list[tuple[int, str]]:
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
    while index < len(lines) and lines[index][0] == indent and not lines[index][1].startswith("- "):
        key, separator, rest = lines[index][1].partition(":")
        if not separator:
            raise ContractFormatError(f"unsupported line: {lines[index][1]!r}")
        key = key.strip()
        rest = rest.strip()
        index += 1
        if rest in _BLOCK_SCALAR_HEADERS:
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

#: Recorded so ``ScopeBoundaryTestCase`` can assert over what was actually read rather than
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
    """Return every dotted attribute access in ``tree``, such as ``socket.getaddrinfo``.

    Read from the syntax tree rather than from the text, because both files' docstrings name
    the calls they deliberately do *not* make, and a substring search cannot tell that
    explanation apart from the thing it explains.
    """

    chains: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        parts = [node.attr]
        current: ast.AST = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            chains.add(".".join(reversed(parts)))
    return chains


def _imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


class _Tripwire:
    """Any use at all raises. Installed where a resource would otherwise be created."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attribute: str) -> Any:
        raise AssertionError(f"{self._name}.{attribute} was reached before the bound was enforced")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"{self._name} was called before the bound was enforced")


def _tripwired() -> Any:
    """Return a context manager replacing every resource surface of the harness."""

    patches = [
        mock.patch.object(harness, name, _Tripwire(f"harness.{name}"))
        for name in (
            "tempfile",
            "threading",
            "os",
            "shutil",
            "sqlite3",
            "http",
            "hash_file",
            "open_table",
            "create_server",
            "serve_in_background",
        )
    ]

    class _Combined:
        def __enter__(self) -> None:
            for patch in patches:
                patch.start()

        def __exit__(self, *_: Any) -> None:
            for patch in reversed(patches):
                patch.stop()

    return _Combined()


def _temporary_workspaces() -> set[str]:
    """Return the harness's leftover workspaces in the platform temporary directory."""

    root = pathlib.Path(tempfile.gettempdir())
    if not root.is_dir():
        return set()
    return {path.name for path in root.glob("ts-studio-r2-sec-*")}


# ---------------------------------------------------------------------------------------
# 1. contract and implementation must agree
# ---------------------------------------------------------------------------------------


class ContractConsistencyTestCase(unittest.TestCase):
    """Every number and name the contract declares is compared against the harness."""

    def test_bounds_match_the_named_harness_constants(self) -> None:
        bounds = CONTRACT["safety_bounds"]
        names = bounds["harness_constant_names"]
        for key, constant in names.items():
            self.assertEqual(
                bounds[key], getattr(harness, constant), f"{key} disagrees with {constant}"
            )
        self.assertEqual(bounds["max_cases"], 64)
        self.assertEqual(bounds["max_http_requests"], 128)
        self.assertEqual(bounds["max_wall_seconds"], 60)
        self.assertEqual(bounds["max_payload_bytes"], 8192)

    def test_bounds_are_declared_as_safety_limits_and_not_as_targets(self) -> None:
        bounds = CONTRACT["safety_bounds"]
        self.assertEqual(bounds["purpose"], "bounded_local_execution_only")
        self.assertFalse(bounds["are_security_maturity_targets"])
        self.assertFalse(bounds["are_pass_fail_thresholds"])
        self.assertFalse(bounds["compared_against_case_outcomes"])
        self.assertEqual(bounds["enforcement_point"], "preflight_before_resource_creation")
        self.assertEqual(bounds["resources_created_before_enforcement"], 0)
        self.assertTrue(bounds["enforced_again_during_execution"])

    def test_payload_bound_does_not_exceed_the_transport_limit(self) -> None:
        self.assertLessEqual(harness.MAX_PAYLOAD_BYTES, MAX_BODY_BYTES)
        self.assertEqual(CONTRACT["safety_bounds"]["max_payload_bytes"], MAX_BODY_BYTES)
        self.assertTrue(CONTRACT["safety_bounds"]["payload_bound_not_above_transport_limit"])

    def test_defaults_are_not_above_the_bounds(self) -> None:
        defaults = CONTRACT["defaults"]
        for key, constant in defaults["harness_constant_names"].items():
            self.assertEqual(defaults[key], getattr(harness, constant))
        self.assertLessEqual(defaults["wall_timeout_seconds"], harness.MAX_WALL_SECONDS)
        self.assertEqual(defaults["port"], 0)
        self.assertTrue(defaults["are_not_above_bounds"])
        self.assertFalse(defaults["may_exceed_bounds"])

    def test_execution_plan_matches_the_harness_plan_constants(self) -> None:
        plan = CONTRACT["execution_plan"]
        self.assertEqual(plan["planned_cases"], harness.PLANNED_CASE_COUNT)
        self.assertEqual(plan["planned_http_requests"], harness.PLANNED_HTTP_REQUEST_COUNT)
        self.assertEqual(plan["planned_cases"], sum(item["cases"] for item in plan["case_composition"]))
        derived_requests = sum(item["http_requests"] for item in plan["case_composition"]) + sum(
            item["requests"] for item in plan["additional_http_requests"]
        )
        self.assertEqual(plan["planned_http_requests"], derived_requests)
        self.assertLessEqual(plan["planned_cases"], harness.MAX_CASES)
        self.assertLessEqual(plan["planned_http_requests"], harness.MAX_HTTP_REQUESTS)

    def test_target_binding_is_loopback_literals_only(self) -> None:
        binding = CONTRACT["target_binding"]
        self.assertEqual(tuple(binding["allowed_hosts"]), harness.ALLOWED_TARGET_HOSTS)
        self.assertTrue(set(harness.ALLOWED_TARGET_HOSTS) <= set(LOOPBACK_HOSTS))
        self.assertEqual(binding["name_strings"], "rejected")
        self.assertEqual(binding["name_resolution"], "not_attempted")
        self.assertEqual(binding["name_resolution_calls_in_harness"], 0)
        self.assertEqual(binding["port_selection"], "ephemeral")
        self.assertEqual(binding["route_count"], len(ROUTES))
        for count in ("new_http_routes", "new_error_codes", "new_runtime_modules", "new_external_dependencies"):
            self.assertEqual(binding[count], 0)

    def test_declared_routes_are_exactly_the_four_that_exist(self) -> None:
        declared = {entry for entry in CONTRACT["target_binding"]["routes"]}
        actual = {f"{method} {path}" for path, method in ROUTES.items()}
        self.assertEqual(declared, actual)
        self.assertEqual(len(ROUTES), 4)

    def test_dimension_identifiers_match_the_harness_and_the_task(self) -> None:
        declared = tuple(item["id"] for item in CONTRACT["verification_dimensions"])
        self.assertEqual(declared, EXPECTED_DIMENSION_IDS)
        self.assertEqual(declared, harness.DIMENSIONS)
        for item in CONTRACT["verification_dimensions"]:
            self.assertEqual(
                item["severity_if_failed"], harness.FINDING_SEVERITY_BY_DIMENSION[item["id"]]
            )

    def test_malformed_group_is_not_counted_as_a_verification_dimension(self) -> None:
        malformed = CONTRACT["malformed_requests"]
        self.assertFalse(malformed["is_a_verification_dimension"])
        self.assertEqual(malformed["group_id"], harness.MALFORMED_GROUP)
        self.assertNotIn(harness.MALFORMED_GROUP, harness.DIMENSIONS)
        self.assertEqual(malformed["cases"], len(harness.MALFORMED_CASES))
        self.assertEqual(
            malformed["severity_if_failed"],
            harness.FINDING_SEVERITY_BY_DIMENSION[harness.MALFORMED_GROUP],
        )

    def test_mutation_snapshot_fields_match_the_harness_snapshot(self) -> None:
        declared = list(CONTRACT["mutation_snapshot"]["fields"])
        self.assertEqual(
            declared,
            [
                "round_id",
                "phase",
                "balance_units",
                "house_bankroll_units",
                "bets",
                "draw_records",
                "ledger_transactions",
                "audit_events",
            ],
        )
        source = ast.get_source_segment(HARNESS_SOURCE, _function(HARNESS_TREE, "_mutation_snapshot"))
        self.assertIsNotNone(source)
        for field in declared:
            self.assertIn(f'"{field}"', str(source))

    def test_output_contract_matches_the_harness_output_keys(self) -> None:
        output = CONTRACT["output_contract"]
        self.assertEqual(tuple(output["top_level_keys"]), harness.OUTPUT_TOP_LEVEL_KEYS)
        self.assertEqual(tuple(output["environment_keys"]), harness.ENVIRONMENT_KEYS)
        self.assertFalse(output["timing_measurement_emitted"])
        self.assertFalse(output["timing_threshold_declared"])
        self.assertFalse(output["throughput_or_capacity_number_emitted"])

    def test_confidentiality_declarations_match_the_harness_constants(self) -> None:
        confidentiality = CONTRACT["confidentiality"]
        self.assertEqual(
            tuple(confidentiality["entropy_material_pattern_names"]),
            tuple(name for name, _ in harness.ENTROPY_MATERIAL_PATTERNS),
        )
        self.assertEqual(
            confidentiality["state_envelope_path_constant"], "RESPONSE_STATE_ENVELOPE_PATH"
        )
        self.assertEqual(harness.RESPONSE_STATE_ENVELOPE_PATH, "$.state")
        self.assertEqual(
            harness.RESPONSE_PROHIBITED_FIELDS,
            tuple(name for name in PROHIBITED_RECORD_FIELDS if name != "state"),
        )
        for flag in (
            "seed_value_recorded",
            "entropy_bytes_recorded",
            "rejection_count_recorded",
            "internal_entropy_state_recorded",
            "real_secret_or_credential_used",
            "personal_data_used",
        ):
            self.assertFalse(confidentiality[flag])
        self.assertTrue(confidentiality["synthetic_identifiers_only"])

    def test_findings_policy_forbids_remediation_in_this_unit(self) -> None:
        policy = CONTRACT["findings_policy"]
        self.assertFalse(policy["remediation_performed_by_this_unit"])
        self.assertFalse(policy["production_runtime_modified"])
        self.assertEqual(policy["failing_criterion_marked_pass"], "prohibited")
        self.assertEqual(policy["evidence_of_a_failure_erased"], "prohibited")
        self.assertTrue(policy["each_finding_names_a_separate_task_candidate"])
        self.assertEqual(policy["task_candidate_prefix"], harness.REMEDIATION_TASK_CANDIDATE_PREFIX)
        self.assertFalse(policy["task_candidate_is_an_authorisation"])

    def test_audit_manipulation_is_declared_copy_only(self) -> None:
        manipulation = CONTRACT["audit_manipulation"]
        self.assertFalse(manipulation["performed_on_original"])
        self.assertFalse(manipulation["performed_on_repository_tracked_files"])
        self.assertTrue(manipulation["original_hash_compared_before_and_after"])
        self.assertTrue(manipulation["repository_audit_records_hashed_before_and_after"])
        self.assertEqual(
            sorted(manipulation["detection_required_for"]), ["deleted_event", "forged_event_body"]
        )

    def test_cleanup_declarations_do_not_suppress_failures(self) -> None:
        cleanup = CONTRACT["cleanup"]
        self.assertFalse(cleanup["cleanup_errors_suppressed"])
        self.assertEqual(cleanup["cleanup_failure_surfaced_as"], "WORKSPACE_NOT_RELEASED")
        self.assertTrue(cleanup["workspace_absence_asserted_positively"])
        self.assertTrue(cleanup["worker_threads_enrolled_and_joined"])
        self.assertFalse(cleanup["temporary_workspace_inside_repository"])

    def test_frozen_paths_and_new_files_are_declared_consistently(self) -> None:
        frozen = CONTRACT["frozen_paths"]
        self.assertEqual(frozen["modified_by_this_unit"], 0)
        pinned = set(_relative_inputs())
        for relative in frozen["paths"]:
            self.assertIn(relative, pinned, f"{relative} is declared frozen but is not pinned")
        self.assertEqual(sorted(CONTRACT["new_files"]), sorted(_relative_deliverables()[:6]))

    def test_bets_are_declared_accepted_only_in_the_contracted_phase(self) -> None:
        round_state = _read_text(ROUND_STATE_PATH)
        self.assertIn("accept_bets_only_in: OPEN", round_state)
        self.assertEqual(BETS_ACCEPTED_IN.value, "OPEN")
        statement = CONTRACT["verification_dimensions"][1]["statement"]
        self.assertIn("accept_bets_only_in", statement)
        self.assertIn("BETS_ACCEPTED_IN", statement)


def _function(tree: ast.AST, name: str) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


# ---------------------------------------------------------------------------------------
# 2. the bounds are enforced before anything exists
# ---------------------------------------------------------------------------------------


class PreflightRefusalTestCase(unittest.TestCase):
    """A refused configuration must not have created a directory, a socket or a thread."""

    def _refused(self, config: harness.VerificationConfig) -> str:
        before = _temporary_workspaces()
        with _tripwired():
            with self.assertRaises(harness.SecurityVerificationError) as raised:
                harness.run_verification(config)
        self.assertEqual(before, _temporary_workspaces())
        return raised.exception.code

    def test_a_case_ceiling_above_the_approved_bound_is_refused(self) -> None:
        self.assertEqual(
            self._refused(harness.VerificationConfig(max_cases=harness.MAX_CASES + 1)),
            "BOUND_EXCEEDED",
        )

    def test_a_request_ceiling_above_the_approved_bound_is_refused(self) -> None:
        self.assertEqual(
            self._refused(harness.VerificationConfig(max_http_requests=harness.MAX_HTTP_REQUESTS + 1)),
            "BOUND_EXCEEDED",
        )

    def test_a_wall_bound_above_the_approved_bound_is_refused(self) -> None:
        self.assertEqual(
            self._refused(harness.VerificationConfig(wall_timeout_seconds=harness.MAX_WALL_SECONDS + 1)),
            "BOUND_EXCEEDED",
        )

    def test_a_payload_bound_above_the_approved_bound_is_refused(self) -> None:
        self.assertEqual(
            self._refused(harness.VerificationConfig(max_payload_bytes=harness.MAX_PAYLOAD_BYTES + 1)),
            "BOUND_EXCEEDED",
        )

    def test_a_ceiling_below_the_plan_is_refused_before_anything_runs(self) -> None:
        self.assertEqual(self._refused(harness.VerificationConfig(max_cases=1)), "CASE_BUDGET_EXCEEDED")
        self.assertEqual(
            self._refused(harness.VerificationConfig(max_http_requests=1)), "REQUEST_BUDGET_EXCEEDED"
        )

    def test_a_non_integer_bound_is_refused(self) -> None:
        self.assertEqual(
            self._refused(harness.VerificationConfig(max_cases=True)), "CONFIG_INVALID"
        )
        self.assertEqual(
            self._refused(harness.VerificationConfig(wall_timeout_seconds="30")), "CONFIG_INVALID"
        )

    def test_a_non_loopback_ip_literal_is_refused(self) -> None:
        for host in ("10.0.0.1", "192.168.0.5", "0.0.0.0", "8.8.8.8", "::2", "169.254.1.1"):
            with self.subTest(host=host):
                self.assertEqual(
                    self._refused(harness.VerificationConfig(host=host)), "TARGET_NOT_LOOPBACK"
                )

    def test_every_name_string_is_refused_including_the_slice_s_own_aliases(self) -> None:
        for host in ("localhost", "ip6-localhost", "example.com", "internal.invalid", ""):
            with self.subTest(host=host):
                self.assertEqual(
                    self._refused(harness.VerificationConfig(host=host)), "TARGET_NOT_LOOPBACK"
                )
        # The two aliases refused above are in the slice's own allowlist, so this is a
        # deliberate narrowing rather than a disagreement with the transport contract.
        self.assertLess(len(harness.ALLOWED_TARGET_HOSTS), len(LOOPBACK_HOSTS))

    def test_a_fixed_port_is_refused_so_the_port_is_always_ephemeral(self) -> None:
        self.assertEqual(self._refused(harness.VerificationConfig(port=8765)), "PORT_NOT_EPHEMERAL")

    def test_the_target_is_refused_with_every_resolver_broken(self) -> None:
        """The decision is membership, so it must still be made when nothing can be resolved."""

        def _explode(*_: Any, **__: Any) -> Any:
            raise AssertionError("the harness attempted a name resolution")

        with mock.patch.object(socket, "getaddrinfo", _explode), mock.patch.object(
            socket, "gethostbyname", _explode
        ), mock.patch.object(socket, "getfqdn", _explode), mock.patch.object(
            socket, "gethostname", _explode
        ):
            self.assertEqual(
                self._refused(harness.VerificationConfig(host="example.com")), "TARGET_NOT_LOOPBACK"
            )
            self.assertEqual(
                self._refused(harness.VerificationConfig(host="10.0.0.1")), "TARGET_NOT_LOOPBACK"
            )

    def test_a_valid_configuration_survives_preflight(self) -> None:
        """Without this the whole class would pass against a validator that refuses everything."""

        config = harness.VerificationConfig().validate()
        self.assertEqual(config.host, harness.DEFAULT_HOST)
        self.assertEqual(config.port, 0)


# ---------------------------------------------------------------------------------------
# 3. static discipline of the harness and this suite
# ---------------------------------------------------------------------------------------


class StaticDisciplineTestCase(unittest.TestCase):
    """What the harness and this suite may import, call and reach."""

    def test_harness_and_suite_import_the_standard_library_only(self) -> None:
        for label, tree in (("harness", HARNESS_TREE), ("suite", SUITE_TREE)):
            with self.subTest(module=label):
                external = {
                    root
                    for root in _imported_roots(tree)
                    if root not in REPO_PACKAGES and root not in sys.stdlib_module_names
                }
                self.assertEqual(external, set(), f"{label} imports a non-standard-library module")

    def test_no_dependency_manifest_was_introduced(self) -> None:
        for relative in DEPENDENCY_MANIFESTS:
            with self.subTest(manifest=relative):
                self.assertFalse((ROOT / relative).exists(), f"{relative} must not exist")

    def test_no_prohibited_module_is_imported(self) -> None:
        for label, tree in (("harness", HARNESS_TREE), ("suite", SUITE_TREE)):
            with self.subTest(module=label):
                self.assertEqual(_imported_roots(tree) & PROHIBITED_IMPORTS, set())

    def test_the_harness_makes_no_name_resolution_or_out_of_scope_call(self) -> None:
        self.assertEqual(_attribute_chains(HARNESS_TREE) & PROHIBITED_CALL_CHAINS, set())

    def test_the_suite_makes_no_out_of_scope_call_beyond_the_resolvers_it_breaks(self) -> None:
        # The suite names two identity calls on purpose: it asks the machine for its host name
        # and the account name so it can assert neither appears in the emitted record. That is
        # the opposite of leaking them, and it is the only exemption.
        allowed = {"platform.node", "getpass.getuser"}
        self.assertEqual((_attribute_chains(SUITE_TREE) & PROHIBITED_CALL_CHAINS) - allowed, set())

    def test_the_harness_declares_no_new_error_code(self) -> None:
        """Every ``error.code`` the harness expects must already exist in the slice contract."""

        slice_contract = _read_text(SLICE_CONTRACT_PATH)
        declared = set(re.findall(r"^\s+- ([A-Z][A-Z_]{2,})$", slice_contract, flags=re.MULTILINE))
        expected = {case["expected"] for case in harness.MALFORMED_CASES} - {"NONE"}
        expected |= {"CLIENT_AUTHORITY_DENIED", "BAD_REQUEST", "BET_INVALID", "PHASE_DENIED"}
        expected |= {"ROUND_IN_PROGRESS", "REQUEST_ID_CONFLICT"}
        self.assertTrue(expected <= declared, f"undeclared codes: {sorted(expected - declared)}")

    def test_the_malformed_case_table_is_a_fixed_constant(self) -> None:
        self.assertIsInstance(harness.MALFORMED_CASES, tuple)
        self.assertEqual(len(harness.MALFORMED_CASES), 13)
        identifiers = [case["case_id"] for case in harness.MALFORMED_CASES]
        self.assertEqual(len(set(identifiers)), len(identifiers))
        for case in harness.MALFORMED_CASES:
            with self.subTest(case=case["case_id"]):
                self.assertIn(case["method"], {"GET", "POST", "PUT"})
                self.assertIsInstance(case["path"], str)
                self.assertIsInstance(case["expected"], str)
                body = case.get("body")
                self.assertTrue(body is None or isinstance(body, bytes))
                if isinstance(body, bytes):
                    self.assertLessEqual(len(body), harness.MAX_PAYLOAD_BYTES)

    def test_every_declared_authority_field_has_a_forged_value(self) -> None:
        self.assertEqual(set(harness._FORGED_VALUES), set(CLIENT_AUTHORITY_FIELDS))
        self.assertEqual(len(CLIENT_AUTHORITY_FIELDS), 13)

    def test_no_test_here_waits_on_a_fixed_pause(self) -> None:
        self.assertNotIn("time.sleep", _attribute_chains(SUITE_TREE))
        self.assertNotIn("time.sleep", _attribute_chains(HARNESS_TREE))

    def test_the_validator_was_not_extended_by_this_unit(self) -> None:
        """AC-013: the baseline validator gains no stage, and none of this unit's files.

        The validator already names ``R2-SEC-0005`` once, in the tuple of R2 units the
        durable-state unit deferred. That mention predates this unit and is exactly what an
        untouched validator should still say, so the assertion is that the *count* has not
        grown and that no file of this unit appears in it at all.
        """

        validator = _read_text("scripts/validate_baseline.py")
        self.assertEqual(validator.count("R2-SEC-0005"), 1, "the validator gained a new mention")
        self.assertIn('R2_DBC_DEFERRED_UNITS = ("R2-NET-0003", "R2-LOAD-0004", "R2-SEC-0005")', validator)
        for fragment in ("verify_r2_security", "security-verification-contract", "test_security_verification"):
            with self.subTest(fragment=fragment):
                self.assertFalse(fragment in validator, f"the validator references {fragment}")


# ---------------------------------------------------------------------------------------
# 4. the verifier's own detectors must be able to fire
# ---------------------------------------------------------------------------------------


class DetectorTestCase(unittest.TestCase):
    """A verifier whose detectors never fire would report a clean run over a broken surface."""

    def test_entropy_material_detector_catches_planted_material(self) -> None:
        """The planted material is assembled here rather than written out as a literal.

        This file is one of the documents the harness scans, so a literal specimen of the
        thing the detector looks for would make the scan report this suite -- and the fix for
        that would be to stop scanning the suite, which is the wrong trade. Assembling the
        specimens at run time keeps the source clean and still feeds the detector exactly
        what it is supposed to catch.
        """

        long_hex = "the value is " + "ab" * 20
        escape_run = "".join("\\x%02x" % value for value in (0, 17, 34, 51, 68))
        assigned = "seed" + "_value" + " = " + "Q" * 20

        self.assertIn("unlabelled_long_hex_run", harness._entropy_material_hits(long_hex))
        self.assertIn("byte_escape_sequence_run", harness._entropy_material_hits(escape_run))
        self.assertIn(
            "entropy_material_assigned_to_a_key", harness._entropy_material_hits(assigned)
        )

    def test_entropy_material_detector_accepts_a_published_digest(self) -> None:
        clean = 'proof_hash: "sha256:' + "0" * 64 + '"'
        self.assertEqual(harness._entropy_material_hits(clean), [])
        self.assertEqual(harness._entropy_material_hits("entropy-ref://os-csprng/CSPRNG-X"), [])

    def test_response_marker_detector_catches_a_leaked_internal_detail(self) -> None:
        self.assertIn("traceback", harness._prohibited_markers("Traceback (most recent call last)"))
        self.assertIn("sqlite", harness._prohibited_markers("sqlite3.OperationalError"))
        self.assertEqual(harness._prohibited_markers('{"error":{"code":"BAD_JSON"}}'), [])

    def test_key_path_detector_distinguishes_the_envelope_from_a_nested_state(self) -> None:
        self.assertEqual(harness._key_paths({"state": {"a": 1}}, "state"), ["$.state"])
        nested = {"state": {"round": {"state": {"entropy": 1}}}}
        self.assertIn("$.state.round.state", harness._key_paths(nested, "state"))

    def test_prohibited_key_detector_matches_keys_and_not_reference_text(self) -> None:
        self.assertEqual(harness._keys_present({"seed": 1}, ("seed",)), ["seed"])
        self.assertEqual(
            harness._keys_present({"resource_refs": ["rng-entropy://entropy-ref://x/y"]}, ("entropy",)),
            [],
        )

    def test_float_detector_finds_a_currency_float_anywhere(self) -> None:
        self.assertEqual(harness._find_floats({"a": [{"stake_units": 1.5}]}), ["$.a[0].stake_units"])
        self.assertEqual(harness._find_floats({"a": [{"stake_units": 1}]}), [])

    def test_the_case_ledger_refuses_to_cross_its_own_bound(self) -> None:
        ledger = harness._CaseLedger(harness.VerificationConfig(max_cases=1, max_http_requests=1))
        ledger.record("C-1", "g", "expectation", True, "detail")
        with self.assertRaises(harness.SecurityVerificationError) as raised:
            ledger.record("C-2", "g", "expectation", True, "detail")
        self.assertEqual(raised.exception.code, "CASE_BUDGET_EXCEEDED")
        ledger.spend_request()
        with self.assertRaises(harness.SecurityVerificationError) as raised:
            ledger.spend_request()
        self.assertEqual(raised.exception.code, "REQUEST_BUDGET_EXCEEDED")

    def test_a_group_with_one_failed_case_does_not_hold(self) -> None:
        ledger = harness._CaseLedger(harness.VerificationConfig())
        ledger.record("C-1", "g", "expectation", True, "detail")
        self.assertTrue(ledger.group_holds("g"))
        ledger.record("C-2", "g", "expectation", False, "detail")
        self.assertFalse(ledger.group_holds("g"))
        self.assertEqual(len(ledger.failed()), 1)

    def test_a_failed_case_becomes_a_sanitized_finding_and_never_a_repair(self) -> None:
        ledger = harness._CaseLedger(harness.VerificationConfig())
        ledger.record("C-1", "seed_reference_confidentiality", "expectation", False, "code=X")
        findings = harness._findings(ledger)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertTrue(findings[0]["sanitized"])
        self.assertFalse(findings[0]["reproducible_payload_recorded"])
        self.assertFalse(findings[0]["remediation_performed_by_this_unit"])
        self.assertTrue(
            findings[0]["remediation_task_candidate"].startswith(
                harness.REMEDIATION_TASK_CANDIDATE_PREFIX
            )
        )

    def test_the_audit_chain_verifier_reports_a_broken_link(self) -> None:
        """The detection the audit dimension leans on, exercised on synthetic events."""

        clean = [
            {"previous_event_hash": None, "contains_secret": False, "event_id": "AE-X-0001"},
            {"previous_event_hash": None, "contains_secret": False, "event_id": "AE-X-0002"},
        ]
        for index, event in enumerate(clean):
            if index:
                event["previous_event_hash"] = clean[index - 1]["event_hash"]
            event["event_hash"] = compute_event_hash(event)
        self.assertEqual(verify_audit_chain(clean), [])
        forged = json.loads(json.dumps(clean))
        forged[1]["event_id"] = "AE-X-9999"
        self.assertNotEqual(verify_audit_chain(forged), [])
        self.assertNotEqual(verify_audit_chain([clean[1]]), [])


# ---------------------------------------------------------------------------------------
# 5. one real bounded verification
# ---------------------------------------------------------------------------------------


class VerificationRunTestCase(unittest.TestCase):
    """Everything the harness claims, asserted over a record it actually produced."""

    record: dict[str, Any]
    workspaces_before: set[str]
    workspaces_after: set[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.workspaces_before = _temporary_workspaces()
        cls.record = harness.run_verification(harness.VerificationConfig())
        cls.workspaces_after = _temporary_workspaces()

    def test_every_declared_dimension_holds(self) -> None:
        results = self.record["dimensions"]["results"]
        failed = sorted(name for name, held in results.items() if not held)
        self.assertEqual(failed, [], f"dimensions that did not hold: {failed}")
        self.assertTrue(self.record["dimensions"]["all_dimensions_hold"])
        self.assertEqual(tuple(self.record["dimensions"]["declared"]), EXPECTED_DIMENSION_IDS)

    def test_no_case_failed_and_therefore_no_finding_was_recorded(self) -> None:
        failed = [case for case in self.record["cases"] if not case["held"]]
        self.assertEqual(
            [case["case_id"] for case in failed], [], f"failed cases: {[c['detail'] for c in failed]}"
        )
        self.assertEqual(self.record["findings"], [])
        self.assertEqual(self.record["remediation"]["findings_recorded"], 0)
        self.assertFalse(self.record["remediation"]["performed_by_this_unit"])

    def test_the_run_stayed_inside_every_bound_and_matched_its_plan(self) -> None:
        counts = self.record["counts"]
        self.assertEqual(counts["executed_cases"], harness.PLANNED_CASE_COUNT)
        self.assertEqual(counts["executed_http_requests"], harness.PLANNED_HTTP_REQUEST_COUNT)
        self.assertTrue(counts["plan_matches_execution"])
        self.assertLessEqual(counts["executed_cases"], harness.MAX_CASES)
        self.assertLessEqual(counts["executed_http_requests"], harness.MAX_HTTP_REQUESTS)
        self.assertTrue(counts["cases_within_bound"])
        self.assertTrue(counts["http_requests_within_bound"])

    def test_every_client_authority_field_was_covered_at_a_nested_position(self) -> None:
        evidence = self.record["dimensions"]["evidence"]["client_authority_forgery_denial"]
        self.assertEqual(evidence["declared_authority_fields"], len(CLIENT_AUTHORITY_FIELDS))
        self.assertEqual(evidence["authority_fields_covered"], len(CLIENT_AUTHORITY_FIELDS))
        self.assertTrue(evidence["every_declared_field_covered"])
        self.assertTrue(evidence["nested_placement_covered"])
        self.assertTrue(evidence["top_level_placement_covered"])
        self.assertTrue(evidence["list_nested_placement_covered"])
        authority_cases = [
            case for case in self.record["cases"] if case["group"] == "client_authority_forgery_denial"
        ]
        self.assertEqual(len(authority_cases), 15)
        for case in authority_cases:
            with self.subTest(case=case["case_id"]):
                self.assertIn("snapshot_unchanged=True", case["detail"])

    def test_every_denial_left_the_mutation_snapshot_untouched(self) -> None:
        denials = [
            case
            for case in self.record["cases"]
            if case["group"]
            in ("client_authority_forgery_denial", "betting_phase_lock_bypass_denial")
            and "snapshot_unchanged" in case["detail"]
        ]
        self.assertGreaterEqual(len(denials), 19)
        for case in denials:
            with self.subTest(case=case["case_id"]):
                self.assertIn("snapshot_unchanged=True", case["detail"])

    def test_a_repeated_identifier_committed_exactly_once(self) -> None:
        evidence = self.record["dimensions"]["evidence"]["idempotency_and_settlement_replay_safety"]
        self.assertEqual(evidence["spin_submissions"], 3)
        self.assertEqual(evidence["fresh_commits"], 1)
        self.assertEqual(evidence["replays"], 2)
        self.assertEqual(evidence["distinct_commit_identities"], 1)
        self.assertEqual(evidence["conflicting_submissions_refused"], 2)
        self.assertEqual(evidence["entropy_reads_during_replay"], 0)
        self.assertEqual(evidence["entropy_bytes_during_replay"], 0)
        self.assertFalse(evidence["entropy_material_recorded"])

    def test_the_settlement_reconciles_in_integer_minimum_units(self) -> None:
        settlement = self.record["evidence"]["settlement"]
        self.assertTrue(settlement["balance_delta_matches_ledger"])
        self.assertEqual(
            settlement["player_balance_delta_units"], settlement["ledger_player_delta_units"]
        )
        self.assertTrue(settlement["ledger_entries_sum_to_zero"])
        self.assertEqual(settlement["float_values_found"], 0)
        self.assertTrue(settlement["currency_is_integer_only"])
        self.assertEqual(settlement["audit_chain_problems_after_reload"], 0)
        self.assertEqual(settlement["committed_draw_records"], 2)
        self.assertEqual(settlement["committed_ledger_transactions"], 2)

    def test_the_audit_manipulation_happened_only_on_copies(self) -> None:
        evidence = self.record["dimensions"]["evidence"][
            "audit_event_tamper_and_delete_detection_on_copy"
        ]
        self.assertTrue(evidence["every_manipulated_path_is_inside_the_workspace"])
        self.assertTrue(evidence["original_database_hash_unchanged"])
        self.assertTrue(evidence["repository_audit_records_unchanged"])
        self.assertGreaterEqual(evidence["repository_audit_records_checked"], 2)
        self.assertTrue(evidence["append_only_guard_refuses_update"])
        self.assertTrue(evidence["append_only_guard_refuses_delete"])
        self.assertGreater(evidence["forged_copy_problems"], 0)
        self.assertGreater(evidence["deleted_copy_problems"], 0)

    def test_no_seed_material_reached_any_surface(self) -> None:
        evidence = self.record["dimensions"]["evidence"]["seed_reference_confidentiality"]
        self.assertEqual(evidence["seed_reference_form"], "entropy-ref://<source-id>/<algorithm-id>")
        self.assertEqual(evidence["distinct_seed_references"], 1)
        self.assertFalse(evidence["seed_value_recorded"])
        self.assertFalse(evidence["rejection_count_recorded"])
        self.assertFalse(evidence["entropy_bytes_recorded"])
        self.assertEqual(evidence["documents_with_entropy_material"], 0)
        self.assertEqual(evidence["documents_absent_at_scan_time"], 0)
        self.assertEqual(evidence["documents_scanned"], len(harness.SANITIZATION_SCAN_TARGETS))

    def test_malformed_requests_leaked_no_internal_detail(self) -> None:
        evidence = self.record["dimensions"]["evidence"]["malformed_request_safety"]
        self.assertEqual(evidence["responses_leaking_internal_detail"], 0)
        self.assertTrue(evidence["fixed_input_set"])
        self.assertFalse(evidence["random_generation"])
        self.assertFalse(evidence["time_based_mutation"])
        self.assertFalse(evidence["repetition_storm"])
        self.assertFalse(evidence["destructive_on_source_data"])
        final = [case for case in self.record["cases"] if case["case_id"] == "SEC-MAL-13"]
        self.assertEqual(len(final), 1)
        self.assertTrue(final[0]["held"])
        self.assertIn("status=200", final[0]["detail"])

    def test_the_output_never_names_the_operator(self) -> None:
        serialized = json.dumps(self.record, ensure_ascii=False)
        for forbidden in (
            platform.node(),
            getpass.getuser(),
            os.getcwd(),
            tempfile.gettempdir(),
            str(ROOT),
        ):
            if not forbidden:
                continue
            with self.subTest(value=forbidden[:12]):
                self.assertNotIn(forbidden, serialized)
        self.assertIsNone(
            re.search(r"[A-Za-z]:\\\\|(?<![\w/])/(?:home|Users|tmp|var)/", serialized)
        )

    def test_the_output_carries_no_timing_or_capacity_number(self) -> None:
        serialized = json.dumps(self.record, ensure_ascii=False)
        for forbidden in ("latency", "throughput", "requests_per_second", "p95", "elapsed_ms"):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, serialized)

    def test_the_output_keys_are_exactly_the_declared_ones(self) -> None:
        self.assertEqual(tuple(self.record), harness.OUTPUT_TOP_LEVEL_KEYS)
        self.assertEqual(tuple(self.record["environment"]), harness.ENVIRONMENT_KEYS)

    def test_no_route_error_code_or_runtime_module_was_added(self) -> None:
        evidence = self.record["evidence"]
        self.assertEqual(sorted(evidence["routes_observed"]), sorted(ROUTES))
        for key in ("new_http_routes", "new_error_codes", "new_runtime_modules", "new_dependencies"):
            self.assertEqual(evidence[key], 0)
        self.assertFalse(evidence["runtime_code_modified"])
        self.assertFalse(evidence["remediation_applied"])

    def test_the_workspace_and_every_thread_were_released(self) -> None:
        cleanup = self.record["cleanup"]
        self.assertTrue(cleanup["workspace_released"])
        self.assertFalse(cleanup["cleanup_errors_suppressed"])
        self.assertTrue(cleanup["server_thread_stopped"])
        self.assertTrue(cleanup["worker_threads_joined"])
        self.assertFalse(cleanup["temporary_workspace_inside_repository"])
        self.assertEqual(self.workspaces_before, self.workspaces_after)

    def test_the_bounds_block_restates_them_as_safety_limits(self) -> None:
        bounds = self.record["bounds"]
        self.assertFalse(bounds["are_security_maturity_targets"])
        self.assertFalse(bounds["are_pass_fail_thresholds"])
        self.assertTrue(bounds["enforced_before_resource_creation"])
        self.assertTrue(bounds["payload_bound_within_transport_limit"])
        self.assertEqual(bounds["transport_max_body_bytes"], MAX_BODY_BYTES)


class RepeatedVerificationTestCase(unittest.TestCase):
    """AC-015: a second run must reach the same verdict, case for case."""

    def test_a_second_run_reaches_an_identical_verdict(self) -> None:
        before = _temporary_workspaces()
        first = harness.run_verification(harness.VerificationConfig())
        second = harness.run_verification(harness.VerificationConfig())
        self.assertEqual(before, _temporary_workspaces())

        def shape(record: dict[str, Any]) -> list[tuple[str, str, str, bool]]:
            return [
                (case["case_id"], case["group"], case["expectation"], case["held"])
                for case in record["cases"]
            ]

        self.assertEqual(shape(first), shape(second))
        self.assertEqual(first["dimensions"]["results"], second["dimensions"]["results"])
        self.assertEqual(first["counts"]["executed_cases"], second["counts"]["executed_cases"])
        self.assertEqual(
            first["counts"]["executed_http_requests"], second["counts"]["executed_http_requests"]
        )
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual(tuple(first), tuple(second))


# ---------------------------------------------------------------------------------------
# 6. frozen paths, contracts and scope
# ---------------------------------------------------------------------------------------


class FrozenPathTestCase(unittest.TestCase):
    """The thirty-one pinned paths, re-hashed, plus this unit's own contract integrity."""

    def test_every_pinned_input_still_matches_its_declared_hash(self) -> None:
        self.assertEqual(len(TASK["inputs"]), 31)
        for entry in TASK["inputs"]:
            relative = entry["uri"][len("repo://") :]
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"{relative} is missing")
                self.assertEqual(_hash(relative), entry["content_hash"])

    def test_the_task_is_ready_high_risk_and_owned_by_one_agent(self) -> None:
        self.assertEqual(TASK["task_id"], "R2-SEC-0005")
        self.assertEqual(TASK["status"], "READY")
        self.assertEqual(TASK["risk_class"], "HIGH")
        self.assertEqual(TASK["owner_agent_id"], "A-02")
        self.assertIn("USER", TASK["approvers"])
        self.assertIn("A-50", TASK["approvers"])
        self.assertEqual(TASK["security"]["network_policy"], "NONE")
        self.assertEqual(TASK["security"]["secrets_policy"], "NONE")
        self.assertFalse(TASK["security"]["contains_pii"])

    def test_every_declared_deliverable_exists(self) -> None:
        for relative in _relative_deliverables():
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"{relative} is missing")

    def test_the_artifact_binds_the_contract_it_represents(self) -> None:
        artifact = json.loads(_read_text(ARTIFACT_PATH))
        self.assertEqual(artifact["task_id"], "R2-SEC-0005")
        self.assertEqual(artifact["uri"], f"repo://{CONTRACT_PATH}")
        self.assertEqual(artifact["content_hash"], _hash(CONTRACT_PATH))
        self.assertNotIn(artifact["source"]["created_by"], artifact["reviewers"])
        self.assertEqual(artifact["source"]["provider"], "claude_agent")
        self.assertEqual(
            artifact["source"]["input_hash"], _hash("docs/operations/R2-followup-units.md")
        )
        self.assertIsNone(artifact["approved_at"])

    def test_the_artifact_records_the_component_hashes_it_claims(self) -> None:
        artifact = json.loads(_read_text(ARTIFACT_PATH))
        specification = artifact["specification"]
        components = {
            "component_hash_security_verification_contract": CONTRACT_PATH,
            "component_hash_verification_harness": HARNESS_PATH,
            "component_hash_verification_test_suite": SUITE_PATH,
            "component_hash_design_document": DESIGN_PATH,
            "component_hash_validation_report": REPORT_PATH,
            "component_hash_audit_events": EVENTS_PATH,
        }
        for key, relative in components.items():
            with self.subTest(component=relative):
                self.assertIn(key, specification)
                self.assertEqual(specification[key], _hash(relative))

    def test_the_handoff_is_addressed_for_independent_verification(self) -> None:
        handoff = json.loads(_read_text(HANDOFF_PATH))
        self.assertEqual(handoff["task_id"], "R2-SEC-0005")
        self.assertEqual(handoff["from_agent_id"], "A-02")
        self.assertEqual(handoff["to_agent_id"], "A-20")
        self.assertNotEqual(handoff["from_agent_id"], handoff["to_agent_id"])
        self.assertTrue(handoff["acknowledgement_required"])
        self.assertIn("ART-R2-SEC-0005-0001", handoff["artifact_refs"])
        results = {item["check"]: item["result"] for item in handoff["verification_evidence"]}
        for command in ("python scripts/validate_baseline.py", "python -m unittest discover -s tests -v"):
            with self.subTest(command=command):
                self.assertIn(command, results)
        self.assertIn(handoff["readiness"], {"READY_FOR_REVIEW", "READY_FOR_QA", "REWORK_REQUIRED"})

    def test_the_handoff_readiness_and_the_command_records_agree(self) -> None:
        """A packet may not claim review readiness while recording a command that did not pass."""

        handoff = json.loads(_read_text(HANDOFF_PATH))
        results = {item["check"]: item["result"] for item in handoff["verification_evidence"]}
        commands = ("python scripts/validate_baseline.py", "python -m unittest discover -s tests -v")
        passing = all(results.get(command) == "PASS" for command in commands)
        if handoff["readiness"] in {"READY_FOR_REVIEW", "READY_FOR_QA"}:
            self.assertTrue(passing, "review readiness requires both commands recorded as PASS")
        else:
            self.assertFalse(passing, "a packet recording both commands as PASS is not in rework")

    def test_no_final_gate_is_claimed_by_this_unit(self) -> None:
        artifact = json.loads(_read_text(ARTIFACT_PATH))
        specification = artifact["specification"]
        for claim in (
            "a50_qa_gate_decision",
            "a00_gate_decision",
            "user_final_approval",
            "hosted_ci_status",
            "commit_push_merge_status",
        ):
            with self.subTest(claim=claim):
                self.assertEqual(specification[claim], "NOT_RUN")
        self.assertFalse(specification["human_approved"])
        self.assertFalse(specification["production_ready"])
        self.assertFalse(specification["committed"])
        self.assertFalse(specification["pushed"])
        self.assertFalse(specification["merged"])


class AuditEventsTestCase(unittest.TestCase):
    """The unit's own audit record: shaped, chained, attached to this task, and honest."""

    document: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(_read_text(EVENTS_PATH))

    def test_every_event_carries_the_required_shape(self) -> None:
        required = (
            "schema_version",
            "event_id",
            "event_type",
            "timestamp",
            "actor_type",
            "actor_id",
            "task_id",
            "action",
            "resource_refs",
            "decision",
            "policy_version",
            "request_hash",
            "previous_event_hash",
            "event_hash",
            "contains_secret",
        )
        events = self.document["events"]
        self.assertGreaterEqual(len(events), 8)
        for event in events:
            with self.subTest(event=event.get("event_id")):
                self.assertEqual(sorted(event), sorted(required))
                self.assertEqual(event["schema_version"], "1.0.0")
                self.assertEqual(event["task_id"], "R2-SEC-0005")
                self.assertIs(event["contains_secret"], False)
                self.assertIsNotNone(re.fullmatch(r"AE-[A-Z0-9]+-[0-9]{4}", event["event_id"]))
                self.assertIsNotNone(re.fullmatch(r"sha256:[a-f0-9]{64}", event["request_hash"]))
                self.assertIsNotNone(re.fullmatch(r"sha256:[a-f0-9]{64}", event["event_hash"]))
                self.assertIn(
                    event["decision"], {"ALLOW", "DENY", "START", "COMPLETE", "FAIL", "BLOCK"}
                )

    def test_the_chain_links_and_verifies(self) -> None:
        self.assertEqual(verify_audit_chain(self.document["events"]), [])

    def test_the_record_keeps_the_gate_and_the_scope_boundaries_visible(self) -> None:
        actions = {event["action"] for event in self.document["events"]}
        self.assertIn("FINAL_GATE_AND_HOSTED_CI_NOT_RUN", actions)
        self.assertIn("REMEDIATION_WITHHELD_FROM_THIS_UNIT", actions)
        serialized = json.dumps(self.document, ensure_ascii=False)
        self.assertEqual(harness._entropy_material_hits(serialized), [])


class ReportConsistencyTestCase(unittest.TestCase):
    """The validation report and the design document must restate what the code does."""

    report: str
    design: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = _read_text(REPORT_PATH)
        cls.design = _read_text(DESIGN_PATH)

    def test_the_report_restates_the_approved_bounds(self) -> None:
        for value in ("64", "128", "60", "8192"):
            with self.subTest(value=value):
                self.assertIn(value, self.report)
        self.assertIn(str(harness.PLANNED_CASE_COUNT), self.report)
        self.assertIn(str(harness.PLANNED_HTTP_REQUEST_COUNT), self.report)

    def test_both_documents_name_every_dimension(self) -> None:
        for dimension in EXPECTED_DIMENSION_IDS:
            with self.subTest(dimension=dimension):
                self.assertIn(dimension, self.report)
                self.assertIn(dimension, self.design)

    def test_the_report_states_that_no_remediation_was_performed(self) -> None:
        self.assertIn(harness.REMEDIATION_TASK_CANDIDATE_PREFIX, self.report)
        for phrase in ("A-50", "USER", "NOT_RUN"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.report)

    def test_neither_document_carries_entropy_material(self) -> None:
        self.assertEqual(harness._entropy_material_hits(self.report), [])
        self.assertEqual(harness._entropy_material_hits(self.design), [])

    def test_neither_document_declares_a_schedule_or_a_release_date(self) -> None:
        for text, label in ((self.report, "report"), (self.design, "design")):
            with self.subTest(document=label):
                self.assertNotIn("출시일", text)
                self.assertNotIn("release date", text.lower())


class ScopeBoundaryTestCase(unittest.TestCase):
    """What this unit added, and what it never went near."""

    def test_the_files_this_suite_read_contain_no_r4_asset_or_art_path(self) -> None:
        for relative in sorted(set(_FILES_READ)):
            for fragment in R4_AND_ASSET_PATH_FRAGMENTS:
                with self.subTest(path=relative, fragment=fragment):
                    self.assertNotIn(fragment, relative)

    def test_no_new_file_of_this_unit_references_an_asset_image_or_art_file(self) -> None:
        for relative in DECLARED_NEW_FILES:
            with self.subTest(path=relative):
                self.assertIsNone(ASSET_EXTENSION.search(_read_text(relative)))

    def test_r4_art_0007_is_neither_pinned_nor_delivered_by_this_unit(self) -> None:
        """Naming it as unmodified is correct; pinning or delivering it would not be.

        The R4 art contract may legitimately be *mentioned* -- the Task Contract's rollback
        clause and the verification contract both say it must stay untouched. What must not
        happen is the integrity re-pinning chain reaching it, so the assertion is about the
        pinned and delivered sets rather than about the word appearing in a sentence.
        """

        r4_task = "tasks/R4-ART-0007.json"
        self.assertNotIn(r4_task, _relative_inputs())
        self.assertNotIn(r4_task, _relative_deliverables())
        self.assertNotIn(r4_task, DECLARED_NEW_FILES)

    def test_the_declared_new_file_set_is_exactly_nine(self) -> None:
        self.assertEqual(len(DECLARED_NEW_FILES), 9)
        self.assertEqual(len(set(DECLARED_NEW_FILES)), 9)
        for relative in DECLARED_NEW_FILES:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())
        declared = set(_relative_deliverables()) | {TASK_PATH}
        self.assertEqual(declared, set(DECLARED_NEW_FILES))

    def test_no_new_file_of_this_unit_is_a_runtime_module_of_the_observed_slice(self) -> None:
        modules = sorted(path.name for path in (ROOT / "apps/roulette_web").glob("*.py"))
        self.assertEqual(modules, ["__init__.py", "server.py", "table.py"])
        for relative in DECLARED_NEW_FILES:
            with self.subTest(path=relative):
                self.assertFalse(relative.startswith("apps/"))
                self.assertFalse(relative.startswith("studio_core/"))


if __name__ == "__main__":
    unittest.main()
