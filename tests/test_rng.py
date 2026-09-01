"""R2-RNG-0001: certification suite for the production CSPRNG draw boundary.

The suite is organised by the property it defends rather than by the class it calls, because
the acceptance criteria are stated as properties. Unbiasedness is proved by exhausting the
byte domain; the statistical tests defend the assumption that the live entropy source behaves
like the uniform source that proof presumes.
"""

from __future__ import annotations

import ast
import copy
import json
import pathlib
import random
import shutil
import tempfile
import threading
import unittest

from studio_core.rng import (
    ACCEPTED_BYTE_LIMIT,
    ALGORITHM_ID,
    ALGORITHM_VERSION,
    AUDIT_TASK_ID,
    BYTE_DOMAIN,
    MAX_REJECTION_ATTEMPTS,
    POCKET_COUNT,
    PROHIBITED_RECORD_FIELDS,
    RRNG_SCHEMA_VERSION,
    RULESET_ID,
    AuditChain,
    DeterministicTestEntropySource,
    DrawRequest,
    FailureAction,
    OsCsprngEntropySource,
    RngDenied,
    RngEnvironment,
    RouletteDrawEngine,
    compute_event_hash,
    compute_proof_hash,
    draw_pocket,
    map_entropy_byte,
    mapping_distribution,
    read_entropy,
    verify_audit_chain,
    verify_draw_record,
)
from studio_core import rng_stats
from studio_core.rng_stats import (
    DEFAULT_ALPHA,
    certify_stream,
    chi_square_p_value,
    pair_counts,
    pocket_counts,
    rejection_rate_test,
    serial_independence_test,
    summarize,
    uniformity_test,
)
from scripts.validate_baseline import (
    BaselineValidationError,
    R2_RNG_INPUT_FILES,
    ROOT,
    load_json,
    validate_instance,
    validate_r2_rng,
    validate_schema_structure,
)


def _imported_modules(relative_path: str) -> set[str]:
    """Return every module name imported by a source file, via its parse tree.

    A text search for ``import x`` is evadable by spelling the import differently, and an
    architecture rule that a violation can sidestep is not a rule. The parse tree sees every
    form, including ``importlib.import_module`` targets spelled as literals.
    """

    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level
            names.add(f"{prefix}{node.module or ''}")
        elif isinstance(node, ast.Call):
            function = node.func
            target = getattr(function, "attr", getattr(function, "id", None))
            if target == "import_module":
                names.update(
                    argument.value for argument in node.args if isinstance(argument, ast.Constant)
                    and isinstance(argument.value, str)
                )
    return names

FIXED_CLOCK = "2026-09-01T00:00:00Z"
EXPECTED_ACCEPTANCE_RATE = ACCEPTED_BYTE_LIMIT / BYTE_DOMAIN


def _engine(stream: bytes = b"\x11", **overrides) -> RouletteDrawEngine:
    """Return a non-production engine over a reproducible entropy stream."""

    options = {
        "entropy_source": DeterministicTestEntropySource(stream),
        "environment": RngEnvironment.NON_PRODUCTION,
        "audit_sink": AuditChain("TEST"),
        "clock": lambda: FIXED_CLOCK,
    }
    options.update(overrides)
    return RouletteDrawEngine(**options)


def _request(index: int = 1, round_index: int | None = None) -> DrawRequest:
    return DrawRequest(
        request_id=f"RNG-TEST-{index:04d}",
        round_id=f"RR-TEST-{round_index if round_index is not None else index:04d}",
    )


class UnbiasedMappingTests(unittest.TestCase):
    """AC-003: the mapping is proved unbiased by enumeration, not by sampling."""

    def test_accepted_limit_is_the_largest_multiple_of_the_pocket_count(self) -> None:
        self.assertEqual(ACCEPTED_BYTE_LIMIT, 222)
        self.assertEqual(ACCEPTED_BYTE_LIMIT, POCKET_COUNT * (BYTE_DOMAIN // POCKET_COUNT))
        self.assertEqual(ACCEPTED_BYTE_LIMIT % POCKET_COUNT, 0)

    def test_every_pocket_claims_exactly_six_of_the_256_byte_values(self) -> None:
        distribution = mapping_distribution()
        for pocket in range(POCKET_COUNT):
            self.assertEqual(distribution[pocket], 6, f"pocket {pocket} is not balanced")
        self.assertEqual(distribution[None], BYTE_DOMAIN - ACCEPTED_BYTE_LIMIT)
        self.assertEqual(distribution[None], 34)
        self.assertEqual(sum(distribution.values()), BYTE_DOMAIN)

    def test_naive_modulo_would_have_been_biased(self) -> None:
        # Documents why rejection sampling exists: the shortcut is measurably unfair.
        naive: dict[int, int] = {pocket: 0 for pocket in range(POCKET_COUNT)}
        for value in range(BYTE_DOMAIN):
            naive[value % POCKET_COUNT] += 1
        self.assertEqual(set(naive.values()), {6, 7})

    def test_rejected_bytes_map_to_none_and_accepted_bytes_stay_in_range(self) -> None:
        for value in range(ACCEPTED_BYTE_LIMIT, BYTE_DOMAIN):
            self.assertIsNone(map_entropy_byte(value))
        for value in range(ACCEPTED_BYTE_LIMIT):
            pocket = map_entropy_byte(value)
            self.assertIsInstance(pocket, int)
            self.assertTrue(0 <= pocket < POCKET_COUNT)

    def test_bytes_outside_the_domain_are_denied_without_echoing_the_value(self) -> None:
        for value in (-1, 256, 999, True, 1.5, "17"):
            with self.assertRaises(RngDenied) as caught:
                map_entropy_byte(value)  # type: ignore[arg-type]
            self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_INVALID")
            self.assertNotIn(str(value), str(caught.exception))


class EntropySourceTests(unittest.TestCase):
    """AC-002: only the OS CSPRNG may back a production draw."""

    def test_os_source_is_not_deterministic_and_returns_the_requested_size(self) -> None:
        source = OsCsprngEntropySource()
        self.assertFalse(source.is_deterministic)
        self.assertEqual(source.source_id, "os-csprng")
        for size in (1, 8, 64):
            self.assertEqual(len(source.read(size)), size)

    def test_os_source_rejects_non_positive_and_non_integer_sizes(self) -> None:
        source = OsCsprngEntropySource()
        for size in (0, -1, True, 1.5, "8"):
            with self.assertRaises(RngDenied) as caught:
                source.read(size)  # type: ignore[arg-type]
            self.assertEqual(caught.exception.code, "ENTROPY_REQUEST_INVALID")

    def test_os_source_repr_cannot_echo_entropy(self) -> None:
        self.assertEqual(repr(OsCsprngEntropySource()), "OsCsprngEntropySource(source_id='os-csprng')")

    def test_deterministic_source_replays_exactly_and_cycles(self) -> None:
        source = DeterministicTestEntropySource(bytes([1, 2, 3]))
        self.assertEqual(source.read(5), bytes([1, 2, 3, 1, 2]))
        self.assertEqual(source.consumed, 5)

    def test_deterministic_source_can_refuse_to_cycle(self) -> None:
        source = DeterministicTestEntropySource(bytes([1, 2]), cycle=False)
        source.read(2)
        with self.assertRaises(RngDenied) as caught:
            source.read(1)
        self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_EXHAUSTED")
        self.assertIs(caught.exception.action, FailureAction.VOID_ROUND)

    def test_deterministic_source_rejects_an_empty_stream(self) -> None:
        with self.assertRaises(ValueError):
            DeterministicTestEntropySource(b"")

    def test_deterministic_source_repr_leaks_neither_stream_nor_rejection_count(self) -> None:
        source = DeterministicTestEntropySource(bytes([170, 187, 204]))
        source.read(7)
        rendered = repr(source)
        self.assertIn("length=3", rendered)
        for value in (170, 187, 204):
            self.assertNotIn(str(value), rendered)
        # ``consumed`` minus the draws issued is the rejection count, which AC-004 forbids
        # on any operator-visible surface.
        self.assertNotIn("consumed", rendered)
        self.assertNotIn("7", rendered)
        self.assertEqual(source.consumed, 7)

    def test_a_foreign_source_cannot_smuggle_a_message_through_our_exception_type(self) -> None:
        class Smuggler:
            source_id = "smuggler"
            is_deterministic = True

            def read(self, size: int) -> bytes:
                raise RngDenied(
                    "ENTROPY_SOURCE_INVALID", FailureAction.VOID_ROUND, "read failed at seed=0xDEADBEEF offset=3"
                )

        with self.assertRaises(RngDenied) as caught:
            read_entropy(Smuggler(), 1)
        message = str(caught.exception)
        self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_INVALID")
        self.assertIs(caught.exception.action, FailureAction.VOID_ROUND)
        self.assertNotIn("DEADBEEF", message)
        self.assertNotIn("seed=", message)

    def test_our_own_adapters_keep_their_denial_messages(self) -> None:
        source = DeterministicTestEntropySource(bytes([1]), cycle=False)
        read_entropy(source, 1)
        with self.assertRaises(RngDenied) as caught:
            read_entropy(source, 1)
        self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_EXHAUSTED")
        self.assertIn("exhausted", str(caught.exception))

    def test_read_entropy_reports_only_the_exception_type_of_a_hostile_source(self) -> None:
        class Hostile:
            source_id = "hostile"
            is_deterministic = True

            def read(self, size: int) -> bytes:
                raise ValueError("seed=DEADBEEF")

        with self.assertRaises(RngDenied) as caught:
            read_entropy(Hostile(), 1)
        message = str(caught.exception)
        self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_FAILED")
        self.assertIn("ValueError", message)
        self.assertNotIn("DEADBEEF", message)
        self.assertIsNone(caught.exception.__cause__)

    def test_read_entropy_rejects_short_and_non_binary_reads(self) -> None:
        class Short:
            source_id = "short"
            is_deterministic = True

            def read(self, size: int) -> bytes:
                return b""

        class NotBinary:
            source_id = "text"
            is_deterministic = True

            def read(self, size: int):
                return "A" * size

        for source in (Short(), NotBinary()):
            with self.assertRaises(RngDenied) as caught:
                read_entropy(source, 1)
            self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_INVALID")


class RejectionSamplingTests(unittest.TestCase):
    """AC-003: rejection never degrades into a biased fallback."""

    def test_draw_pocket_skips_rejected_bytes(self) -> None:
        source = DeterministicTestEntropySource(bytes([255, 254, 222, 40]), cycle=False)
        self.assertEqual(draw_pocket(source), 3)
        self.assertEqual(source.consumed, 4)

    def test_exhausting_the_rejection_budget_raises_instead_of_falling_back(self) -> None:
        source = DeterministicTestEntropySource(bytes([255]))
        with self.assertRaises(RngDenied) as caught:
            draw_pocket(source)
        self.assertEqual(caught.exception.code, "ENTROPY_REJECTION_EXHAUSTED")
        self.assertIs(caught.exception.action, FailureAction.VOID_ROUND)
        self.assertEqual(source.consumed, MAX_REJECTION_ATTEMPTS)

    def test_a_starved_round_is_voided_by_the_engine(self) -> None:
        # draw_pocket has no round concept, so the round-level property needs the engine.
        engine = _engine(bytes([255]))
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        self.assertEqual(caught.exception.code, "ENTROPY_REJECTION_EXHAUSTED")
        self.assertTrue(engine.is_round_voided("RR-TEST-0001"))
        with self.assertRaises(RngDenied) as retried:
            engine.draw(DrawRequest(request_id="RNG-TEST-0002", round_id="RR-TEST-0001"))
        self.assertEqual(retried.exception.code, "ROUND_VOIDED")

    def test_a_failing_entropy_source_voids_the_round(self) -> None:
        class Broken:
            source_id = "broken"
            is_deterministic = True

            def read(self, size: int) -> bytes:
                raise OSError("entropy device unavailable")

        engine = _engine(entropy_source=Broken())
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_FAILED")
        self.assertTrue(engine.is_round_voided("RR-TEST-0001"))

    def test_the_rejection_boundary_byte_is_rejected_and_its_predecessor_accepted(self) -> None:
        self.assertIsNone(map_entropy_byte(ACCEPTED_BYTE_LIMIT))
        self.assertEqual(map_entropy_byte(ACCEPTED_BYTE_LIMIT - 1), (ACCEPTED_BYTE_LIMIT - 1) % POCKET_COUNT)


class EngineConstructionTests(unittest.TestCase):
    """AC-002: the engine refuses to start in an unsafe configuration."""

    def test_a_deterministic_adapter_may_never_back_a_production_engine(self) -> None:
        with self.assertRaises(RngDenied) as caught:
            RouletteDrawEngine(
                entropy_source=DeterministicTestEntropySource(b"\x01"),
                environment=RngEnvironment.PRODUCTION,
            )
        self.assertEqual(caught.exception.code, "DETERMINISTIC_SOURCE_IN_PRODUCTION")
        self.assertIs(caught.exception.action, FailureAction.BLOCK_AND_ESCALATE)

    def test_the_default_production_engine_uses_the_os_csprng(self) -> None:
        engine = RouletteDrawEngine(environment=RngEnvironment.PRODUCTION, audit_sink=AuditChain("PROD"))
        self.assertIs(engine.environment, RngEnvironment.PRODUCTION)
        self.assertIn("os-csprng", engine.seed_reference)
        record = engine.draw(_request(9001))
        self.assertTrue(0 <= record.pocket < POCKET_COUNT)
        self.assertFalse(record.entropy_source_deterministic)
        self.assertEqual(record.environment, "PRODUCTION")

    def test_an_unknown_environment_is_rejected_rather_than_coerced(self) -> None:
        for environment in ("prod", "STAGING", None, 1):
            with self.assertRaises(RngDenied) as caught:
                RouletteDrawEngine(entropy_source=OsCsprngEntropySource(), environment=environment)  # type: ignore[arg-type]
            self.assertEqual(caught.exception.code, "ENVIRONMENT_INVALID")

    def test_a_malformed_entropy_source_is_rejected(self) -> None:
        class MissingAttributes:
            pass

        class BadSourceId:
            source_id = "Not A Valid Id"
            is_deterministic = False

            def read(self, size: int) -> bytes:
                return b"\x01" * size

        class NonBooleanFlag:
            source_id = "flagged"
            is_deterministic = "no"

            def read(self, size: int) -> bytes:
                return b"\x01" * size

        for source in (MissingAttributes(), BadSourceId(), NonBooleanFlag()):
            with self.assertRaises(RngDenied) as caught:
                RouletteDrawEngine(entropy_source=source, environment=RngEnvironment.NON_PRODUCTION)
            self.assertEqual(caught.exception.code, "ENTROPY_SOURCE_INVALID")

    def test_an_audit_sink_without_append_is_rejected(self) -> None:
        with self.assertRaises(RngDenied) as caught:
            RouletteDrawEngine(
                entropy_source=DeterministicTestEntropySource(b"\x11"),
                environment=RngEnvironment.NON_PRODUCTION,
                audit_sink=object(),  # type: ignore[arg-type]
            )
        self.assertEqual(caught.exception.code, "AUDIT_SINK_INVALID")

    def test_an_unusable_clock_voids_the_round(self) -> None:
        for clock, code in ((lambda: "yesterday", "CLOCK_INVALID"), (lambda: 1 / 0, "CLOCK_FAILED")):
            engine = _engine(clock=clock)
            with self.assertRaises(RngDenied) as caught:
                engine.draw(_request(1))
            self.assertEqual(caught.exception.code, code)
            self.assertIs(caught.exception.action, FailureAction.VOID_ROUND)
            # The pocket was already sampled and discarded before the clock failed. If the
            # round stayed drawable, a caller able to induce clock faults could re-roll it.
            self.assertTrue(engine.is_round_voided("RR-TEST-0001"))
            with self.assertRaises(RngDenied) as retried:
                engine.draw(DrawRequest(request_id="RNG-TEST-0002", round_id="RR-TEST-0001"))
            self.assertEqual(retried.exception.code, "ROUND_VOIDED")


class DrawRequestValidationTests(unittest.TestCase):
    """AC-005: a malformed or mismatched request is blocked and escalated."""

    def test_malformed_identifiers_are_blocked(self) -> None:
        cases = [
            (DrawRequest(request_id="short", round_id="RR-A"), "REQUEST_ID_INVALID"),
            (DrawRequest(request_id="RNG-TEST-0001", round_id="lowercase-round"), "ROUND_ID_INVALID"),
            (DrawRequest(request_id="RNG-TEST-0001", round_id="RR-A", draw_index=-1), "DRAW_INDEX_INVALID"),
            (DrawRequest(request_id="RNG-TEST-0001", round_id="RR-A", draw_index=10_000), "DRAW_INDEX_INVALID"),
            (DrawRequest(request_id="RNG-TEST-0001", round_id="RR-A", draw_index=True), "DRAW_INDEX_INVALID"),
        ]
        for request, code in cases:
            with self.assertRaises(RngDenied) as caught:
                request.validate()
            self.assertEqual(caught.exception.code, code)
            self.assertIs(caught.exception.action, FailureAction.BLOCK_AND_ESCALATE)

    def test_the_engine_requires_a_draw_request_instance(self) -> None:
        with self.assertRaises(RngDenied) as caught:
            _engine().draw({"request_id": "RNG-TEST-0001", "round_id": "RR-TEST-0001"})  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "REQUEST_INVALID")

    def test_a_foreign_ruleset_or_algorithm_version_is_blocked(self) -> None:
        engine = _engine()
        cases = [
            (DrawRequest(request_id="RNG-TEST-0002", round_id="RR-TEST-0002", ruleset_id="ROULETTE-US-DOUBLE-ZERO"), "RULESET_MISMATCH"),
            (DrawRequest(request_id="RNG-TEST-0003", round_id="RR-TEST-0003", algorithm_version="9.9.9"), "ALGORITHM_VERSION_MISMATCH"),
            (DrawRequest(request_id="RNG-TEST-0004", round_id="RR-TEST-0004", algorithm_id="LCG-FAST"), "ALGORITHM_VERSION_MISMATCH"),
        ]
        for request, code in cases:
            with self.assertRaises(RngDenied) as caught:
                engine.draw(request)
            self.assertEqual(caught.exception.code, code)
            self.assertIs(caught.exception.action, FailureAction.BLOCK_AND_ESCALATE)


class AuthoritativeDrawTests(unittest.TestCase):
    """AC-005: one authoritative draw per round, replayed exactly on retry."""

    def test_a_duplicate_request_returns_the_original_result(self) -> None:
        engine = _engine(bytes([40, 41, 42]))
        request = _request(1)
        first = engine.draw(request)
        for _ in range(3):
            self.assertEqual(engine.draw(request).to_dict(), first.to_dict())

    def test_a_reused_request_id_with_different_parameters_is_blocked(self) -> None:
        engine = _engine()
        engine.draw(_request(1))
        with self.assertRaises(RngDenied) as caught:
            engine.draw(DrawRequest(request_id="RNG-TEST-0001", round_id="RR-TEST-9999"))
        self.assertEqual(caught.exception.code, "DUPLICATE_REQUEST_CONFLICT")
        self.assertIs(caught.exception.action, FailureAction.BLOCK_AND_ESCALATE)

    def test_a_round_accepts_only_one_authoritative_draw(self) -> None:
        engine = _engine()
        engine.draw(_request(1))
        with self.assertRaises(RngDenied) as caught:
            engine.draw(DrawRequest(request_id="RNG-TEST-0002", round_id="RR-TEST-0001"))
        self.assertEqual(caught.exception.code, "ROUND_ALREADY_DRAWN")

    def test_a_voided_round_cannot_be_drawn(self) -> None:
        engine = _engine()
        engine.void_round("RR-TEST-0001")
        self.assertTrue(engine.is_round_voided("RR-TEST-0001"))
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        self.assertEqual(caught.exception.code, "ROUND_VOIDED")

    def test_replaying_the_same_entropy_stream_reproduces_the_same_pockets(self) -> None:
        # `replay_test_exact_match: true`. A single-value comparison would hold for any
        # deterministic mapping, so the replay covers a long stream and pins the expected
        # pockets, which also fixes the rejection positions (250 and 231 are rejected).
        # 250 and 231 are rejected; 88 -> 14, 221 -> 36 and 100 -> 26 under `% 37`.
        stream = bytes([250, 17, 3, 231, 88, 0, 221, 36, 100])
        expected = [17, 3, 14, 0, 36, 36, 26]
        for _ in range(2):
            source = DeterministicTestEntropySource(stream, cycle=False)
            self.assertEqual([draw_pocket(source) for _ in expected], expected)
            self.assertEqual(source.consumed, len(stream))

    def test_the_proof_hash_is_recomputable_from_the_record_alone(self) -> None:
        record = _engine().draw(_request(1))
        self.assertEqual(
            record.proof_hash,
            compute_proof_hash(
                algorithm_id=record.algorithm_id,
                algorithm_version=record.algorithm_version,
                draw_index=record.draw_index,
                pocket=record.pocket,
                request_id=record.request_id,
                round_id=record.round_id,
                ruleset_id=record.ruleset_id,
                seed_reference=record.seed_reference,
            ),
        )

    def test_a_different_pocket_produces_a_different_proof_hash(self) -> None:
        record = _engine().draw(_request(1))
        tampered = compute_proof_hash(
            algorithm_id=record.algorithm_id,
            algorithm_version=record.algorithm_version,
            draw_index=record.draw_index,
            pocket=(record.pocket + 1) % POCKET_COUNT,
            request_id=record.request_id,
            round_id=record.round_id,
            ruleset_id=record.ruleset_id,
            seed_reference=record.seed_reference,
        )
        self.assertNotEqual(record.proof_hash, tampered)


class ProofVerificationTests(unittest.TestCase):
    """AC-006: `missing_or_invalid_proof: VOID_ROUND` needs a check, not just a computation."""

    def test_an_authentic_record_verifies(self) -> None:
        record = _engine().draw(_request(1))
        verify_draw_record(record)
        verify_draw_record(record.to_dict())

    def test_every_bound_field_is_actually_bound(self) -> None:
        record = _engine().draw(_request(1)).to_dict()
        mutations = {
            "pocket": (record["pocket"] + 1) % POCKET_COUNT,
            "round_id": "RR-TEST-9999",
            "request_id": "RNG-TEST-9999",
            "draw_index": record["draw_index"] + 1,
            "seed_reference": "entropy-ref://other-source/CSPRNG-REJECTION-UNIFORM-37",
            "algorithm_version": "9.9.9",
            "ruleset_id": "ROULETTE-US-DOUBLE-ZERO",
            "algorithm_id": "LCG-FAST",
        }
        for field, value in mutations.items():
            with self.assertRaises(RngDenied) as caught:
                verify_draw_record(dict(record, **{field: value}))
            self.assertEqual(caught.exception.code, "PROOF_INVALID", f"{field} is not bound by the proof")
            self.assertIs(caught.exception.action, FailureAction.VOID_ROUND)

    def test_a_record_missing_proof_material_is_refused(self) -> None:
        record = _engine().draw(_request(1)).to_dict()
        for field in ("proof_hash", "pocket", "seed_reference"):
            with self.assertRaises(RngDenied) as caught:
                verify_draw_record({key: value for key, value in record.items() if key != field})
            self.assertEqual(caught.exception.code, "PROOF_MISSING")
        with self.assertRaises(RngDenied) as caught:
            verify_draw_record("not a record")
        self.assertEqual(caught.exception.code, "PROOF_MISSING")


class VoidRoundTests(unittest.TestCase):
    """AC-006: voiding is an authoritative state change, so it is validated and recorded."""

    def test_a_malformed_round_id_cannot_be_voided(self) -> None:
        engine = _engine()
        for round_id in ("lowercase", "", "RR_TEST", 7, None):
            with self.assertRaises(RngDenied) as caught:
                engine.void_round(round_id)  # type: ignore[arg-type]
            self.assertEqual(caught.exception.code, "ROUND_ID_INVALID")

    def test_a_malformed_reason_is_refused(self) -> None:
        engine = _engine()
        for reason in ("lower case", "", "x", 7):
            with self.assertRaises(RngDenied) as caught:
                engine.void_round("RR-TEST-0001", reason=reason)  # type: ignore[arg-type]
            self.assertEqual(caught.exception.code, "VOID_REASON_INVALID")
        self.assertFalse(engine.is_round_voided("RR-TEST-0001"))

    def test_voiding_is_recorded_with_its_reason(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(audit_sink=chain)
        engine.void_round("RR-TEST-0001", reason="SUSPECTED_TAMPERING")
        self.assertTrue(engine.is_round_voided("RR-TEST-0001"))
        self.assertEqual(len(chain.events), 1)
        event = chain.events[0]
        self.assertEqual(event["action"], "ROULETTE_RNG_ROUND_VOIDED")
        self.assertEqual(event["decision"], "BLOCK")
        self.assertEqual(event["event_type"], "SECURITY")
        self.assertIn("rng-void-reason://SUSPECTED_TAMPERING", event["resource_refs"])
        validate_instance(event, load_json("audit/audit-event.schema.json"))


class DenialAuditTests(unittest.TestCase):
    """AC-006: a refused draw is the security-relevant half and must not be invisible."""

    def test_a_denied_draw_is_recorded_as_a_security_denial(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(audit_sink=chain)
        engine.draw(_request(1))
        with self.assertRaises(RngDenied):
            engine.draw(DrawRequest(request_id="RNG-TEST-0002", round_id="RR-TEST-0001"))

        denials = [event for event in chain.events if event["decision"] == "DENY"]
        self.assertEqual(len(denials), 1)
        event = denials[0]
        self.assertEqual(event["action"], "ROULETTE_RNG_DRAW_DENIED")
        self.assertEqual(event["event_type"], "SECURITY")
        self.assertFalse(event["contains_secret"])
        self.assertIn("rng-denial-code://ROUND_ALREADY_DRAWN", event["resource_refs"])
        self.assertEqual(verify_audit_chain(chain.events), [])
        validate_instance(event, load_json("audit/audit-event.schema.json"))

    def test_a_discarded_sample_leaves_an_audit_trace(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(bytes([255]), audit_sink=chain)
        with self.assertRaises(RngDenied):
            engine.draw(_request(1))
        codes = [
            ref
            for event in chain.events
            for ref in event["resource_refs"]
            if ref.startswith("rng-denial-code://")
        ]
        self.assertIn("rng-denial-code://ENTROPY_REJECTION_EXHAUSTED", codes)

    def test_a_denial_audit_outage_does_not_replace_the_original_failure(self) -> None:
        class FailingSink:
            def append(self, body):
                raise RuntimeError("audit store offline")

        engine = _engine(bytes([255]), audit_sink=FailingSink())
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        # The entropy failure is the real one; the audit outage must not mask it.
        self.assertEqual(caught.exception.code, "ENTROPY_REJECTION_EXHAUSTED")

    def test_denial_audit_records_carry_no_entropy(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(bytes([255]), audit_sink=chain)
        with self.assertRaises(RngDenied):
            engine.draw(_request(1))
        serialized = json.dumps(chain.events, ensure_ascii=False, sort_keys=True)
        for name in PROHIBITED_RECORD_FIELDS:
            self.assertNotIn(f'"{name}"', serialized)
        self.assertNotIn("255", serialized)


class ConcurrencyTests(unittest.TestCase):
    """AC-005: one authoritative draw per round must survive concurrent callers."""

    def test_concurrent_draws_on_one_round_yield_a_single_authoritative_result(self) -> None:
        engine = _engine(bytes(range(1, 200)))
        results: list[object] = []
        barrier = threading.Barrier(8)

        def attempt(index: int) -> None:
            barrier.wait()
            try:
                results.append(engine.draw(DrawRequest(request_id=f"RNG-RACE-{index:04d}", round_id="RR-RACE-0001")))
            except RngDenied as denied:
                results.append(denied.code)

        threads = [threading.Thread(target=attempt, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        records = [item for item in results if not isinstance(item, str)]
        self.assertEqual(len(results), 8)
        self.assertEqual(len(records), 1, "a round must yield exactly one authoritative draw")
        self.assertTrue(all(item == "ROUND_ALREADY_DRAWN" for item in results if isinstance(item, str)))


class AuditTests(unittest.TestCase):
    """AC-006: no result exists until its audit event does."""

    def test_the_audit_event_precedes_the_record_and_carries_the_seed_reference(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(audit_sink=chain)
        record = engine.draw(_request(1))
        self.assertEqual(len(chain.events), 1)
        event = chain.events[0]
        self.assertEqual(event["action"], "ROULETTE_RNG_DRAW")
        self.assertEqual(event["decision"], "COMPLETE")
        self.assertEqual(event["task_id"], AUDIT_TASK_ID)
        self.assertFalse(event["contains_secret"])
        self.assertIn(record.seed_reference, " ".join(event["resource_refs"]))
        self.assertIn(record.audit_event_ref.removeprefix("audit://"), event["event_id"])

    def test_an_audit_write_failure_discards_the_result_and_voids_the_round(self) -> None:
        class FailingSink:
            def append(self, body):
                raise RuntimeError("audit store offline")

        engine = _engine(audit_sink=FailingSink())
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        self.assertEqual(caught.exception.code, "AUDIT_WRITE_FAILURE")
        self.assertIs(caught.exception.action, FailureAction.BLOCK_AND_VOID)
        self.assertTrue(engine.is_round_voided("RR-TEST-0001"))
        with self.assertRaises(RngDenied) as retried:
            engine.draw(_request(1))
        self.assertEqual(retried.exception.code, "ROUND_VOIDED")

    def test_an_unresolvable_audit_reference_voids_the_round(self) -> None:
        class VagueSink:
            def append(self, body):
                return "ok"

        engine = _engine(audit_sink=VagueSink())
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        self.assertEqual(caught.exception.code, "AUDIT_WRITE_FAILURE")
        self.assertTrue(engine.is_round_voided("RR-TEST-0001"))

    def test_the_audit_chain_links_and_detects_tampering(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(bytes([10, 20, 30]), audit_sink=chain)
        for index in (1, 2, 3):
            engine.draw(_request(index))
        events = chain.events
        self.assertEqual(len(events), 3)
        self.assertEqual(verify_audit_chain(events), [])
        self.assertIsNone(events[0]["previous_event_hash"])
        self.assertEqual(events[1]["previous_event_hash"], events[0]["event_hash"])

        edited = copy.deepcopy(events)
        edited[1]["action"] = "ROULETTE_RNG_DRAW_EDITED"
        self.assertTrue(verify_audit_chain(edited))

        reordered = [events[1], events[0], events[2]]
        self.assertTrue(verify_audit_chain(reordered))

    def test_a_chain_event_claiming_a_secret_is_reported(self) -> None:
        chain = AuditChain("TEST")
        _engine(audit_sink=chain).draw(_request(1))
        event = chain.events[0]
        event["contains_secret"] = True
        event["event_hash"] = compute_event_hash(event)
        self.assertTrue(any("contains_secret" in problem for problem in verify_audit_chain([event])))

    def test_the_audit_namespace_is_validated(self) -> None:
        for namespace in ("lower", "TOO-LONG-NAMESPACE", "", 7):
            with self.assertRaises(ValueError):
                AuditChain(namespace)  # type: ignore[arg-type]

    def test_every_draw_audit_event_satisfies_the_repository_audit_schema(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(bytes([10, 20, 30]), audit_sink=chain)
        for index in (1, 2):
            engine.draw(_request(index))
        schema = load_json("audit/audit-event.schema.json")
        for event in chain.events:
            validate_instance(event, schema)


class SecretHygieneTests(unittest.TestCase):
    """AC-004: entropy material never reaches a record, an event, or a message."""

    def test_the_record_carries_no_prohibited_field(self) -> None:
        record = _engine().draw(_request(1))
        payload = record.to_dict()
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        for name in PROHIBITED_RECORD_FIELDS:
            self.assertNotIn(name, payload)
            self.assertNotIn(f'"{name}"', serialized)

    def test_the_audit_event_carries_no_prohibited_field(self) -> None:
        chain = AuditChain("TEST")
        engine = _engine(audit_sink=chain)
        engine.draw(_request(2))
        serialized = json.dumps(chain.events, ensure_ascii=False, sort_keys=True)
        for name in PROHIBITED_RECORD_FIELDS:
            self.assertNotIn(f'"{name}"', serialized)

    def test_the_rejection_count_is_not_observable_from_the_result(self) -> None:
        # Both engines draw pocket 3, one after 2 rejections and one immediately. Their
        # records must be identical apart from identifiers, or the record would leak how
        # much of the entropy stream fell in the rejected band.
        rejecting = _engine(bytes([255, 254, 40]))
        direct = _engine(bytes([40]))
        first = rejecting.draw(_request(1)).to_dict()
        second = direct.draw(_request(1)).to_dict()
        self.assertEqual(first["pocket"], second["pocket"])
        self.assertEqual(first, second)

    def test_the_seed_reference_names_an_authority_and_not_a_value(self) -> None:
        engine = _engine()
        self.assertEqual(
            engine.seed_reference, f"entropy-ref://deterministic-test/{ALGORITHM_ID}"
        )
        production = RouletteDrawEngine(environment=RngEnvironment.PRODUCTION, audit_sink=AuditChain("P"))
        self.assertEqual(production.seed_reference, f"entropy-ref://os-csprng/{ALGORITHM_ID}")

    def test_denial_messages_never_echo_entropy_bytes(self) -> None:
        class Leaky:
            source_id = "leaky"
            is_deterministic = True

            def read(self, size: int) -> bytes:
                raise RuntimeError("failed while emitting bytes 0xAB 0xCD")

        engine = _engine(entropy_source=Leaky())
        with self.assertRaises(RngDenied) as caught:
            engine.draw(_request(1))
        message = str(caught.exception)
        self.assertIn("RuntimeError", message)
        self.assertNotIn("0xAB", message)
        self.assertNotIn("0xCD", message)


class DrawRecordSchemaTests(unittest.TestCase):
    """AC-008: the record schema rejects entropy leakage structurally."""

    SCHEMA_PATH = "games/roulette/rng-draw-record.schema.json"

    def setUp(self) -> None:
        self.schema = load_json(self.SCHEMA_PATH)

    def test_the_schema_is_structurally_valid_and_closed(self) -> None:
        validate_schema_structure(self.schema, self.SCHEMA_PATH)
        self.assertIs(self.schema["additionalProperties"], False)

    def test_the_schema_declares_no_prohibited_field(self) -> None:
        for name in PROHIBITED_RECORD_FIELDS:
            self.assertNotIn(name, self.schema["properties"])
            self.assertNotIn(name, self.schema["required"])

    def test_the_repository_fixture_is_a_valid_record(self) -> None:
        fixture = load_json("games/roulette/fixtures/rng-draw-record.example.json")
        validate_instance(fixture, self.schema)
        self.assertEqual(fixture["schema_version"], RRNG_SCHEMA_VERSION)
        self.assertEqual(fixture["ruleset_id"], RULESET_ID)
        self.assertEqual(fixture["algorithm_id"], ALGORITHM_ID)
        self.assertEqual(fixture["algorithm_version"], ALGORITHM_VERSION)

    def test_a_live_record_validates_against_the_schema(self) -> None:
        for stream in (bytes([0]), bytes([36]), bytes([221]), bytes([255, 255, 100])):
            record = _engine(stream).draw(_request(1))
            validate_instance(record.to_dict(), self.schema)

    def test_the_schema_rejects_a_record_carrying_a_seed(self) -> None:
        record = _engine().draw(_request(1)).to_dict()
        for name in ("seed", "entropy_bytes", "rejection_attempts", "state"):
            leaking = dict(record)
            leaking[name] = "leaked"
            with self.assertRaises(BaselineValidationError):
                validate_instance(leaking, self.schema)

    def test_the_schema_rejects_an_out_of_range_pocket(self) -> None:
        record = _engine().draw(_request(1)).to_dict()
        for pocket in (-1, 37, 100):
            invalid = dict(record, pocket=pocket)
            with self.assertRaises(BaselineValidationError):
                validate_instance(invalid, self.schema)

    def test_the_record_projects_into_a_round_document(self) -> None:
        record = _engine().draw(_request(1))
        round_schema = load_json("games/roulette/round.schema.json")
        rng_record_schema = round_schema["properties"]["rng_record"]["oneOf"][1]
        projection = record.to_round_rng_record()
        validate_instance(projection, rng_record_schema)
        self.assertEqual(projection["proof_hash"], record.proof_hash)
        self.assertEqual(projection["version"], record.algorithm_version)
        self.assertEqual(projection["seed_reference"], record.seed_reference)
        for name in PROHIBITED_RECORD_FIELDS:
            self.assertNotIn(name, projection)


class ChiSquareTests(unittest.TestCase):
    """AC-007: the tail probability is trustworthy before any verdict depends on it."""

    def test_reference_values_match_published_tables(self) -> None:
        cases = [
            (3.841, 1, 0.05), (6.635, 1, 0.01), (10.828, 1, 0.001),
            (50.998, 36, 0.05), (58.619, 36, 0.01), (67.985, 36, 0.001),
            (1368.0, 1368, 0.4936),
        ]
        for statistic, dof, expected in cases:
            self.assertAlmostEqual(chi_square_p_value(statistic, dof), expected, delta=0.002)

    def test_the_tail_is_monotonic_and_bounded(self) -> None:
        previous = 1.0
        for statistic in range(0, 200, 5):
            value = chi_square_p_value(float(statistic), 36)
            self.assertTrue(0.0 <= value <= 1.0)
            self.assertLessEqual(value, previous + 1e-12)
            previous = value

    def test_invalid_arguments_are_rejected(self) -> None:
        for statistic, dof in ((-1.0, 36), (float("nan"), 36), (1.0, 0), (1.0, -3), (1.0, True)):
            with self.assertRaises(ValueError):
                chi_square_p_value(statistic, dof)  # type: ignore[arg-type]


class StatisticalIndependenceTests(unittest.TestCase):
    """AC-007: the statistics module knows nothing about the generator."""

    def test_the_module_does_not_import_the_rng_implementation(self) -> None:
        imported = _imported_modules("studio_core/rng_stats.py")
        for name in imported:
            self.assertNotIn("rng", name.rsplit(".", 1)[-1].replace("rng_stats", ""))
        self.assertNotIn("studio_core.rng", imported)
        self.assertNotIn(".rng", imported)
        # The verdict must depend on nothing but the sequence it is handed.
        self.assertEqual(imported, {"__future__", "math", "dataclasses", "typing"})

    def test_counting_helpers_cover_every_pocket_and_pair(self) -> None:
        sequence = [0, 36, 0, 36]
        counts = pocket_counts(sequence)
        self.assertEqual(len(counts), POCKET_COUNT)
        self.assertEqual(counts[0], 2)
        self.assertEqual(counts[36], 2)
        self.assertEqual(sum(counts), 4)

        pairs = pair_counts(sequence)
        self.assertEqual(len(pairs), POCKET_COUNT * POCKET_COUNT)
        self.assertEqual(pairs[0 * POCKET_COUNT + 36], 2)
        self.assertEqual(sum(pairs), 2)

    def test_an_odd_trailing_draw_is_ignored_by_the_pair_counter(self) -> None:
        self.assertEqual(sum(pair_counts([1, 2, 3])), 1)

    def test_non_pocket_values_are_rejected(self) -> None:
        for sequence in ([0, 37], [0, -1], [0, True], [0, "3"], [1.0]):
            with self.assertRaises(ValueError):
                pocket_counts(sequence)  # type: ignore[arg-type]

    def test_a_uniform_stream_passes_uniformity(self) -> None:
        sequence = [index % POCKET_COUNT for index in range(POCKET_COUNT * 300)]
        result = uniformity_test(sequence)
        self.assertTrue(result.passed)
        self.assertEqual(result.degrees_of_freedom, POCKET_COUNT - 1)
        self.assertAlmostEqual(result.statistic, 0.0, places=9)

    def test_a_favoured_pocket_is_detected(self) -> None:
        generator = random.Random(7)
        sequence = [
            0 if generator.random() < 0.05 else generator.randrange(POCKET_COUNT)
            for _ in range(20000)
        ]
        result = uniformity_test(sequence)
        self.assertFalse(result.passed)
        self.assertLess(result.p_value, DEFAULT_ALPHA)
        self.assertIn("deviate", result.detail)

    def test_a_predictable_successor_is_detected(self) -> None:
        # Uniform overall, but every second draw is a function of the one before it.
        generator = random.Random(11)
        sequence: list[int] = []
        for _ in range(20000):
            value = generator.randrange(POCKET_COUNT)
            sequence.append(value)
            sequence.append((value + 1) % POCKET_COUNT)
        uniformity = uniformity_test(sequence)
        self.assertTrue(uniformity.passed, "the biased stream must stay uniform to isolate the defect")
        serial = serial_independence_test(sequence)
        self.assertFalse(serial.passed)
        self.assertLess(serial.p_value, DEFAULT_ALPHA)

    def test_an_independent_stream_passes_serial_independence(self) -> None:
        generator = random.Random(13)
        sequence = [generator.randrange(POCKET_COUNT) for _ in range(40000)]
        self.assertTrue(serial_independence_test(sequence).passed)

    def test_sparse_samples_are_refused_rather_than_guessed(self) -> None:
        with self.assertRaises(ValueError):
            uniformity_test([0] * 10)
        with self.assertRaises(ValueError):
            serial_independence_test([0] * 100)

    def test_the_declared_acceptance_rate_is_checked(self) -> None:
        good = rejection_rate_test(2220, 340, expected_acceptance_rate=EXPECTED_ACCEPTANCE_RATE)
        self.assertTrue(good.passed)
        self.assertEqual(good.degrees_of_freedom, 1)

        drifted = rejection_rate_test(2560, 0, expected_acceptance_rate=EXPECTED_ACCEPTANCE_RATE)
        self.assertFalse(drifted.passed)

    def test_rejection_rate_arguments_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            rejection_rate_test(-1, 10, expected_acceptance_rate=0.5)
        with self.assertRaises(ValueError):
            rejection_rate_test(10, 10, expected_acceptance_rate=1.0)
        with self.assertRaises(ValueError):
            rejection_rate_test(1, 1, expected_acceptance_rate=0.5)

    def test_certify_stream_reports_skipped_tests_instead_of_passing_them(self) -> None:
        report = certify_stream([index % POCKET_COUNT for index in range(POCKET_COUNT * 10)])
        skipped = {item["test_id"] for item in report["skipped"]}
        self.assertIn("SERIAL_INDEPENDENCE", skipped)
        self.assertNotIn("SERIAL_INDEPENDENCE", {item["test_id"] for item in report["results"]})

    def test_certify_stream_fails_when_any_test_fails(self) -> None:
        generator = random.Random(17)
        sequence = [0 if generator.random() < 0.2 else generator.randrange(POCKET_COUNT) for _ in range(20000)]
        report = certify_stream(sequence)
        self.assertFalse(report["all_passed"])
        self.assertIn("FAIL", summarize(report))


class LiveCsprngCertificationTests(unittest.TestCase):
    """AC-002 and AC-007: the live OS CSPRNG is certified through the production draw path."""

    SAMPLE_SIZE = 20000

    def _sample(self) -> tuple[list[int], int]:
        class CountingOsSource(OsCsprngEntropySource):
            def __init__(self) -> None:
                self.bytes_read = 0

            def read(self, size: int) -> bytes:
                self.bytes_read += size
                return super().read(size)

        source = CountingOsSource()
        sequence = [draw_pocket(source) for _ in range(self.SAMPLE_SIZE)]
        return sequence, source.bytes_read

    def test_the_live_csprng_survives_statistical_certification(self) -> None:
        # A single alpha=0.001 sample would fail roughly once in a thousand runs by chance.
        # Requiring a failure to repeat on a fresh sample makes a spurious red build a
        # one-in-a-million event without weakening the test against a real defect, which
        # would fail on every attempt.
        report = None
        for _ in range(2):
            sequence, bytes_read = self._sample()
            report = certify_stream(
                sequence,
                accepted=len(sequence),
                rejected=bytes_read - len(sequence),
                expected_acceptance_rate=EXPECTED_ACCEPTANCE_RATE,
            )
            if report["all_passed"]:
                break
        assert report is not None
        self.assertEqual(report["skipped"], [])
        self.assertEqual({item["test_id"] for item in report["results"]},
                         {"POCKET_UNIFORMITY", "SERIAL_INDEPENDENCE", "REJECTION_RATE"})
        self.assertTrue(report["all_passed"], summarize(report))

    def test_every_live_draw_lands_on_the_wheel(self) -> None:
        sequence, bytes_read = self._sample()
        self.assertTrue(all(0 <= value < POCKET_COUNT for value in sequence))
        self.assertEqual(len(set(sequence)), POCKET_COUNT)
        self.assertGreaterEqual(bytes_read, len(sequence))


class ValidatorIntegrationTests(unittest.TestCase):
    """AC-009: the baseline validator owns the R2 RNG contract."""

    def test_the_r2_rng_validation_passes(self) -> None:
        result = validate_r2_rng()
        self.assertTrue(result["statistics"]["all_passed"])
        self.assertEqual(result["statistics"]["skipped"], [])

    def _isolated_root(self) -> pathlib.Path:
        """Return a throwaway copy of every file the validator reads.

        The negative cases must not write to tracked files. One of them is the R1 checklist,
        where a mutation left behind by an aborted run would forge a human QA approval in the
        working tree -- the one place in this repository where a stale edit is a governance
        hazard rather than an inconvenience.
        """

        directory = pathlib.Path(tempfile.mkdtemp(prefix="r2-rng-validator-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        for relative in R2_RNG_INPUT_FILES:
            destination = directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return directory

    def test_the_isolated_copy_still_passes_before_it_is_tampered_with(self) -> None:
        # Without this, every negative case below could be passing for the wrong reason.
        validate_r2_rng(root=self._isolated_root())

    def test_the_validator_rejects_a_fixture_carrying_a_seed(self) -> None:
        root = self._isolated_root()
        path = root / "games/roulette/fixtures/rng-draw-record.example.json"
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["seed"] = "0xDEADBEEF"
        path.write_text(json.dumps(tampered, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(BaselineValidationError, r"unexpected property 'seed'"):
            validate_r2_rng(root=root)
        self.assertEqual(
            (ROOT / "games/roulette/fixtures/rng-draw-record.example.json").read_text(encoding="utf-8").find('"seed"'),
            -1,
        )

    def test_the_validator_rejects_a_record_schema_that_stops_being_closed(self) -> None:
        root = self._isolated_root()
        path = root / "games/roulette/rng-draw-record.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema["additionalProperties"] = True
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(BaselineValidationError, r"additionalProperties must be false"):
            validate_r2_rng(root=root)

    def test_the_validator_rejects_a_schema_that_declares_a_prohibited_field(self) -> None:
        root = self._isolated_root()
        path = root / "games/roulette/rng-draw-record.schema.json"
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema["properties"]["seed"] = {"type": "string"}
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(BaselineValidationError, r"prohibited entropy fields are declared"):
            validate_r2_rng(root=root)

    def test_the_validator_rejects_a_broken_recovery_chain(self) -> None:
        root = self._isolated_root()
        path = root / "audit/events/R2-RNG-0001-events.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["events"][1]["action"] = "SOMETHING_ELSE"
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(BaselineValidationError, r"recovery audit chain is broken"):
            validate_r2_rng(root=root)

    def test_the_validator_rejects_an_erased_gate_violation(self) -> None:
        root = self._isolated_root()
        path = root / "audit/events/R2-RNG-0001-events.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["events"] = [
            event for event in document["events"] if event["action"] != "READY_GATE_VIOLATION_DETECTED"
        ]
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaises(BaselineValidationError) as caught:
            validate_r2_rng(root=root)
        self.assertRegex(str(caught.exception), r"recovery record is incomplete|chain is broken")

    def test_the_validator_rejects_a_forged_human_approval(self) -> None:
        root = self._isolated_root()
        path = root / "docs/approvals/R1-checklist.md"
        original = path.read_text(encoding="utf-8")
        forged = original.replace(
            "- [ ] QA Lead: 수학·부정 테스트 독립 승인", "- [x] QA Lead: 수학·부정 테스트 독립 승인", 1
        )
        self.assertNotEqual(forged, original, "the checklist wording changed; update this test")
        path.write_text(forged, encoding="utf-8")
        with self.assertRaisesRegex(BaselineValidationError, r"without a human sign-off"):
            validate_r2_rng(root=root)
        # The live checklist must be untouched. Only the follow-up section is checked: the
        # automated-checks section above it carries legitimate "- [x]" marks.
        live = (ROOT / "docs/approvals/R1-checklist.md").read_text(encoding="utf-8")
        self.assertNotIn("- [x]", live.split("## 후속 승인", 1)[1].split("\n## ", 1)[0])

    def test_the_validator_rejects_a_downgraded_task_contract(self) -> None:
        root = self._isolated_root()
        path = root / "tasks/R2-RNG-0001.json"
        task = json.loads(path.read_text(encoding="utf-8"))
        task["risk_class"] = "LOW"
        path.write_text(json.dumps(task, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(BaselineValidationError, r"HIGH risk task"):
            validate_r2_rng(root=root)

    def test_the_recovery_record_keeps_the_gate_violation_on_file(self) -> None:
        document = load_json("audit/events/R2-RNG-0001-events.json")
        actions = {event["action"] for event in document["events"]}
        self.assertIn("READY_GATE_VIOLATION_DETECTED", actions)
        self.assertIn("GATE_VIOLATION_RECOVERY_COMPLETED", actions)
        self.assertEqual(verify_audit_chain(document["events"]), [])

        recovery = (ROOT / "docs/operations/R2-RNG-0001-recovery.md").read_text(encoding="utf-8")
        self.assertIn("aedfacb41a18e03756f21ddd3203df9f9b82abf4c73d1319b838bf44c78d8591", recovery)

    def test_the_task_contract_is_ready_high_risk_and_correctly_approved(self) -> None:
        task = load_json("tasks/R2-RNG-0001.json")
        validate_instance(task, load_json("contracts/task.schema.json"))
        self.assertEqual(task["status"], "READY")
        self.assertEqual(task["risk_class"], "HIGH")
        self.assertEqual(task["owner_agent_id"], "A-20")
        self.assertEqual(set(task["approvers"]), {"A-50", "A-02", "A-00", "USER"})
        self.assertEqual(task["budget"]["max_cost_usd"], 20.0)
        self.assertEqual(task["budget"]["max_runtime_seconds"], 10800)
        self.assertIs(task["budget"]["stop_on_limit"], True)
        self.assertEqual(task["security"]["data_classification"], "INTERNAL")
        self.assertIs(task["security"]["contains_pii"], False)
        self.assertEqual(task["security"]["secrets_policy"], "REFERENCE_ONLY")
        self.assertIs(task["rollback"]["source_preserved"], True)

    def test_no_human_follow_up_approval_is_claimed(self) -> None:
        checklist = (ROOT / "docs/approvals/R1-checklist.md").read_text(encoding="utf-8")
        follow_up = checklist.split("## 후속 승인", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("- [x]", follow_up.lower())
        self.assertIn("서명은 수행되지 않았", follow_up)

    def test_the_out_of_scope_r2_risks_stay_open(self) -> None:
        closure = (ROOT / "docs/approvals/R1-evidence-closure.md").read_text(encoding="utf-8")
        for risk in ("데이터베이스 격리", "보안 침투"):
            self.assertIn(risk, closure)
        self.assertIn("OPEN", closure)


class ModuleSurfaceTests(unittest.TestCase):
    """The public surface is what a reviewer reads; keep it honest."""

    def test_rng_exports_resolve(self) -> None:
        import studio_core.rng as module

        for name in module.__all__:
            self.assertTrue(hasattr(module, name), f"{name} is exported but missing")

    def test_rng_stats_exports_resolve(self) -> None:
        for name in rng_stats.__all__:
            self.assertTrue(hasattr(rng_stats, name), f"{name} is exported but missing")

    def test_the_draw_boundary_does_not_depend_on_payouts_or_the_ledger(self) -> None:
        # Structural, not stylistic: if the entropy path could see the payout table, "the RNG
        # cannot be influenced by payouts" would be a review promise instead of a property.
        imported = _imported_modules("studio_core/rng.py")
        for name in imported:
            self.assertNotIn("roulette", name)
            self.assertNotIn("ledger", name)
            self.assertNotIn("rounds", name)
        self.assertEqual(
            imported,
            {"__future__", "copy", "hashlib", "json", "re", "secrets", "threading",
             "dataclasses", "datetime", "enum", "typing"},
        )

    def test_the_repository_fixture_matches_a_regenerated_draw(self) -> None:
        chain = AuditChain("RNG")
        engine = RouletteDrawEngine(
            entropy_source=DeterministicTestEntropySource(bytes([250, 17])),
            environment=RngEnvironment.NON_PRODUCTION,
            audit_sink=chain,
            clock=lambda: FIXED_CLOCK,
        )
        record = engine.draw(
            DrawRequest(request_id="RNG-R2-FIXTURE-0001", round_id="RR-R2-FIXTURE-0001", draw_index=0)
        )
        fixture = json.loads(
            pathlib.Path(ROOT / "games/roulette/fixtures/rng-draw-record.example.json").read_text(encoding="utf-8")
        )
        self.assertEqual(record.to_dict(), fixture)


if __name__ == "__main__":
    unittest.main()
