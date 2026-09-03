"""R4-FIX-0008: the table recovers from a settlement submission that raises.

``RouletteTable.spin`` hands the whole round to ``DurableRoundStore.submit_round`` and
translated exactly two refusals -- ``RngDenied`` and ``DurableStateError`` -- into a voided
local round. Anything else that escaped the store propagated with the in-memory round still
``SPINNING`` or ``SETTLING`` and the stake still reserved. The store had already rolled its
transaction back, so nothing was committed, but the table could never open another round:
every later bet, spin and ``new_round`` was refused for the rest of the process.

These tests inject failures through the store's existing ``fault_hook`` at each pre-commit
stage and hold the table to three things at once:

* the exception itself is preserved -- neither translated into a refusal nobody decided nor
  swallowed into a false success;
* the durable side is untouched: no draw record, no settlement, no balance movement, and
  the failed round can never be drawn again;
* the local side is terminal: reservations released, the next round opens, and it settles
  normally once the fault is gone.

A fault *after* the commit is the opposite case and gets its own section: the store has
settled the round, so the table must reconcile with storage and show that settlement, not a
void, while the exception still propagates. The initial revision of this suite only held the
post-commit round to "terminal"; that was rejected in review and is superseded below.

Every database here is a throwaway temporary file; nothing touches the runtime location.
"""

from __future__ import annotations

import dataclasses
import pathlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import open_table  # noqa: E402
from apps.roulette_web.table import (  # noqa: E402
    ESCROW_ACCOUNT,
    HOUSE_ACCOUNT,
    PLAYER_ACCOUNT,
    TERMINAL_PHASES,
    RoundPhase,
    TableConfig,
    TableError,
)
from studio_core.durable_state import FAULT_STAGES, DurableStateError  # noqa: E402
from studio_core.rng import (  # noqa: E402
    DeterministicTestEntropySource,
    DrawRequest,
    FailureAction,
    RngDenied,
    RngEnvironment,
)

FIXED_CLOCK = "2026-09-03T00:00:00Z"
ENTROPY_STREAM = bytes([7, 11, 13, 17, 19, 23])
OPENING_PLAYER_UNITS = 1_000
OPENING_HOUSE_UNITS = 100_000
RED = {"type": "red", "selections": [], "stake_units": 25}

PRE_COMMIT_STAGES = ("after_draw", "after_ledger", "before_commit")

#: Failure types the store does not classify, each of which must propagate unchanged.
UNCLASSIFIED_FAULTS = (
    ("RuntimeError", lambda stage: RuntimeError(f"injected fault at {stage}")),
    ("sqlite3.OperationalError", lambda stage: sqlite3.OperationalError(f"disk I/O error at {stage}")),
)

#: Everything that may escape ``after_commit``; the settled round must survive each of them.
POST_COMMIT_FAULTS = UNCLASSIFIED_FAULTS + (
    ("KeyboardInterrupt", lambda stage: KeyboardInterrupt(f"interrupted at {stage}")),
)


class OneShotFault:
    """A ``fault_hook`` that raises a prepared exception once at one stage, then stays quiet.

    The exception object is built up front and kept so a test can assert that the very same
    instance reached the caller: identity is a stronger claim than type, because it also
    rules out a re-raise that copied the message into something else.
    """

    def __init__(self, stage: str, factory) -> None:
        self.stage = stage
        self.exception = factory(stage)
        self.fired = 0
        self.armed = True
        self.reached: list[str] = []

    def __call__(self, stage: str) -> None:
        self.reached.append(stage)
        if self.armed and stage == self.stage:
            self.armed = False
            self.fired += 1
            raise self.exception


class FailureRecoveryTestCase(unittest.TestCase):
    """One isolated database directory and one deterministic entropy stream per test."""

    def setUp(self) -> None:
        self.workspace = pathlib.Path(tempfile.mkdtemp(prefix="r4fix-test-"))
        self.addCleanup(shutil.rmtree, self.workspace, True)
        self.entropy = DeterministicTestEntropySource(ENTROPY_STREAM)

    def open(self, *, fault_hook=None, name: str = "slice"):
        store, table = open_table(
            self.workspace / name / "roulette-web.sqlite3",
            config=TableConfig(opening_player_units=OPENING_PLAYER_UNITS, opening_house_units=OPENING_HOUSE_UNITS),
            clock=lambda: FIXED_CLOCK,
            entropy_source=self.entropy,
            environment=RngEnvironment.NON_PRODUCTION,
            fault_hook=fault_hook,
        )
        self.addCleanup(store.close)
        return store, table

    # -- shared assertions ----------------------------------------------------------------

    def assert_nothing_committed(self, store, round_id: str) -> None:
        """The failed transaction left no durable trace except the void that fences it."""

        self.assertEqual(store.count("draw_record"), 0)
        self.assertEqual(store.count("ledger_transaction"), 0)
        self.assertEqual(store.count("ledger_entry"), 0)
        self.assertEqual(
            store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT, ESCROW_ACCOUNT]),
            {PLAYER_ACCOUNT: OPENING_PLAYER_UNITS, HOUSE_ACCOUNT: OPENING_HOUSE_UNITS, ESCROW_ACCOUNT: 0},
        )
        actions = [event["action"] for event in store.audit_events()]
        self.assertNotIn("ROULETTE_RNG_DRAW", actions)
        self.assertNotIn("ROULETTE_ROUND_SETTLED", actions)
        self.assertEqual(store.verify_chain(), [])
        # The sample was taken and discarded, so the store fences the round durably.
        self.assertTrue(store.is_round_voided(round_id))

    def assert_round_is_terminal_and_released(self, table, round_id: str) -> None:
        state = table.state()
        self.assertEqual(state["round"]["round_id"], round_id)
        self.assertIn(RoundPhase(state["round"]["phase"]), TERMINAL_PHASES)
        self.assertTrue(state["round"]["is_terminal"])
        self.assertFalse(state["round"]["accepts_bets"])
        self.assertEqual(state["reserved_units"], 0)
        self.assertEqual(state["balance_units"], OPENING_PLAYER_UNITS)
        self.assertEqual(state["available_units"], OPENING_PLAYER_UNITS)
        self.assertEqual(state["house_bankroll_units"], OPENING_HOUSE_UNITS)
        self.assertIsNone(state["round"]["result"])
        self.assertEqual([item["round_id"] for item in state["recent_results"]], [])

    def assert_failed_round_cannot_be_retried(self, store, table, request_id: str) -> None:
        """A retry -- same or new identifier -- is refused by the phase guard and draws nothing."""

        consumed = self.entropy.consumed
        draws = store.count("draw_record")
        for retry_id in (request_id, request_id + "-retry"):
            with self.assertRaises(TableError) as caught:
                table.spin(retry_id)
            self.assertEqual(caught.exception.code, "PHASE_DENIED")
            self.assertEqual(caught.exception.status, 409)
        with self.assertRaises(TableError) as caught:
            table.place_bet(request_id + "-bet", dict(RED))
        self.assertEqual(caught.exception.code, "PHASE_DENIED")
        self.assertEqual(self.entropy.consumed, consumed)
        self.assertEqual(store.count("draw_record"), draws)

    def assert_next_round_completes(self, store, table, failed_round_id: str, *, prefix: str) -> None:
        """Opening a fresh round works, and it settles as if the failure never happened."""

        opened = table.new_round(f"{prefix}-NEW")
        self.assertTrue(opened["accepted"])
        state = opened["state"]
        self.assertEqual(state["round"]["phase"], "OPEN")
        self.assertNotEqual(state["round"]["round_id"], failed_round_id)
        self.assertEqual(state["round"]["bets"], [])
        self.assertEqual(state["reserved_units"], 0)

        placed = table.place_bet(f"{prefix}-BET2", dict(RED))
        self.assertTrue(placed["accepted"])
        self.assertEqual(placed["state"]["reserved_units"], RED["stake_units"])

        consumed = self.entropy.consumed
        spun = table.spin(f"{prefix}-SPIN2")
        self.assertFalse(spun["replayed"])
        self.assertGreater(self.entropy.consumed, consumed)
        result = spun["result"]
        self.assertEqual(result["round_id"], state["round"]["round_id"])
        self.assertIsInstance(result["pocket"], int)
        self.assertEqual(spun["state"]["round"]["phase"], "SETTLED")
        self.assertEqual(spun["state"]["reserved_units"], 0)
        self.assertEqual(
            [step["to"] for step in spun["state"]["round"]["transitions"]],
            ["LOCKED", "SPINNING", "SETTLING", "SETTLED"],
        )
        self.assertEqual(
            spun["state"]["balance_units"], OPENING_PLAYER_UNITS + int(result["net_change_units"])
        )
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)
        self.assertEqual(store.verify_chain(), [])
        self.assertEqual(
            [item["round_id"] for item in spun["state"]["recent_results"]], [result["round_id"]]
        )
        self.assertEqual(spun["state"]["recent_results"], table.reload_history())


# ---------------------------------------------------------------------------------------
# AC-001 / AC-002 / AC-003: unclassified exceptions at every pre-commit stage
# ---------------------------------------------------------------------------------------


class PreCommitFaultRecoveryTests(FailureRecoveryTestCase):
    def test_the_injected_stages_are_the_ones_the_store_declares(self) -> None:
        self.assertEqual(set(PRE_COMMIT_STAGES) | {"after_begin", "after_commit"}, set(FAULT_STAGES))

    def test_an_unclassified_failure_at_any_pre_commit_stage_voids_the_round_and_frees_the_table(self) -> None:
        for stage in PRE_COMMIT_STAGES:
            for label, factory in UNCLASSIFIED_FAULTS:
                with self.subTest(stage=stage, exception=label):
                    self.setUp()
                    fault = OneShotFault(stage, factory)
                    store, table = self.open(fault_hook=fault)
                    table.place_bet("R4FIX-BET-0001", dict(RED))
                    round_id = table.state()["round"]["round_id"]
                    consumed_before = self.entropy.consumed

                    with self.assertRaises(type(fault.exception)) as caught:
                        table.spin("R4FIX-SPIN-0001")
                    # The original exception, not a translation of it and not a success.
                    self.assertIs(caught.exception, fault.exception)
                    self.assertNotIsInstance(caught.exception, TableError)
                    self.assertEqual(fault.fired, 1)
                    # Exactly one sample was taken before the fault, and it was discarded.
                    self.assertGreater(self.entropy.consumed, consumed_before)

                    self.assert_round_is_terminal_and_released(table, round_id)
                    self.assert_nothing_committed(store, round_id)
                    self.assert_failed_round_cannot_be_retried(store, table, "R4FIX-SPIN-0001")
                    self.assert_next_round_completes(store, table, round_id, prefix="R4FIX-NEXT")
                    # The one-shot fault never fired again on the successful round.
                    self.assertEqual(fault.fired, 1)
                    self.doCleanups()

    def test_the_stage_that_failed_determines_the_phase_the_round_had_reached(self) -> None:
        """The recovery is not a blanket reset: the walk up to the fault is still recorded."""

        expected_walk = {
            "after_draw": ["LOCKED", "SPINNING"],
            "after_ledger": ["LOCKED", "SPINNING", "SETTLING"],
            "before_commit": ["LOCKED", "SPINNING", "SETTLING"],
        }
        for stage in PRE_COMMIT_STAGES:
            with self.subTest(stage=stage):
                self.setUp()
                fault = OneShotFault(stage, UNCLASSIFIED_FAULTS[0][1])
                _, table = self.open(fault_hook=fault)
                table.place_bet("R4FIX-BET-0002", dict(RED))
                with self.assertRaises(RuntimeError):
                    table.spin("R4FIX-SPIN-0002")
                walked = [step["to"] for step in table.state()["round"]["transitions"]]
                self.assertEqual(walked[: len(expected_walk[stage])], expected_walk[stage])
                self.assertEqual(table.state()["round"]["phase"], "VOIDED")
                self.doCleanups()

    def test_a_failure_inside_the_table_settlement_itself_is_recovered_the_same_way(self) -> None:
        """A defect in settlement arithmetic surfaces from inside the store's transaction."""

        store, table = self.open()
        table.place_bet("R4FIX-BET-0003", dict(RED))
        round_id = table.state()["round"]["round_id"]
        defect = ValueError("settlement arithmetic defect")
        with mock.patch.object(table, "_settle_round", side_effect=defect):
            with self.assertRaises(ValueError) as caught:
                table.spin("R4FIX-SPIN-0003")
        self.assertIs(caught.exception, defect)
        self.assert_round_is_terminal_and_released(table, round_id)
        self.assert_nothing_committed(store, round_id)
        self.assert_failed_round_cannot_be_retried(store, table, "R4FIX-SPIN-0003")
        self.assert_next_round_completes(store, table, round_id, prefix="R4FIX-NEXT3")


# ---------------------------------------------------------------------------------------
# AC-003: process-control exceptions propagate, and the table is still not wedged
# ---------------------------------------------------------------------------------------


class ProcessControlExceptionTests(FailureRecoveryTestCase):
    def test_a_keyboard_interrupt_during_commit_propagates_and_releases_the_table(self) -> None:
        """``KeyboardInterrupt`` is not an ``Exception``; it must neither be swallowed nor wedge."""

        for stage in PRE_COMMIT_STAGES:
            with self.subTest(stage=stage):
                self.setUp()
                fault = OneShotFault(stage, lambda reached: KeyboardInterrupt(f"interrupted at {reached}"))
                store, table = self.open(fault_hook=fault)
                table.place_bet("R4FIX-BET-0004", dict(RED))
                round_id = table.state()["round"]["round_id"]

                with self.assertRaises(KeyboardInterrupt) as caught:
                    table.spin("R4FIX-SPIN-0004")
                self.assertIs(caught.exception, fault.exception)

                self.assert_round_is_terminal_and_released(table, round_id)
                # The store's transaction rolled back: nothing durable exists for the round.
                self.assertEqual(store.count("draw_record"), 0)
                self.assertEqual(store.count("ledger_transaction"), 0)
                self.assertEqual(
                    store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT]),
                    {PLAYER_ACCOUNT: OPENING_PLAYER_UNITS, HOUSE_ACCOUNT: OPENING_HOUSE_UNITS},
                )
                self.assertEqual(store.verify_chain(), [])
                # The phase guard of the table is what stops a second draw of this round.
                self.assert_failed_round_cannot_be_retried(store, table, "R4FIX-SPIN-0004")
                self.assert_next_round_completes(store, table, round_id, prefix="R4FIX-NEXT4")
                self.doCleanups()


# ---------------------------------------------------------------------------------------
# AC-003: the two typed refusals keep their mappings and their cleanup
# ---------------------------------------------------------------------------------------


class TypedRefusalMappingTests(FailureRecoveryTestCase):
    def test_a_durable_state_refusal_is_still_reported_as_commit_denied(self) -> None:
        fault = OneShotFault(
            "before_commit", lambda stage: DurableStateError("INJECTED_REFUSAL", f"refused at {stage}")
        )
        store, table = self.open(fault_hook=fault)
        table.place_bet("R4FIX-BET-0005", dict(RED))
        round_id = table.state()["round"]["round_id"]
        with self.assertRaises(TableError) as caught:
            table.spin("R4FIX-SPIN-0005")
        self.assertEqual(caught.exception.code, "COMMIT_DENIED")
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("INJECTED_REFUSAL", caught.exception.message)
        self.assertNotIn(str(self.workspace), caught.exception.message)
        self.assert_round_is_terminal_and_released(table, round_id)
        self.assert_nothing_committed(store, round_id)
        self.assert_failed_round_cannot_be_retried(store, table, "R4FIX-SPIN-0005")
        self.assert_next_round_completes(store, table, round_id, prefix="R4FIX-NEXT5")

    def test_an_rng_refusal_is_still_reported_as_draw_denied(self) -> None:
        fault = OneShotFault(
            "after_draw",
            lambda stage: RngDenied("INJECTED_DENIAL", FailureAction.BLOCK_AND_VOID, f"denied at {stage}"),
        )
        store, table = self.open(fault_hook=fault)
        table.place_bet("R4FIX-BET-0006", dict(RED))
        round_id = table.state()["round"]["round_id"]
        with self.assertRaises(TableError) as caught:
            table.spin("R4FIX-SPIN-0006")
        self.assertEqual(caught.exception.code, "DRAW_DENIED")
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("INJECTED_DENIAL", caught.exception.message)
        self.assert_round_is_terminal_and_released(table, round_id)
        self.assert_nothing_committed(store, round_id)
        self.assert_failed_round_cannot_be_retried(store, table, "R4FIX-SPIN-0006")
        self.assert_next_round_completes(store, table, round_id, prefix="R4FIX-NEXT6")


# ---------------------------------------------------------------------------------------
# AC-006: a failure after the commit can neither lose nor duplicate the settled result
# ---------------------------------------------------------------------------------------


class PostCommitFaultTests(FailureRecoveryTestCase):
    """The store committed and then raised. Storage is the truth; the table must agree with it."""

    REQUEST_ID = "R4FIX-SPIN-0007"

    def spin_with_post_commit_fault(self, factory):
        """Spin once into an ``after_commit`` fault and return everything a check needs."""

        fault = OneShotFault("after_commit", factory)
        store, table = self.open(fault_hook=fault)
        table.place_bet("R4FIX-BET-0007", dict(RED))
        round_id = table.state()["round"]["round_id"]
        consumed_before = self.entropy.consumed
        with self.assertRaises(type(fault.exception)) as caught:
            table.spin(self.REQUEST_ID)
        self.assertIs(caught.exception, fault.exception)
        self.assertNotIsInstance(caught.exception, TableError)
        self.assertEqual(fault.fired, 1)
        self.assertGreater(self.entropy.consumed, consumed_before)
        return store, table, round_id, self.entropy.consumed

    def assert_committed_once(self, store, round_id: str) -> dict:
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)
        self.assertEqual(store.verify_chain(), [])
        self.assertFalse(store.is_round_voided(round_id))
        record = store.draw_record(self.REQUEST_ID)
        self.assertIsNotNone(record)
        self.assertEqual(record.round_id, round_id)
        balances = store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT, ESCROW_ACCOUNT])
        self.assertEqual(balances[ESCROW_ACCOUNT], 0)
        self.assertEqual(
            balances[PLAYER_ACCOUNT] + balances[HOUSE_ACCOUNT], OPENING_PLAYER_UNITS + OPENING_HOUSE_UNITS
        )
        return balances

    def assert_local_round_matches_storage(self, store, table, round_id: str) -> dict:
        """The immediate snapshot -- no ``reload_history`` -- is the settled round from storage."""

        balances = self.assert_committed_once(store, round_id)
        record = store.draw_record(self.REQUEST_ID)
        state = table.state()
        self.assertEqual(state["round"]["round_id"], round_id)
        self.assertEqual(state["round"]["phase"], "SETTLED")
        self.assertTrue(state["round"]["is_terminal"])
        self.assertEqual(
            [step["to"] for step in state["round"]["transitions"]],
            ["LOCKED", "SPINNING", "SETTLING", "SETTLED"],
        )
        self.assertEqual(state["reserved_units"], 0)
        self.assertEqual(state["balance_units"], balances[PLAYER_ACCOUNT])
        self.assertEqual(state["available_units"], balances[PLAYER_ACCOUNT])
        self.assertEqual(state["house_bankroll_units"], balances[HOUSE_ACCOUNT])
        result = state["round"]["result"]
        self.assertIsNotNone(result)
        self.assertEqual(result["round_id"], round_id)
        self.assertEqual(result["pocket"], record.pocket)
        self.assertEqual(result["proof_hash"], record.proof_hash)
        self.assertEqual(result["settled_at"], record.created_at)
        self.assertEqual(result["total_stake_units"], RED["stake_units"])
        self.assertEqual(balances[PLAYER_ACCOUNT], OPENING_PLAYER_UNITS + result["net_change_units"])
        stored = store.ledger_transaction(result["settlement_transaction_id"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored["round_id"], round_id)
        self.assertEqual([item["round_id"] for item in state["recent_results"]], [round_id])
        self.assertEqual(state["recent_results"][0]["pocket"], record.pocket)
        # What the snapshot showed is exactly what a restart would rebuild.
        self.assertEqual(state["recent_results"], table.reload_history())
        return result

    def assert_replay_and_refusal(self, store, table, result: dict, consumed: int) -> None:
        """Same id: the committed result again. New id: refused. Neither touches storage."""

        replayed = table.spin(self.REQUEST_ID)
        self.assertTrue(replayed["replayed"])
        self.assertTrue(replayed["accepted"])
        self.assertEqual(replayed["result"], result)
        self.assertEqual(replayed["state"]["round"]["phase"], "SETTLED")
        with self.assertRaises(TableError) as caught:
            table.spin(self.REQUEST_ID + "-retry")
        self.assertEqual(caught.exception.code, "PHASE_DENIED")
        self.assertEqual(caught.exception.status, 409)
        with self.assertRaises(TableError) as caught:
            table.place_bet(self.REQUEST_ID + "-bet", dict(RED))
        self.assertEqual(caught.exception.code, "PHASE_DENIED")
        self.assertEqual(self.entropy.consumed, consumed)
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)
        entries = store.ledger_transaction(result["settlement_transaction_id"])["entries"]
        self.assertEqual(store.count("ledger_entry"), len(entries))

    def assert_next_round_settles(self, store, table, round_id: str, *, prefix: str) -> None:
        opened = table.new_round(f"{prefix}-NEW")
        self.assertEqual(opened["state"]["round"]["phase"], "OPEN")
        self.assertNotEqual(opened["state"]["round"]["round_id"], round_id)
        table.place_bet(f"{prefix}-BET2", dict(RED))
        spun = table.spin(f"{prefix}-SPIN2")
        self.assertEqual(spun["state"]["round"]["phase"], "SETTLED")
        self.assertEqual(store.count("draw_record"), 2)
        self.assertEqual(store.count("ledger_transaction"), 2)
        self.assertEqual(store.verify_chain(), [])

    def test_a_fault_after_the_commit_reconciles_to_the_settled_round(self) -> None:
        """RuntimeError, sqlite3.OperationalError and KeyboardInterrupt: same outcome each."""

        for label, factory in POST_COMMIT_FAULTS:
            with self.subTest(exception=label):
                self.setUp()
                store, table, round_id, consumed = self.spin_with_post_commit_fault(factory)
                result = self.assert_local_round_matches_storage(store, table, round_id)
                self.assertNotEqual(table.state()["round"]["phase"], "VOIDED")
                self.assert_replay_and_refusal(store, table, result, consumed)
                self.assert_next_round_settles(store, table, round_id, prefix="R4FIX-NEXT7")
                self.doCleanups()

    def test_the_reconciled_result_is_what_the_store_replays(self) -> None:
        """The adopted result is the read-back of the store itself, not a locally invented one."""

        store, table, round_id, consumed = self.spin_with_post_commit_fault(UNCLASSIFIED_FAULTS[0][1])
        result = table.state()["round"]["result"]
        replay = store.submit_round(DrawRequest(request_id=self.REQUEST_ID, round_id=round_id))
        self.assertTrue(replay.replayed)
        self.assertEqual(self.entropy.consumed, consumed)
        self.assertEqual(result["pocket"], replay.record.pocket)
        self.assertEqual(result["proof_hash"], replay.record.proof_hash)
        self.assertEqual(result["settlement_transaction_id"], replay.settlement_transaction_id)
        self.assertEqual(result["audit_event_refs"], list(replay.audit_event_refs))
        self.assertEqual(table.state()["balance_units"], replay.balances[PLAYER_ACCOUNT])

    def test_a_stored_record_for_another_round_is_not_adopted(self) -> None:
        """A record that matches the request but not this round is refused, fail-closed."""

        fault = OneShotFault("after_commit", UNCLASSIFIED_FAULTS[0][1])
        store, table = self.open(fault_hook=fault)
        original = store.draw_record
        seen: list = []

        def other_round(request_id):
            real = original(request_id)
            seen.append(real)
            return None if real is None else dataclasses.replace(real, round_id="RR-WEB-OTHER-0001")

        table.place_bet("R4FIX-BET-0007", dict(RED))
        round_id = table.state()["round"]["round_id"]
        with mock.patch.object(store, "draw_record", side_effect=other_round):
            with self.assertRaises(RuntimeError) as caught:
                table.spin(self.REQUEST_ID)
        self.assertIs(caught.exception, fault.exception)
        self.assertTrue(seen and seen[0] is not None)
        consumed = self.entropy.consumed

        # The durable round is settled and untouched; the local one is closed without a
        # result it cannot vouch for, and no retry redraws or re-settles anything.
        self.assert_committed_once(store, round_id)
        state = table.state()
        self.assertEqual(state["round"]["phase"], "VOIDED")
        self.assertIsNone(state["round"]["result"])
        self.assertEqual(state["reserved_units"], 0)
        self.assertEqual(state["recent_results"], [])
        self.assert_failed_round_cannot_be_retried(store, table, self.REQUEST_ID)
        self.assertEqual(self.entropy.consumed, consumed)
        self.assertEqual(store.count("ledger_transaction"), 1)
        self.assert_next_round_settles(store, table, round_id, prefix="R4FIX-NEXT8")

    def test_a_reconciliation_read_failure_keeps_the_original_error_and_fails_closed(self) -> None:
        """A storage outage while reconciling neither replaces the error nor fakes a result."""

        outage = sqlite3.OperationalError("database is locked during reconciliation")
        cases = {
            "draw_record": lambda store: {"draw_record": mock.Mock(side_effect=outage)},
            "submit_round replay": lambda store: {"submit_round": _FailSecondCall(store.submit_round, outage)},
        }
        for label, build in cases.items():
            with self.subTest(read=label):
                self.setUp()
                fault = OneShotFault("after_commit", UNCLASSIFIED_FAULTS[0][1])
                store, table = self.open(fault_hook=fault)
                table.place_bet("R4FIX-BET-0007", dict(RED))
                round_id = table.state()["round"]["round_id"]
                with mock.patch.multiple(store, **build(store)):
                    with self.assertRaises(RuntimeError) as caught:
                        table.spin(self.REQUEST_ID)
                self.assertIs(caught.exception, fault.exception)
                self.assertIsNot(caught.exception, outage)

                # Durable: settled. Local: fail-closed, released, and never a false SETTLED.
                self.assert_committed_once(store, round_id)
                state = table.state()
                self.assertEqual(state["round"]["phase"], "VOIDED")
                self.assertIsNone(state["round"]["result"])
                self.assertEqual(state["reserved_units"], 0)
                self.assertEqual(state["balance_units"], store.balances([PLAYER_ACCOUNT])[PLAYER_ACCOUNT])
                self.assert_failed_round_cannot_be_retried(store, table, self.REQUEST_ID)
                self.assertEqual(store.count("draw_record"), 1)
                # The committed round is still recoverable once storage answers again.
                self.assertEqual([item["round_id"] for item in table.reload_history()], [round_id])
                self.assert_next_round_settles(store, table, round_id, prefix="R4FIX-NEXT9")
                self.doCleanups()

    def test_a_failure_inside_the_cleanup_itself_still_preserves_the_original_error(self) -> None:
        """Even a defect in the recovery path may not replace the exception being reported."""

        fault = OneShotFault("after_commit", UNCLASSIFIED_FAULTS[0][1])
        store, table = self.open(fault_hook=fault)
        table.place_bet("R4FIX-BET-0007", dict(RED))
        round_id = table.state()["round"]["round_id"]
        original_transition = table._transition

        def broken_transition(target):
            if target in TERMINAL_PHASES:
                raise RuntimeError("cleanup defect")
            return original_transition(target)

        with mock.patch.object(table, "_transition", side_effect=broken_transition):
            with self.assertRaises(RuntimeError) as caught:
                table.spin(self.REQUEST_ID)
        self.assertIs(caught.exception, fault.exception)
        self.assert_committed_once(store, round_id)
        state = table.state()
        self.assertIn(RoundPhase(state["round"]["phase"]), TERMINAL_PHASES)
        self.assertEqual(state["reserved_units"], 0)
        self.assertEqual(store.count("draw_record"), 1)
        opened = table.new_round("R4FIX-NEXT10-NEW")
        self.assertEqual(opened["state"]["round"]["phase"], "OPEN")


class _FailSecondCall:
    """Let the first call through (the real submission) and raise on the second (the replay)."""

    def __init__(self, target, exception: BaseException) -> None:
        self.target = target
        self.exception = exception
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 2:
            raise self.exception
        return self.target(*args, **kwargs)


if __name__ == "__main__":
    unittest.main()
