"""R2-DBC-0002: certification suite for the durable-state boundary.

The suite is organised by the acceptance criterion it defends rather than by the method it
calls, because the criteria are stated as properties of the store rather than of any one
function. Two of them cannot be established by a unit test at all:

* ``AC-006`` is a race. It is proved with real threads on separate connections synchronised by
  a barrier, not by calling the code twice in sequence and reasoning about what would have
  happened -- a sequential test passes just as happily against a store with no locking.
* ``AC-005`` is atomicity under failure. It is proved by injecting a fault at every stage the
  implementation declares, reopening the database from disk, and looking at what survived.

Every database this file creates lives in a temporary directory, as the task contract
requires; none is written into the repository.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import shutil
import sqlite3
import tempfile
import threading
import unittest

from studio_core.durable_state import (
    AUDIT_SEGMENT_SIZE,
    BUSY_TIMEOUT_MS,
    DURABLE_SCHEMA_VERSION,
    FAILURE_BEHAVIOR,
    FAULT_STAGES,
    FOREIGN_KEYS,
    ISOLATION_LEVEL,
    JOURNAL_MODE,
    MAX_AUDIT_SEGMENT,
    MAX_BUSY_RETRIES,
    PATH_HANDLING,
    POLICY_VERSION,
    PROHIBITED_STORAGE_FIELDS,
    SCHEMA_STATEMENTS,
    SUPPORTED_SCHEMA_VERSIONS,
    SYNCHRONOUS,
    TASK_ID,
    TRANSACTION_MODE,
    CommittedRound,
    DurableRoundStore,
    DurableStateError,
    LedgerConflict,
    SchemaVersionError,
    contract_declaration,
    prohibited_fields,
    resolve_database_path,
    schema_sql,
)
from studio_core.integrity import hash_file
from studio_core.rng import (
    PROHIBITED_RECORD_FIELDS,
    DeterministicTestEntropySource,
    DrawRequest,
    OsCsprngEntropySource,
    RngDenied,
    RngEnvironment,
    compute_event_hash,
    verify_audit_chain,
)
from scripts.validate_baseline import (
    BaselineValidationError,
    R2_DBC_INPUT_FILES,
    R2_DBC_REQUIRED_AUDIT_ACTIONS,
    ROOT,
    load_json,
    load_yaml,
    validate_instance,
    validate_r2_durable_state,
)

FIXED_CLOCK = "2026-09-01T00:00:00Z"

#: Byte values every one of which the debiasing rule accepts, so the draw path consumes
#: exactly these and their absence from a database file is evidence rather than luck.
ENTROPY_MARKER = bytes([7, 11, 13, 17, 19, 23])

PLAYER = "player:demo"
HOUSE = "house:bank"


def settlement_for(record, *, index: int = 1, stake: int = 100) -> dict:
    """Return a balanced integer settlement for a drawn round."""

    return {
        "schema_version": "1.0.0",
        "transaction_id": f"LT-DBCTEST-{index:04d}",
        "idempotency_key": f"idem:{record.round_id}:settlement",
        "round_id": record.round_id,
        "transaction_type": "ROUND_SETTLEMENT",
        "currency": "VIRTUAL_CHIP",
        "entries": [
            {"account_id": PLAYER, "account_type": "PLAYER", "amount_units": -stake},
            {"account_id": HOUSE, "account_type": "HOUSE_BANKROLL", "amount_units": stake},
        ],
        "created_at": FIXED_CLOCK,
        "request_hash": "sha256:" + "0" * 64,
    }


class DurableStateTestCase(unittest.TestCase):
    """Base class giving every test an isolated temporary database directory."""

    def setUp(self) -> None:
        self.workspace = pathlib.Path(tempfile.mkdtemp(prefix="r2dbc-test-"))
        # ``ignore_errors`` covers only the Windows case where a worker thread's connection is
        # still awaiting garbage collection; the tests close their own stores explicitly and a
        # leaked handle would show up as a failing assertion, not as a silent cleanup skip.
        self.addCleanup(shutil.rmtree, self.workspace, True)
        self.database = self.workspace / "durable-state.sqlite3"

    def open_store(self, *, path: pathlib.Path | None = None, stream: bytes = ENTROPY_MARKER, **overrides):
        """Return an opened store over a reproducible entropy stream, closed on teardown."""

        options = {
            "namespace": "DBCT",
            "entropy_source": DeterministicTestEntropySource(stream),
            "environment": RngEnvironment.NON_PRODUCTION,
            "clock": lambda: FIXED_CLOCK,
        }
        options.update(overrides)
        store = DurableRoundStore(self.database if path is None else path, **options)
        self.addCleanup(store.close)
        return store

    def raw(self, path: pathlib.Path | None = None) -> sqlite3.Connection:
        """Return a raw connection with foreign keys on, closed on teardown."""

        connection = sqlite3.connect(str(self.database if path is None else path), isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        self.addCleanup(connection.close)
        return connection

    def seed_accounts(self, store, *, opening: int = 1000) -> None:
        store.register_account(PLAYER, "PLAYER", opening)
        store.register_account(HOUSE, "HOUSE_BANKROLL", 0)


# ---------------------------------------------------------------------------------------
# AC-008, AC-009: declared storage decisions, schema version and path handling
# ---------------------------------------------------------------------------------------


class StorageContractTests(DurableStateTestCase):
    def test_contract_file_declares_exactly_what_the_implementation_does(self) -> None:
        contract = load_yaml("games/roulette/durable-state-contract.yaml")
        self.assertEqual(dict(contract["storage"]), contract_declaration())
        self.assertEqual(dict(contract["failure_behavior"]), FAILURE_BEHAVIOR)
        for key, value in PATH_HANDLING.items():
            self.assertEqual(contract["path_handling"][key], value, key)

    def test_declaration_matches_the_module_constants(self) -> None:
        declared = contract_declaration()
        self.assertEqual(declared["isolation_level"], ISOLATION_LEVEL)
        self.assertEqual(declared["transaction_mode"], TRANSACTION_MODE)
        self.assertEqual(declared["journal_mode"], JOURNAL_MODE)
        self.assertEqual(declared["synchronous"], SYNCHRONOUS)
        self.assertIs(declared["foreign_keys"], FOREIGN_KEYS)
        self.assertEqual(declared["busy_timeout_ms"], BUSY_TIMEOUT_MS)
        self.assertEqual(declared["max_busy_retries"], MAX_BUSY_RETRIES)
        self.assertEqual(declared["schema_version"], DURABLE_SCHEMA_VERSION)
        self.assertEqual(declared["supported_schema_versions"], list(SUPPORTED_SCHEMA_VERSIONS))
        self.assertEqual(declared["audit_segment_size"], AUDIT_SEGMENT_SIZE)
        self.assertEqual(declared["max_audit_segment"], MAX_AUDIT_SEGMENT)
        self.assertEqual(declared["policy_version"], POLICY_VERSION)
        self.assertEqual(declared["task_id"], TASK_ID)

    def test_published_sql_is_the_sql_the_store_runs(self) -> None:
        published = (ROOT / "games/roulette/durable-state-schema.sql").read_text(encoding="utf-8")
        self.assertEqual(published.replace("\r\n", "\n"), schema_sql())
        for statement in SCHEMA_STATEMENTS:
            self.assertIn(statement, published.replace("\r\n", "\n"))

    def test_open_store_applies_every_declared_pragma(self) -> None:
        store = self.open_store()
        connection = self.raw()
        self.assertEqual(str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(), JOURNAL_MODE)
        self.assertEqual(int(connection.execute("PRAGMA user_version").fetchone()[0]), DURABLE_SCHEMA_VERSION)
        self.assertEqual(store.schema_version, DURABLE_SCHEMA_VERSION)
        row = connection.execute("SELECT value FROM schema_meta WHERE key = 'policy_version'").fetchone()
        self.assertEqual(row["value"], POLICY_VERSION)

    def test_reopening_an_existing_store_does_not_recreate_the_schema(self) -> None:
        first = self.open_store()
        self.seed_accounts(first)
        first.close()
        second = self.open_store()
        self.assertEqual(second.balances(), {HOUSE: 0, PLAYER: 1000})

    def test_a_future_schema_version_is_refused_not_downgraded(self) -> None:
        seeded = self.raw()
        seeded.execute(f"PRAGMA user_version = {DURABLE_SCHEMA_VERSION + 1}")
        with self.assertRaises(SchemaVersionError) as caught:
            self.open_store()
        self.assertEqual(caught.exception.code, "SCHEMA_VERSION_UNSUPPORTED")
        self.assertEqual(
            int(self.raw().execute("PRAGMA user_version").fetchone()[0]), DURABLE_SCHEMA_VERSION + 1
        )

    def test_a_disagreeing_schema_meta_row_is_refused(self) -> None:
        self.open_store().close()
        self.raw().execute("UPDATE schema_meta SET value = '77' WHERE key = 'schema_version'")
        with self.assertRaises(SchemaVersionError) as caught:
            self.open_store()
        self.assertEqual(caught.exception.code, "SCHEMA_META_MISMATCH")

    def test_a_missing_schema_meta_row_is_refused(self) -> None:
        self.open_store().close()
        self.raw().execute("DELETE FROM schema_meta WHERE key = 'schema_version'")
        with self.assertRaises(SchemaVersionError) as caught:
            self.open_store()
        self.assertEqual(caught.exception.code, "SCHEMA_META_MISSING")

    def test_owned_tables_at_version_zero_are_ambiguous_not_migrated(self) -> None:
        seeded = self.raw()
        seeded.execute("CREATE TABLE audit_event (event_seq INTEGER PRIMARY KEY)")
        seeded.execute("PRAGMA user_version = 0")
        with self.assertRaises(SchemaVersionError) as caught:
            self.open_store()
        self.assertEqual(caught.exception.code, "SCHEMA_STATE_AMBIGUOUS")

    def test_unsafe_database_paths_are_refused(self) -> None:
        for spelling in (":memory:", "file:x.sqlite3?mode=memory", "  ", "a\x00b"):
            with self.subTest(spelling=spelling), self.assertRaises(DurableStateError) as caught:
                resolve_database_path(spelling)
            self.assertEqual(caught.exception.code, "PATH_INVALID")

    def test_a_directory_and_a_missing_parent_are_refused(self) -> None:
        with self.assertRaises(DurableStateError) as directory:
            resolve_database_path(self.workspace)
        self.assertEqual(directory.exception.code, "PATH_INVALID")
        with self.assertRaises(DurableStateError) as parent:
            resolve_database_path(self.workspace / "absent" / "db.sqlite3")
        self.assertEqual(parent.exception.code, "PATH_INVALID")

    def test_a_relative_path_is_anchored_to_the_process_directory(self) -> None:
        self.assertTrue(resolve_database_path("relative.sqlite3").is_absolute())
        self.assertEqual(resolve_database_path("relative.sqlite3").parent, pathlib.Path(os.getcwd()))

    def test_construction_rejects_a_malformed_namespace_and_timeout(self) -> None:
        with self.assertRaises(DurableStateError) as namespace:
            self.open_store(namespace="lower")
        self.assertEqual(namespace.exception.code, "NAMESPACE_INVALID")
        with self.assertRaises(DurableStateError) as timeout:
            self.open_store(busy_timeout_ms=0)
        self.assertEqual(timeout.exception.code, "BUSY_TIMEOUT_INVALID")


# ---------------------------------------------------------------------------------------
# AC-001: durability of the authoritative result across a restart
# ---------------------------------------------------------------------------------------


class RestartIdempotencyTests(DurableStateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.entropy = DeterministicTestEntropySource(ENTROPY_MARKER)
        self.request = DrawRequest(request_id="DBC-RESTART-0001", round_id="RR-DBC-RESTART-01")

    def _store(self):
        return self.open_store(entropy_source=self.entropy)

    def test_a_committed_round_replays_after_close_and_reopen(self) -> None:
        store = self._store()
        self.seed_accounts(store)
        committed = store.submit_round(self.request, settlement=settlement_for)
        self.assertFalse(committed.replayed)
        self.assertEqual(committed.balances, {PLAYER: 900, HOUSE: 100})
        consumed = self.entropy.consumed
        self.assertGreater(consumed, 0)
        store.close()

        reopened = self._store()
        replay = reopened.submit_round(self.request, settlement=settlement_for)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record.to_dict(), committed.record.to_dict())
        self.assertEqual(self.entropy.consumed, consumed, "a replay must not re-consume entropy")
        self.assertEqual(reopened.count("draw_record"), 1)
        self.assertEqual(reopened.count("ledger_transaction"), 1)
        self.assertEqual(reopened.balances(), {HOUSE: 100, PLAYER: 900})

    def test_replay_returns_the_settlement_and_balances_of_the_original_commit(self) -> None:
        store = self._store()
        self.seed_accounts(store)
        committed = store.submit_round(self.request, settlement=settlement_for)
        store.close()
        replay = self._store().submit_round(self.request, settlement=settlement_for)
        self.assertEqual(replay.settlement_transaction_id, committed.settlement_transaction_id)
        self.assertEqual(replay.balances, committed.balances)
        self.assertIn(committed.record.audit_event_ref, replay.audit_event_refs)

    def test_a_round_without_settlement_still_replays_exactly(self) -> None:
        store = self._store()
        committed = store.submit_round(self.request)
        self.assertIsNone(committed.settlement_transaction_id)
        store.close()
        replay = self._store().submit_round(self.request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record.pocket, committed.record.pocket)
        self.assertEqual(self.entropy.consumed, 1)

    def test_a_stored_record_edited_in_place_is_refused_on_replay(self) -> None:
        """A record corrupted behind the immutability trigger is refused, not replayed.

        ``draw_record_is_immutable`` covers ``payload_json``, so this corruption cannot be
        staged without dropping it first. The drop is deliberate and explicit: the property
        under test is that ``verify_draw_record`` re-derives the proof on every replay, which
        only matters once the write-time control has already been defeated. The control itself
        is proved separately by :meth:`test_an_immutable_draw_column_cannot_be_rewritten`, which
        stays in place and is asserted here before anything is dropped.
        """

        store = self._store()
        store.submit_round(self.request)
        store.close()
        payload = json.loads(
            self.raw().execute("SELECT payload_json FROM draw_record").fetchone()["payload_json"]
        )
        payload["pocket"] = (payload["pocket"] + 1) % 37
        edit = (
            "UPDATE draw_record SET payload_json = ? WHERE request_id = ?",
            (json.dumps(payload), self.request.request_id),
        )
        with self.assertRaises(sqlite3.IntegrityError) as guarded:
            self.raw().execute(*edit)
        self.assertIn("immutable", str(guarded.exception))

        corrupting = self.raw()
        corrupting.execute("DROP TRIGGER draw_record_is_immutable")
        corrupting.execute(*edit)
        with self.assertRaises(RngDenied) as caught:
            self._store().submit_round(self.request)
        self.assertEqual(caught.exception.code, "PROOF_INVALID")

    def test_an_immutable_draw_column_cannot_be_rewritten(self) -> None:
        store = self._store()
        store.submit_round(self.request)
        store.close()
        for statement in (
            "UPDATE draw_record SET pocket = 0",
            "UPDATE draw_record SET proof_hash = 'sha256:' || '0'",
            "UPDATE draw_record SET payload_json = '{}'",
            "UPDATE draw_record SET round_id = 'RR-FORGED-01'",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError) as caught:
                self.raw().execute(statement)
            self.assertIn("immutable", str(caught.exception))

    def test_a_void_survives_a_restart(self) -> None:
        store = self._store()
        store.void_round("RR-DBC-VOIDED-01", reason="OPERATOR_VOID")
        store.close()
        reopened = self._store()
        self.assertTrue(reopened.is_round_voided("RR-DBC-VOIDED-01"))
        with self.assertRaises(RngDenied) as caught:
            reopened.submit_round(DrawRequest(request_id="DBC-VOID-0001", round_id="RR-DBC-VOIDED-01"))
        self.assertEqual(caught.exception.code, "ROUND_VOIDED")

    def test_a_second_request_for_a_drawn_round_is_refused_after_restart(self) -> None:
        store = self._store()
        store.submit_round(self.request)
        store.close()
        with self.assertRaises(RngDenied) as caught:
            self._store().submit_round(
                DrawRequest(request_id="DBC-RESTART-0002", round_id=self.request.round_id)
            )
        self.assertEqual(caught.exception.code, "ROUND_ALREADY_DRAWN")


# ---------------------------------------------------------------------------------------
# AC-002, AC-003: durable audit references, append-only storage and tamper evidence
# ---------------------------------------------------------------------------------------


class DurableAuditChainTests(DurableStateTestCase):
    def _committed_store(self):
        store = self.open_store()
        self.seed_accounts(store)
        store.submit_round(
            DrawRequest(request_id="DBC-AUDIT-0001", round_id="RR-DBC-AUDIT-01"), settlement=settlement_for
        )
        return store

    def test_audit_references_are_globally_unique_and_schema_valid(self) -> None:
        store = self._committed_store()
        schema = load_json("audit/audit-event.schema.json")
        events = store.audit_events()
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual(len({event["event_id"] for event in events}), len(events))
        for event in events:
            validate_instance(event, schema)
        references = [row["audit_ref"] for row in self.raw().execute("SELECT audit_ref FROM audit_event")]
        self.assertEqual(len(set(references)), len(references))

    def test_a_second_store_instance_continues_the_sequence_instead_of_restarting_it(self) -> None:
        first = self._committed_store()
        first_ids = [event["event_id"] for event in first.audit_events()]
        first.close()
        second = self.open_store()
        second.submit_round(DrawRequest(request_id="DBC-AUDIT-0002", round_id="RR-DBC-AUDIT-02"))
        second_ids = [event["event_id"] for event in second.audit_events()]
        self.assertEqual(second_ids[: len(first_ids)], first_ids)
        self.assertEqual(len(set(second_ids)), len(second_ids))
        self.assertGreater(len(second_ids), len(first_ids))

    def test_the_chain_verifies_after_a_reload(self) -> None:
        store = self._committed_store()
        store.close()
        reopened = self.open_store()
        self.assertEqual(reopened.verify_chain(), [])
        self.assertEqual(verify_audit_chain(reopened.audit_events()), [])

    def test_a_duplicate_event_id_is_refused_by_the_database(self) -> None:
        store = self._committed_store()
        row = self.raw().execute("SELECT * FROM audit_event ORDER BY event_seq LIMIT 1").fetchone()
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.raw().execute(
                "INSERT INTO audit_event (event_seq, event_id, audit_ref, event_hash, previous_event_hash,"
                " action, round_id, recorded_at, body_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    9001,
                    row["event_id"],
                    "audit://duplicate",
                    "sha256:" + "1" * 64,
                    None,
                    "FORGED",
                    None,
                    FIXED_CLOCK,
                    "{}",
                ),
            )
        self.assertIn("UNIQUE", str(caught.exception))

    def test_audit_events_reject_update_and_delete_at_the_database_level(self) -> None:
        store = self._committed_store()
        for statement in (
            "UPDATE audit_event SET action = 'FORGED' WHERE event_seq = 1",
            "DELETE FROM audit_event WHERE event_seq = 1",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError) as caught:
                self.raw().execute(statement)
            self.assertIn("append-only", str(caught.exception))
        self.assertEqual(store.verify_chain(), [])

    def test_a_body_tampered_behind_the_trigger_is_detected_on_reload(self) -> None:
        """AC-003: corruption that got past the write-time controls is still caught on reload.

        The append-only trigger is dropped *deliberately and explicitly* here. The point is not
        that the trigger can be dropped -- ``test_audit_events_reject_update_and_delete_at_the
        _database_level`` proves it stops an ordinary UPDATE -- but that the reload-time chain
        verification is a second, independent line of defence. Simulating an attacker with
        write access to the file is the only honest way to test it.
        """

        store = self._committed_store()
        store.close()
        connection = self._corruption_connection()
        body = json.loads(connection.execute("SELECT body_json FROM audit_event WHERE event_seq = 1").fetchone()[0])
        body["action"] = "FORGED_ACTION"
        connection.execute("UPDATE audit_event SET body_json = ? WHERE event_seq = 1", (json.dumps(body),))
        problems = self.open_store().verify_chain()
        self.assertTrue(problems)
        self.assertTrue(any("event_hash" in problem for problem in problems))

    def test_a_deleted_event_breaks_the_reloaded_chain_linkage(self) -> None:
        """AC-003: an event removed behind the controls leaves a detectable linkage hole.

        Two controls have to be bypassed to stage this, and both bypasses are stated rather
        than worked around silently: the append-only DELETE trigger, and the foreign key that
        ``draw_record`` and ``ledger_transaction`` hold on ``audit_event(event_seq)``. That the
        foreign key refuses the delete while it is enforced is itself the guarantee, and it is
        asserted below before it is switched off.
        """

        store = self._committed_store()
        store.close()
        with self.assertRaises(sqlite3.IntegrityError) as guarded:
            self.raw().execute("DELETE FROM audit_event WHERE event_seq = 1")
        self.assertIn("append-only", str(guarded.exception))

        connection = self._corruption_connection()
        connection.execute("DELETE FROM audit_event WHERE event_seq = 1")
        problems = self.open_store().verify_chain()
        self.assertTrue(any("previous_event_hash" in problem for problem in problems))

    def _corruption_connection(self) -> sqlite3.Connection:
        """Return a connection with the audit controls deliberately switched off.

        Used only to simulate a file an attacker or a corrupted disk has already reached. The
        drops and the foreign-key pragma are collected in one clearly named helper so no test
        can disable a control by accident, and so the tests that prove those controls hold
        under normal operation stay untouched.
        """

        connection = self.raw()
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TRIGGER audit_event_is_append_only_update")
        connection.execute("DROP TRIGGER audit_event_is_append_only_delete")
        return connection

    def test_a_recomputed_hash_matches_the_stored_body(self) -> None:
        store = self._committed_store()
        for event in store.audit_events():
            self.assertEqual(event["event_hash"], compute_event_hash(event))
            self.assertIs(event["contains_secret"], False)

    def test_a_denied_submission_is_recorded_as_its_own_audit_event(self) -> None:
        store = self._committed_store()
        before = len(store.audit_events())
        with self.assertRaises(RngDenied):
            store.submit_round(DrawRequest(request_id="DBC-AUDIT-0003", round_id="RR-DBC-AUDIT-01"))
        actions = [event["action"] for event in store.audit_events()]
        self.assertGreater(len(actions), before)
        self.assertIn("ROULETTE_DURABLE_SUBMIT_DENIED", actions)
        self.assertEqual(store.verify_chain(), [])


# ---------------------------------------------------------------------------------------
# AC-004: integer minimum units, unique idempotency keys and balanced entries
# ---------------------------------------------------------------------------------------


class LedgerConstraintTests(DurableStateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = self.open_store()
        self.seed_accounts(self.store)
        self.committed = self.store.submit_round(
            DrawRequest(request_id="DBC-LEDGER-0001", round_id="RR-DBC-LEDGER-01"), settlement=settlement_for
        )

    def _insert_entries(self, connection, transaction_id: str, amounts: list[int]) -> None:
        accounts = [(PLAYER, "PLAYER"), (HOUSE, "HOUSE_BANKROLL")]
        for index, amount in enumerate(amounts):
            account_id, account_type = accounts[index % len(accounts)]
            connection.execute(
                "INSERT INTO ledger_entry (transaction_id, account_id, account_type, amount_units)"
                " VALUES (?, ?, ?, ?)",
                (transaction_id, account_id, account_type, amount),
            )

    def _insert_transaction(self, connection, transaction_id: str, key: str) -> None:
        connection.execute(
            "INSERT INTO ledger_transaction (transaction_id, idempotency_key, round_id, transaction_type,"
            " currency, request_fingerprint, audit_event_seq, payload_json, created_at)"
            " VALUES (?, ?, 'RR-DBC-RAW-01', 'ROUND_SETTLEMENT', 'VIRTUAL_CHIP', 'sha256:x', 1, '{}', ?)",
            (transaction_id, key, FIXED_CLOCK),
        )

    def test_a_duplicate_idempotency_key_is_refused_by_a_unique_constraint(self) -> None:
        connection = self.raw()
        stored_key = connection.execute("SELECT idempotency_key FROM ledger_transaction").fetchone()[0]
        connection.execute("BEGIN IMMEDIATE")
        self._insert_entries(connection, "LT-RAWDUP-0001", [-5, 5])
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self._insert_transaction(connection, "LT-RAWDUP-0001", stored_key)
        connection.execute("ROLLBACK")
        self.assertIn("idempotency_key", str(caught.exception))

    def test_unbalanced_entries_are_refused_by_the_database(self) -> None:
        connection = self.raw()
        connection.execute("BEGIN IMMEDIATE")
        self._insert_entries(connection, "LT-RAWUNBAL-01", [-5, 7])
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self._insert_transaction(connection, "LT-RAWUNBAL-01", "idem:raw:unbalanced")
        connection.execute("ROLLBACK")
        self.assertIn("sum to zero", str(caught.exception))

    def test_a_single_entry_transaction_is_refused_by_the_database(self) -> None:
        connection = self.raw()
        connection.execute("BEGIN IMMEDIATE")
        self._insert_entries(connection, "LT-RAWSINGLE-1", [0 - 0 + 5])
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self._insert_transaction(connection, "LT-RAWSINGLE-1", "idem:raw:single")
        connection.execute("ROLLBACK")
        self.assertIn("two entries", str(caught.exception))

    def test_a_fractional_amount_is_refused_by_a_typeof_check(self) -> None:
        connection = self.raw()
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self._insert_entries(connection, "LT-RAWFLOAT-01", [-5.5])
        self.assertIn("typeof(amount_units)", str(caught.exception))

    def test_a_zero_amount_entry_is_refused(self) -> None:
        connection = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_entries(connection, "LT-RAWZERO-01", [0])

    def test_an_entry_cannot_be_added_after_its_transaction_is_posted(self) -> None:
        connection = self.raw()
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self._insert_entries(connection, self.committed.settlement_transaction_id, [-5])
        self.assertIn("cannot gain further entries", str(caught.exception))

    def test_orphan_entries_fail_the_deferred_foreign_key_at_commit(self) -> None:
        connection = self.raw()
        connection.execute("BEGIN IMMEDIATE")
        self._insert_entries(connection, "LT-RAWORPHAN-1", [-5, 5])
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            connection.execute("COMMIT")
        self.assertIn("FOREIGN KEY", str(caught.exception))
        connection.execute("ROLLBACK")

    def test_posted_ledger_rows_are_immutable(self) -> None:
        for statement in (
            "UPDATE ledger_transaction SET round_id = 'RR-FORGED-01'",
            "DELETE FROM ledger_transaction",
            "UPDATE ledger_entry SET amount_units = 1",
            "DELETE FROM ledger_entry",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.raw().execute(statement)

    def test_a_fractional_account_balance_is_refused(self) -> None:
        connection = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO account (account_id, account_type, balance_units) VALUES ('player:frac', 'PLAYER', 1.5)"
            )

    def test_a_negative_player_balance_is_refused_at_the_database_and_the_boundary(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.raw().execute(
                "INSERT INTO account (account_id, account_type, balance_units)"
                " VALUES ('player:short', 'PLAYER', -1)"
            )
        with self.assertRaises(DurableStateError) as caught:
            self.store.register_account("player:short", "PLAYER", -1)
        self.assertEqual(caught.exception.code, "BALANCE_INVALID")

    def test_a_settlement_that_would_overdraw_a_player_is_refused_and_rolls_back(self) -> None:
        with self.assertRaises(DurableStateError) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-LEDGER-0002", round_id="RR-DBC-LEDGER-02"),
                settlement=lambda record: settlement_for(record, index=2, stake=100_000),
            )
        self.assertEqual(caught.exception.code, "LEDGER_REJECTED")
        self.assertEqual(self.store.count("draw_record"), 1)
        self.assertEqual(self.store.balances(), {HOUSE: 100, PLAYER: 900})

    def test_an_unknown_account_is_never_opened_implicitly(self) -> None:
        def settlement(record):
            body = settlement_for(record, index=3)
            body["entries"][0]["account_id"] = "player:absent"
            return body

        with self.assertRaises(DurableStateError) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-LEDGER-0003", round_id="RR-DBC-LEDGER-03"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "ACCOUNT_UNKNOWN")
        self.assertNotIn("player:absent", self.store.balances())

    def test_a_mislabelled_account_type_is_refused(self) -> None:
        def settlement(record):
            body = settlement_for(record, index=4)
            body["entries"][0]["account_type"] = "SYSTEM_CLEARING"
            return body

        with self.assertRaises(DurableStateError) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-LEDGER-0004", round_id="RR-DBC-LEDGER-04"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "ACCOUNT_TYPE_MISMATCH")

    def test_the_stored_transaction_satisfies_the_published_ledger_schema(self) -> None:
        stored = self.store.ledger_transaction(self.committed.settlement_transaction_id)
        validate_instance(stored, load_json("games/roulette/ledger-transaction.schema.json"))
        self.assertTrue(all(isinstance(entry["amount_units"], int) for entry in stored["entries"]))
        self.assertEqual(sum(entry["amount_units"] for entry in stored["entries"]), 0)

    def test_re_registering_an_account_with_the_same_values_is_a_no_op(self) -> None:
        """Start-up is idempotent only while the committed balance still matches the opening."""

        self.store.register_account("player:idem", "PLAYER", 500)
        self.store.register_account("player:idem", "PLAYER", 500)
        self.assertEqual(self.store.balances(["player:idem"]), {"player:idem": 500})

    def test_re_registering_an_account_with_different_values_is_refused(self) -> None:
        self.store.register_account("player:idem", "PLAYER", 500)
        with self.assertRaises(DurableStateError) as balance:
            self.store.register_account("player:idem", "PLAYER", 42)
        self.assertEqual(balance.exception.code, "ACCOUNT_ALREADY_REGISTERED")
        with self.assertRaises(DurableStateError) as kind:
            self.store.register_account("player:idem", "SYSTEM_CLEARING", 500)
        self.assertEqual(kind.exception.code, "ACCOUNT_TYPE_MISMATCH")
        self.assertEqual(self.store.balances(["player:idem"]), {"player:idem": 500})

    def test_re_registering_a_settled_account_at_its_opening_balance_is_refused(self) -> None:
        """The comparison is against the *committed* balance, not the original opening one.

        ``HOUSE`` opened at 0 and holds 100 after the settlement in ``setUp``. Re-running the
        original start-up call therefore has to fail: accepting it as a no-op would tell the
        caller its account is at 0 while the store still holds 100, and silently resetting it
        would destroy a committed balance. Failing closed is the only answer that leaves the
        two views of the account in agreement.
        """

        self.assertEqual(self.store.balances([HOUSE]), {HOUSE: 100})
        with self.assertRaises(DurableStateError) as caught:
            self.store.register_account(HOUSE, "HOUSE_BANKROLL", 0)
        self.assertEqual(caught.exception.code, "ACCOUNT_ALREADY_REGISTERED")
        self.assertEqual(self.store.balances([HOUSE]), {HOUSE: 100})


# ---------------------------------------------------------------------------------------
# AC-005: one transaction for the draw, the settlement and the audit events
# ---------------------------------------------------------------------------------------


class AtomicCommitTests(DurableStateTestCase):
    def _submit_with_fault(self, stage: str, path: pathlib.Path):
        def hook(reached: str) -> None:
            if reached == stage:
                raise RuntimeError(f"injected fault at {stage}")

        store = self.open_store(path=path, fault_hook=hook)
        self.seed_accounts(store)
        outcome: Exception | None = None
        try:
            store.submit_round(
                DrawRequest(request_id="DBC-FAULT-0001", round_id="RR-DBC-FAULT-01"), settlement=settlement_for
            )
        except Exception as exc:  # noqa: BLE001 - the injected fault is the subject
            outcome = exc
        store.close()
        return outcome

    def test_every_pre_commit_fault_stage_rolls_all_three_writes_back(self) -> None:
        for stage in FAULT_STAGES:
            if stage == "after_commit":
                continue
            with self.subTest(stage=stage):
                path = self.workspace / f"fault-{stage}.sqlite3"
                outcome = self._submit_with_fault(stage, path)
                self.assertIsInstance(outcome, RuntimeError)
                reopened = self.open_store(path=path)
                self.assertEqual(reopened.count("draw_record"), 0)
                self.assertEqual(reopened.count("ledger_transaction"), 0)
                self.assertEqual(reopened.count("ledger_entry"), 0)
                self.assertEqual(reopened.balances(), {HOUSE: 0, PLAYER: 1000})
                actions = [event["action"] for event in reopened.audit_events()]
                self.assertNotIn("ROULETTE_RNG_DRAW", actions)
                self.assertNotIn("ROULETTE_ROUND_SETTLED", actions)
                self.assertEqual(reopened.verify_chain(), [])
                reopened.close()

    def test_a_fault_after_the_sample_voids_the_round_rather_than_leaving_it_drawable(self) -> None:
        for stage in ("after_draw", "after_ledger", "before_commit"):
            with self.subTest(stage=stage):
                path = self.workspace / f"void-{stage}.sqlite3"
                self._submit_with_fault(stage, path)
                reopened = self.open_store(path=path)
                self.assertTrue(reopened.is_round_voided("RR-DBC-FAULT-01"))
                self.assertIn(
                    "ROULETTE_ROUND_VOIDED", [event["action"] for event in reopened.audit_events()]
                )
                with self.assertRaises(RngDenied) as caught:
                    reopened.submit_round(
                        DrawRequest(request_id="DBC-FAULT-0002", round_id="RR-DBC-FAULT-01")
                    )
                self.assertEqual(caught.exception.code, "ROUND_VOIDED")
                reopened.close()

    def test_a_fault_before_the_sample_leaves_the_round_untouched(self) -> None:
        path = self.workspace / "fault-after_begin.sqlite3"
        self._submit_with_fault("after_begin", path)
        reopened = self.open_store(path=path)
        self.assertFalse(reopened.is_round_voided("RR-DBC-FAULT-01"))
        self.assertEqual(reopened.count("round_void"), 0)
        self.assertEqual(reopened.count("audit_event"), 0)
        reopened.close()

    def test_a_fault_after_the_commit_leaves_the_committed_result_intact(self) -> None:
        path = self.workspace / "fault-after_commit.sqlite3"
        outcome = self._submit_with_fault("after_commit", path)
        self.assertIsInstance(outcome, RuntimeError)
        reopened = self.open_store(path=path)
        self.assertEqual(reopened.count("draw_record"), 1)
        self.assertEqual(reopened.count("ledger_transaction"), 1)
        self.assertEqual(reopened.count("ledger_entry"), 2)
        self.assertEqual(reopened.balances(), {HOUSE: 100, PLAYER: 900})
        self.assertFalse(reopened.is_round_voided("RR-DBC-FAULT-01"))
        self.assertEqual(reopened.verify_chain(), [])
        reopened.close()

    def test_a_settlement_failure_discards_the_draw_and_its_audit_event(self) -> None:
        store = self.open_store()
        self.seed_accounts(store)
        with self.assertRaises(DurableStateError) as caught:
            store.submit_round(
                DrawRequest(request_id="DBC-FAULT-0003", round_id="RR-DBC-FAULT-03"),
                settlement=lambda record: {"schema_version": "1.0.0"},
            )
        self.assertEqual(caught.exception.code, "TRANSACTION_INVALID")
        self.assertEqual(store.count("draw_record"), 0)
        self.assertNotIn("ROULETTE_RNG_DRAW", [event["action"] for event in store.audit_events()])
        self.assertEqual(store.verify_chain(), [])

    def test_the_declared_fault_stages_are_the_stages_the_store_reaches(self) -> None:
        reached: list[str] = []
        store = self.open_store(fault_hook=reached.append)
        self.seed_accounts(store)
        store.submit_round(
            DrawRequest(request_id="DBC-FAULT-0004", round_id="RR-DBC-FAULT-04"), settlement=settlement_for
        )
        self.assertEqual(reached, list(FAULT_STAGES))


# ---------------------------------------------------------------------------------------
# AC-006: concurrency proved by real threads on separate connections
# ---------------------------------------------------------------------------------------


class ConcurrentSubmissionTests(DurableStateTestCase):
    THREADS = 8

    def _race(self, worker) -> tuple[list, list]:
        """Run ``worker`` on :attr:`THREADS` real threads released by a single barrier."""

        barrier = threading.Barrier(self.THREADS)
        results: list = [None] * self.THREADS
        failures: list = [None] * self.THREADS

        def run(index: int) -> None:
            try:
                barrier.wait(timeout=30)
                results[index] = worker(index)
            except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
                failures[index] = exc

        threads = [threading.Thread(target=run, args=(index,)) for index in range(self.THREADS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            self.assertFalse(thread.is_alive(), "a concurrent submission never finished")
        return results, [item for item in failures if item is not None]

    def test_separate_connections_commit_exactly_one_result_and_one_settlement(self) -> None:
        store = self.open_store(entropy_source=OsCsprngEntropySource(), environment=RngEnvironment.PRODUCTION)
        self.seed_accounts(store)
        request = DrawRequest(request_id="DBC-RACE-0001", round_id="RR-DBC-RACE-01")

        def worker(_: int):
            try:
                return store.submit_round(request, settlement=settlement_for)
            finally:
                # Each thread owns its own connection; releasing it here is what makes the
                # database file closeable when the race ends.
                store.release_thread_connection()

        results, failures = self._race(worker)
        self.assertEqual(failures, [])
        self.assertTrue(all(isinstance(item, CommittedRound) for item in results))
        self.assertEqual(len({item.record.to_dict()["proof_hash"] for item in results}), 1)
        self.assertEqual(len({item.record.pocket for item in results}), 1)
        self.assertEqual(sum(1 for item in results if not item.replayed), 1)
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)
        self.assertEqual(store.count("ledger_entry"), 2)
        self.assertEqual(store.balances(), {HOUSE: 100, PLAYER: 900})
        self.assertEqual(store.verify_chain(), [])

    def test_separate_store_instances_over_one_file_commit_exactly_one_result(self) -> None:
        setup = self.open_store()
        self.seed_accounts(setup)
        setup.close()
        request = DrawRequest(request_id="DBC-RACE-0002", round_id="RR-DBC-RACE-02")
        sources = [DeterministicTestEntropySource(bytes([index + 1])) for index in range(self.THREADS)]

        def worker(index: int):
            store = DurableRoundStore(
                self.database,
                namespace="DBCT",
                entropy_source=sources[index],
                environment=RngEnvironment.NON_PRODUCTION,
                clock=lambda: FIXED_CLOCK,
            )
            try:
                return store.submit_round(request, settlement=settlement_for)
            finally:
                store.close()

        results, failures = self._race(worker)
        self.assertEqual(failures, [])
        pockets = {item.record.pocket for item in results}
        self.assertEqual(len(pockets), 1)
        # Exactly one entropy source was read: the winner's. Everyone else replayed.
        drawing = [index for index, source in enumerate(sources) if source.consumed > 0]
        self.assertEqual(len(drawing), 1)
        self.assertEqual(pockets, {(drawing[0] + 1) % 37})
        self.assertEqual(sum(1 for item in results if not item.replayed), 1)

        audit = self.open_store()
        self.assertEqual(audit.count("draw_record"), 1)
        self.assertEqual(audit.count("ledger_transaction"), 1)
        self.assertEqual(audit.balances(), {HOUSE: 100, PLAYER: 900})
        self.assertEqual(audit.verify_chain(), [])

    def test_concurrent_distinct_rounds_all_commit_with_one_consistent_balance_delta(self) -> None:
        store = self.open_store(entropy_source=OsCsprngEntropySource(), environment=RngEnvironment.PRODUCTION)
        self.seed_accounts(store)

        def worker(index: int):
            try:
                return store.submit_round(
                    DrawRequest(request_id=f"DBC-RACE-01{index:02d}", round_id=f"RR-DBC-RACEN-{index:02d}"),
                    settlement=lambda record: settlement_for(record, index=index + 10, stake=10),
                )
            finally:
                store.release_thread_connection()

        results, failures = self._race(worker)
        self.assertEqual(failures, [])
        self.assertEqual(sum(1 for item in results if not item.replayed), self.THREADS)
        self.assertEqual(store.count("draw_record"), self.THREADS)
        self.assertEqual(store.count("ledger_transaction"), self.THREADS)
        self.assertEqual(store.balances(), {HOUSE: 10 * self.THREADS, PLAYER: 1000 - 10 * self.THREADS})
        self.assertEqual(store.verify_chain(), [])
        events = store.audit_events()
        self.assertEqual(len({event["event_id"] for event in events}), len(events))

    def test_a_closed_store_refuses_further_work(self) -> None:
        store = self.open_store()
        store.close()
        with self.assertRaises(DurableStateError) as caught:
            store.count("draw_record")
        self.assertEqual(caught.exception.code, "STORE_CLOSED")


# ---------------------------------------------------------------------------------------
# AC-007: a reused identifier with a different payload fails closed
# ---------------------------------------------------------------------------------------


class PayloadBindingTests(DurableStateTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = self.open_store()
        self.seed_accounts(self.store)
        self.request = DrawRequest(request_id="DBC-BIND-0001", round_id="RR-DBC-BIND-01")
        self.committed = self.store.submit_round(self.request, settlement=settlement_for)

    def test_a_reused_request_id_with_a_different_round_is_refused(self) -> None:
        with self.assertRaises(RngDenied) as caught:
            self.store.submit_round(DrawRequest(request_id=self.request.request_id, round_id="RR-DBC-BIND-99"))
        self.assertEqual(caught.exception.code, "DUPLICATE_REQUEST_CONFLICT")

    def test_a_reused_request_id_with_a_different_draw_index_is_refused(self) -> None:
        with self.assertRaises(RngDenied) as caught:
            self.store.submit_round(
                DrawRequest(request_id=self.request.request_id, round_id=self.request.round_id, draw_index=4)
            )
        self.assertEqual(caught.exception.code, "DUPLICATE_REQUEST_CONFLICT")

    def test_a_conflicting_request_never_returns_the_unrelated_prior_result(self) -> None:
        try:
            self.store.submit_round(DrawRequest(request_id=self.request.request_id, round_id="RR-DBC-BIND-98"))
        except RngDenied:
            pass
        self.assertEqual(self.store.count("draw_record"), 1)
        self.assertEqual(self.store.balances(), {HOUSE: 100, PLAYER: 900})

    def test_a_reused_idempotency_key_with_a_different_payload_is_refused(self) -> None:
        def settlement(record):
            body = settlement_for(record, index=2)
            body["idempotency_key"] = f"idem:{self.request.round_id}:settlement"
            return body

        with self.assertRaises(LedgerConflict) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-BIND-0002", round_id="RR-DBC-BIND-02"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "IDEMPOTENCY_KEY_CONFLICT")
        self.assertEqual(self.store.count("ledger_transaction"), 1)
        self.assertEqual(self.store.balances(), {HOUSE: 100, PLAYER: 900})

    def test_a_caller_supplied_audit_reference_is_refused(self) -> None:
        def settlement(record):
            body = settlement_for(record, index=3)
            body["audit_event_ref"] = "audit://AE-FORGED-0001"
            return body

        with self.assertRaises(DurableStateError) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-BIND-0003", round_id="RR-DBC-BIND-03"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "SETTLEMENT_AUDIT_REF_DENIED")

    def test_a_settlement_for_another_round_is_refused(self) -> None:
        def settlement(record):
            body = settlement_for(record, index=4)
            body["round_id"] = "RR-DBC-BIND-77"
            return body

        with self.assertRaises(DurableStateError) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-BIND-0004", round_id="RR-DBC-BIND-04"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "SETTLEMENT_ROUND_MISMATCH")

    def test_an_unknown_transaction_field_is_refused(self) -> None:
        def settlement(record):
            body = settlement_for(record, index=5)
            body["client_result"] = 17
            return body

        with self.assertRaises(DurableStateError) as caught:
            self.store.submit_round(
                DrawRequest(request_id="DBC-BIND-0005", round_id="RR-DBC-BIND-05"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "TRANSACTION_INVALID")

    def test_a_malformed_request_is_refused_before_any_write(self) -> None:
        with self.assertRaises(RngDenied) as caught:
            self.store.submit_round(DrawRequest(request_id="short", round_id="RR-DBC-BIND-06"))
        self.assertEqual(caught.exception.code, "REQUEST_ID_INVALID")
        with self.assertRaises(RngDenied) as kind:
            self.store.submit_round({"request_id": "DBC-BIND-0006"})  # type: ignore[arg-type]
        self.assertEqual(kind.exception.code, "REQUEST_INVALID")


# ---------------------------------------------------------------------------------------
# AC-010: entropy, seeds, secrets, floats and client authority never reach storage
# ---------------------------------------------------------------------------------------


class StorageHygieneTests(DurableStateTestCase):
    def test_entropy_bytes_never_reach_the_database_file(self) -> None:
        store = self.open_store()
        self.seed_accounts(store)
        store.submit_round(
            DrawRequest(request_id="DBC-HYG-0001", round_id="RR-DBC-HYG-01"), settlement=settlement_for
        )
        store.close()
        contents = self.database.read_bytes()
        self.assertNotIn(ENTROPY_MARKER, contents)
        for token in (b"seed_value", b"entropy_bytes", b"random_bytes", b"rejection_attempts"):
            self.assertNotIn(token, contents)

    def test_stored_payloads_carry_no_prohibited_field(self) -> None:
        store = self.open_store()
        self.seed_accounts(store)
        committed = store.submit_round(
            DrawRequest(request_id="DBC-HYG-0002", round_id="RR-DBC-HYG-02"), settlement=settlement_for
        )
        payloads = [committed.record.to_dict(), store.ledger_transaction(committed.settlement_transaction_id)]
        payloads.extend(store.audit_events())
        for payload in payloads:
            self.assertEqual(prohibited_fields(payload), [])

    def test_the_prohibited_field_list_extends_the_rng_boundary_list(self) -> None:
        self.assertTrue(set(PROHIBITED_RECORD_FIELDS) <= set(PROHIBITED_STORAGE_FIELDS))
        for name in ("token", "password", "secret", "client_balance", "client_result"):
            self.assertIn(name, PROHIBITED_STORAGE_FIELDS)

    def test_prohibited_fields_matches_keys_and_not_the_required_entropy_reference(self) -> None:
        # ``rng-entropy://`` names the entropy authority and is required by the RNG contract.
        # A scan that flagged it would be a scan somebody eventually turns off.
        self.assertEqual(prohibited_fields({"resource_refs": ["rng-entropy://entropy-ref://os-csprng/X"]}), [])
        self.assertEqual(prohibited_fields({"seed_reference": "entropy-ref://os-csprng"}), [])
        self.assertEqual(prohibited_fields({"nested": [{"seed": "..."}]}), ["seed"])
        self.assertEqual(prohibited_fields({"entropy_bytes": "..."}), ["entropy_bytes"])

    def test_a_settlement_carrying_a_float_amount_is_refused(self) -> None:
        store = self.open_store()
        self.seed_accounts(store)

        def settlement(record):
            body = settlement_for(record, index=6)
            body["entries"][0]["amount_units"] = -100.0
            return body

        with self.assertRaises(DurableStateError) as caught:
            store.submit_round(
                DrawRequest(request_id="DBC-HYG-0003", round_id="RR-DBC-HYG-03"), settlement=settlement
            )
        self.assertEqual(caught.exception.code, "TRANSACTION_INVALID")
        self.assertEqual(store.count("ledger_entry"), 0)

    def test_a_settlement_matching_a_credential_pattern_is_refused(self) -> None:
        store = self.open_store()
        self.seed_accounts(store)

        def settlement(record):
            body = settlement_for(record, index=7)
            # A credential-shaped value smuggled through a schema-valid string field.
            body["transaction_id"] = "LT-" + "A" * 40
            body["idempotency_key"] = "idem:api_key=" + "B" * 32
            return body

        with self.assertRaises(DurableStateError) as caught:
            store.submit_round(
                DrawRequest(request_id="DBC-HYG-0004", round_id="RR-DBC-HYG-04"), settlement=settlement
            )
        self.assertIn(caught.exception.code, {"SECRET_MATERIAL_DENIED", "TRANSACTION_INVALID"})
        self.assertEqual(store.count("ledger_transaction"), 0)

    def test_the_module_reaches_no_network(self) -> None:
        tree = ast.parse((ROOT / "studio_core/durable_state.py").read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(f"{'.' * node.level}{node.module or ''}")
        forbidden = {"socket", "ssl", "http", "http.client", "urllib", "urllib.request", "requests", "asyncio"}
        self.assertEqual(imported & forbidden, set())

    def test_no_database_file_is_written_into_the_repository(self) -> None:
        strays = [
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file() and path.suffix in {".sqlite3", ".sqlite", ".db"}
        ]
        self.assertEqual(strays, [])


class AuditEventClaimTests(DurableStateTestCase):
    """The durable sink refuses an event that does not declare itself secret-free."""

    def test_an_event_without_contains_secret_false_is_refused(self) -> None:
        from studio_core.durable_state import _DurableAuditSink

        store = self.open_store()
        connection = self.raw()
        connection.execute("BEGIN IMMEDIATE")
        sink = _DurableAuditSink(connection, "DBCT", clock=lambda: FIXED_CLOCK)
        with self.assertRaises(DurableStateError) as caught:
            sink.append({"action": "X", "contains_secret": True})
        connection.execute("ROLLBACK")
        self.assertEqual(caught.exception.code, "AUDIT_EVENT_DENIED")


# ---------------------------------------------------------------------------------------
# AC-011, AC-013: validator integration, evidence records and carried-forward scope
# ---------------------------------------------------------------------------------------


class ValidatorIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = pathlib.Path(tempfile.mkdtemp(prefix="r2dbc-validator-"))
        self.addCleanup(shutil.rmtree, self.workspace, True)

    def _copy_inputs(self) -> pathlib.Path:
        """Materialise the validator's inputs in an isolated tree."""

        for relative in R2_DBC_INPUT_FILES:
            target = self.workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        return self.workspace

    def test_the_repository_passes_the_durable_state_step(self) -> None:
        result = validate_r2_durable_state()
        self.assertEqual(result["contract"]["contract_id"], "DURABLE-STATE-R2")
        self.assertTrue(result["events"])

    def test_a_copy_of_the_repository_inputs_also_passes(self) -> None:
        validate_r2_durable_state(self._copy_inputs())

    def _expect_failure(self, mutate) -> str:
        base = self._copy_inputs()
        mutate(base)
        with self.assertRaises(BaselineValidationError) as caught:
            validate_r2_durable_state(base)
        return str(caught.exception)

    def test_a_contract_that_misstates_the_transaction_mode_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "games/roulette/durable-state-contract.yaml"
            path.write_text(
                path.read_text(encoding="utf-8").replace("transaction_mode: IMMEDIATE", "transaction_mode: DEFERRED"),
                encoding="utf-8",
            )

        self.assertIn("storage declaration", self._expect_failure(mutate))

    def test_a_contract_that_misstates_the_durability_pragma_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "games/roulette/durable-state-contract.yaml"
            path.write_text(
                path.read_text(encoding="utf-8").replace("synchronous: full", "synchronous: normal"),
                encoding="utf-8",
            )

        self.assertIn("storage declaration", self._expect_failure(mutate))

    def test_a_contract_that_drops_a_carried_forward_unit_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "games/roulette/durable-state-contract.yaml"
            path.write_text(
                path.read_text(encoding="utf-8").replace("R2-SEC-0005", "SOMETHING-ELSE"), encoding="utf-8"
            )

        self.assertIn("out_of_scope", self._expect_failure(mutate))

    def test_a_drifted_sql_schema_file_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "games/roulette/durable-state-schema.sql"
            path.write_text(path.read_text(encoding="utf-8") + "\nCREATE TABLE drift (x);\n", encoding="utf-8")

        self.assertIn("drifted", self._expect_failure(mutate))

    def test_a_modified_rng_boundary_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "studio_core/rng.py"
            path.write_text(path.read_text(encoding="utf-8") + "\n# weakened\n", encoding="utf-8")

        self.assertIn("RNG boundary was modified", self._expect_failure(mutate))

    def test_a_broken_audit_chain_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "audit/events/R2-DBC-0002-events.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["events"][1]["action"] = "FORGED_ACTION"
            path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")

        self.assertIn("audit chain is broken", self._expect_failure(mutate))

    def test_a_missing_required_audit_action_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "audit/events/R2-DBC-0002-events.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["events"] = document["events"][:1]
            path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")

        self.assertIn("audit record is incomplete", self._expect_failure(mutate))

    def test_an_artifact_claiming_a_human_approval_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "artifacts/R2-DBC-0002-artifact.json"
            artifact = json.loads(path.read_text(encoding="utf-8"))
            artifact["specification"]["human_approved"] = True
            path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")

        self.assertIn("human approval", self._expect_failure(mutate))

    def test_a_stale_artifact_component_hash_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "artifacts/R2-DBC-0002-artifact.json"
            artifact = json.loads(path.read_text(encoding="utf-8"))
            artifact["specification"]["sql_schema_hash"] = "sha256:" + "0" * 64
            path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")

        self.assertIn("sql_schema_hash", self._expect_failure(mutate))

    def test_a_checked_human_gate_item_in_the_report_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "docs/approvals/R2-DBC-0002-validation-report.md"
            text = path.read_text(encoding="utf-8")
            head, tail = text.split("## 9. 인간 게이트", 1)
            path.write_text(head + "## 9. 인간 게이트" + tail.replace("- [ ]", "- [x]", 1), encoding="utf-8")

        self.assertIn("human sign-off", self._expect_failure(mutate))

    def test_a_status_page_that_drops_a_deferred_unit_is_rejected(self) -> None:
        def mutate(base: pathlib.Path) -> None:
            path = base / "docs/status/R2-STATUS.md"
            path.write_text(
                path.read_text(encoding="utf-8").replace("R2-LOAD-0004", "REMOVED"), encoding="utf-8"
            )

        self.assertIn("carried forward", self._expect_failure(mutate))

    def test_the_required_audit_actions_are_all_present_in_the_record(self) -> None:
        document = load_json("audit/events/R2-DBC-0002-events.json")
        actions = {event["action"] for event in document["events"]}
        self.assertTrue(R2_DBC_REQUIRED_AUDIT_ACTIONS <= actions)
        self.assertEqual(verify_audit_chain(document["events"]), [])

    def test_the_artifact_records_the_canonical_module_hash(self) -> None:
        artifact = load_json("artifacts/R2-DBC-0002-artifact.json")
        self.assertEqual(artifact["uri"], "repo://studio_core/durable_state.py")
        self.assertEqual(
            artifact["content_hash"],
            hash_file(ROOT / "studio_core/durable_state.py", label="studio_core/durable_state.py"),
        )
        self.assertEqual(artifact["status"], "SUBMITTED")
        self.assertIsNone(artifact["approved_at"])

    def test_the_handoff_records_no_approval_it_did_not_receive(self) -> None:
        handoff = load_json("handoffs/R2-DBC-0002-handoff.json")
        self.assertEqual(handoff["readiness"], "READY_FOR_REVIEW")
        self.assertNotEqual(handoff["from_agent_id"], handoff["to_agent_id"])
        results = {item["check"]: item["result"] for item in handoff["verification_evidence"]}
        self.assertEqual(results["python scripts/validate_baseline.py"], "PASS")
        self.assertEqual(results["python -m unittest discover -s tests -v"], "PASS")
        self.assertTrue(any(item["result"] == "NOT_RUN" for item in handoff["verification_evidence"]))

    def test_the_scope_boundary_is_recorded_in_the_carried_forward_documents(self) -> None:
        status = (ROOT / "docs/status/R2-STATUS.md").read_text(encoding="utf-8")
        follow_ups = (ROOT / "docs/operations/R2-followup-units.md").read_text(encoding="utf-8")
        for unit in ("R2-NET-0003", "R2-LOAD-0004", "R2-SEC-0005"):
            self.assertIn(unit, status)
            self.assertIn(unit, follow_ups)
        contract = load_yaml("games/roulette/durable-state-contract.yaml")
        joined = " ".join(contract["out_of_scope"])
        for phrase in ("네트워크", "부하", "침투", "운영 배포"):
            self.assertIn(phrase, joined)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
