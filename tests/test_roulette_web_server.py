"""R4-UI-0006 Phase B1: server and domain tests for the roulette playable slice.

The suite is organised by the question each group answers, not by the module it touches:

* **Domain** -- does the table decide the things only it may decide, and refuse the rest
  without moving any state?
* **Idempotency** -- does a repeated ``request_id`` cost no entropy and return the original
  answer, and does a reused one with different parameters fail closed?
* **Concurrency** -- do two callers racing the same submission produce exactly one draw?
* **Restart** -- does a new process over the same database see the committed balances and
  the stored result order, and refuse a request identifier that was already served?
* **Transport** -- over a real loopback socket, does the server refuse malformed, oversized,
  unknown, traversing and client-authoritative requests without leaking anything internal?

The HTTP groups talk to a genuine ``ThreadingHTTPServer`` on port 0 rather than to a
handler stub, because most of what is being asserted -- status codes, headers, body framing
and the traversal defence -- only exists once a real request has been parsed.
"""

from __future__ import annotations

import http.client
import json
import pathlib
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import (  # noqa: E402
    ALLOWED_STATIC_SUFFIXES,
    LOOPBACK_HOSTS,
    MAX_BODY_BYTES,
    ROUTES,
    SECURITY_HEADERS,
    STATIC_ROOT,
    create_server,
    open_table,
    serve_in_background,
)
from apps.roulette_web.table import (  # noqa: E402
    CLIENT_AUTHORITY_FIELDS,
    COLOR_LABELS,
    ESCROW_ACCOUNT,
    HOUSE_ACCOUNT,
    NOTICE,
    PLAYER_ACCOUNT,
    TERMINAL_PHASES,
    TRANSITIONS,
    RoundPhase,
    RouletteTable,
    TableConfig,
    TableError,
    default_database_path,
    prohibited_client_fields,
)
from studio_core.config import ROOT, load_yaml  # noqa: E402
from studio_core.rng import DeterministicTestEntropySource, RngEnvironment  # noqa: E402
from studio_core.roulette import load_r1_rules, settle_bet  # noqa: E402

FIXED_CLOCK = "2026-09-01T00:00:00Z"
ENTROPY_STREAM = bytes([7, 11, 13, 17, 19, 23])

STRAIGHT_ZERO = {"type": "straight", "selections": [0], "stake_units": 10}
RED = {"type": "red", "selections": [], "stake_units": 25}


def find_floats(value, path="$"):
    """Return the JSON paths of every float inside ``value``.

    Currency is integer minimum units throughout this system, so the useful assertion is
    not "the balance is an int" but "no float exists anywhere in this payload" -- a check
    that keeps working when a new field is added.
    """

    found = []
    if isinstance(value, float):
        found.append(path)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(find_floats(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(find_floats(item, f"{path}[{index}]"))
    return found


def _executable_surface(source: str) -> list[str]:
    """Return every identifier and non-docstring string literal in ``source``.

    Comments never reach the parser at all, and docstrings are dropped explicitly, so what
    is left is the part of the file that can actually name a feature: attributes, function
    and class names, arguments, and the literals the program emits.
    """

    import ast

    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))

    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            names.append(node.value)
        elif isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            names.append(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.extend(alias.name for alias in node.names)
    return names


class SliceTestCase(unittest.TestCase):
    """Gives every test an isolated database directory and a deterministic entropy stream."""

    def setUp(self) -> None:
        self.workspace = pathlib.Path(tempfile.mkdtemp(prefix="r4web-test-"))
        self.addCleanup(shutil.rmtree, self.workspace, True)
        self.database = self.workspace / "slice" / "roulette-web.sqlite3"
        self.entropy = DeterministicTestEntropySource(ENTROPY_STREAM)

    def open(self, *, entropy=None, config=None, **overrides):
        """Open a store and table over the shared database path, closed on teardown."""

        store, table = open_table(
            self.database,
            config=config or TableConfig(opening_player_units=1_000, opening_house_units=100_000),
            clock=lambda: FIXED_CLOCK,
            entropy_source=self.entropy if entropy is None else entropy,
            environment=RngEnvironment.NON_PRODUCTION,
            **overrides,
        )
        self.addCleanup(store.close)
        return store, table

    def bet(self, table, request_id, payload=None):
        return table.place_bet(request_id, dict(payload or STRAIGHT_ZERO))


# ---------------------------------------------------------------------------------------
# domain: state machine, validation, integer currency
# ---------------------------------------------------------------------------------------


class RoundStateMachineTests(SliceTestCase):
    def test_declared_transitions_match_the_round_state_contract(self) -> None:
        contract = load_yaml("games/roulette/round-state.yaml")
        declared = {(item["from"], item["to"]) for item in contract["transitions"]}
        self.assertEqual({(a.value, b.value) for a, b in TRANSITIONS}, declared)
        self.assertEqual({phase.value for phase in TERMINAL_PHASES}, set(contract["terminal_states"]))
        self.assertEqual({phase.value for phase in RoundPhase}, set(contract["states"]))

    def test_a_spin_walks_open_locked_spinning_settling_settled_in_order(self) -> None:
        _, table = self.open()
        self.bet(table, "R4-BET-0001")
        result = table.spin("R4-SPIN-0001")
        state = result["state"]
        self.assertEqual(state["round"]["phase"], "SETTLED")
        walked = [step["to"] for step in state["round"]["transitions"]]
        self.assertEqual(walked, ["LOCKED", "SPINNING", "SETTLING", "SETTLED"])

    def test_a_settled_round_accepts_no_further_bet_or_spin(self) -> None:
        _, table = self.open()
        self.bet(table, "R4-BET-0002")
        table.spin("R4-SPIN-0002")
        with self.assertRaises(TableError) as caught_bet:
            table.place_bet("R4-BET-0003", dict(STRAIGHT_ZERO))
        with self.assertRaises(TableError) as caught_spin:
            table.spin("R4-SPIN-0003")
        for caught in (caught_bet, caught_spin):
            self.assertEqual(caught.exception.code, "PHASE_DENIED")
            self.assertEqual(caught.exception.status, 409)
        self.assertEqual(table.state()["round"]["phase"], "SETTLED")

    def test_a_new_round_is_refused_while_the_current_one_is_still_open(self) -> None:
        _, table = self.open()
        with self.assertRaises(TableError) as caught:
            table.new_round("R4-NEW-0001")
        self.assertEqual(caught.exception.code, "ROUND_IN_PROGRESS")

    def test_a_new_round_after_settlement_opens_empty_and_keeps_the_balance(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-BET-0004")
        table.spin("R4-SPIN-0004")
        settled_balance = table.state()["balance_units"]
        opened = table.new_round("R4-NEW-0002")["state"]
        self.assertEqual(opened["round"]["phase"], "OPEN")
        self.assertEqual(opened["round"]["bets"], [])
        self.assertEqual(opened["balance_units"], settled_balance)
        self.assertEqual(opened["balance_units"], store.balances([PLAYER_ACCOUNT])[PLAYER_ACCOUNT])

    def test_spinning_without_a_bet_is_refused(self) -> None:
        _, table = self.open()
        with self.assertRaises(TableError) as caught:
            table.spin("R4-SPIN-0005")
        self.assertEqual(caught.exception.code, "NO_BETS")
        self.assertEqual(table.state()["round"]["phase"], "OPEN")


class BetValidationTests(SliceTestCase):
    def _assert_refused(self, table, request_id, payload, code):
        before = table.state()
        with self.assertRaises(TableError) as caught:
            table.place_bet(request_id, payload)
        self.assertEqual(caught.exception.code, code)
        after = table.state()
        # A rejection must be free: same phase, same balance, same board.
        self.assertEqual(before["round"]["phase"], after["round"]["phase"])
        self.assertEqual(before["balance_units"], after["balance_units"])
        self.assertEqual(before["round"]["bets"], after["round"]["bets"])
        return caught.exception

    def test_an_unsupported_bet_type_is_refused_through_the_rules_boundary(self) -> None:
        _, table = self.open()
        self._assert_refused(
            table, "R4-BET-1001", {"type": "basket_0_1_2_3", "selections": [0, 1, 2, 3], "stake_units": 5},
            "BET_INVALID",
        )

    def test_an_impossible_selection_set_is_refused(self) -> None:
        _, table = self.open()
        self._assert_refused(
            table, "R4-BET-1002", {"type": "split", "selections": [1, 5], "stake_units": 5}, "BET_INVALID"
        )

    def test_a_non_integer_stake_is_refused_before_the_rules_engine(self) -> None:
        _, table = self.open()
        self._assert_refused(
            table, "R4-BET-1003", {"type": "red", "selections": [], "stake_units": 5.0}, "BET_INVALID"
        )
        self._assert_refused(
            table, "R4-BET-1004", {"type": "red", "selections": [], "stake_units": True}, "BET_INVALID"
        )

    def test_an_unknown_bet_field_is_refused_rather_than_ignored(self) -> None:
        _, table = self.open()
        exception = self._assert_refused(
            table,
            "R4-BET-1005",
            {"type": "red", "selections": [], "stake_units": 5, "payout_units": 999},
            "BET_INVALID",
        )
        self.assertIn("payout_units", exception.message)

    def test_a_stake_beyond_the_unreserved_balance_is_refused(self) -> None:
        _, table = self.open(config=TableConfig(opening_player_units=100, opening_house_units=100_000))
        self.bet(table, "R4-BET-1006", {"type": "red", "selections": [], "stake_units": 60})
        self._assert_refused(
            table, "R4-BET-1007", {"type": "red", "selections": [], "stake_units": 60}, "INSUFFICIENT_CHIPS"
        )
        self.assertEqual(table.state()["available_units"], 40)

    def test_a_bet_the_bankroll_cannot_cover_is_refused(self) -> None:
        _, table = self.open(
            config=TableConfig(opening_player_units=100_000, opening_house_units=100)
        )
        self._assert_refused(
            table,
            "R4-BET-1008",
            {"type": "straight", "selections": [17], "stake_units": 1_000},
            "HOUSE_EXPOSURE_EXCEEDED",
        )

    def test_bets_are_refused_once_the_round_has_left_open(self) -> None:
        _, table = self.open()
        self.bet(table, "R4-BET-1009")
        table.spin("R4-SPIN-1009")
        with self.assertRaises(TableError) as caught:
            self.bet(table, "R4-BET-1010")
        self.assertEqual(caught.exception.code, "PHASE_DENIED")

    def test_an_invalid_request_identifier_is_refused(self) -> None:
        _, table = self.open()
        for bad in ("short", "", "has space!", 17, None, "x" * 65):
            with self.assertRaises(TableError) as caught:
                table.place_bet(bad, dict(STRAIGHT_ZERO))
            self.assertEqual(caught.exception.code, "REQUEST_ID_INVALID")


class IntegerCurrencyTests(SliceTestCase):
    def test_no_floating_point_value_appears_in_any_authoritative_payload(self) -> None:
        _, table = self.open()
        self.bet(table, "R4-INT-0001", RED)
        spun = table.spin("R4-INT-0002")
        for label, payload in (("state", table.state()), ("spin", spun)):
            with self.subTest(label):
                self.assertEqual(find_floats(payload), [], label)
                # Round-tripping proves it survives serialisation as JSON integers too.
                self.assertEqual(find_floats(json.loads(json.dumps(payload))), [])

    def test_the_settled_balance_equals_the_rules_engine_net_change(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-INT-0003", RED)
        opening = table.state()["balance_units"]
        result = table.spin("R4-INT-0004")["result"]
        expected = settle_bet(dict(RED), result["pocket"], table.rules)
        self.assertEqual(result["net_change_units"], expected["net_change_units"])
        self.assertEqual(result["outcomes"][0]["payout_units"], expected["total_return_units"])
        self.assertEqual(table.state()["balance_units"], opening + expected["net_change_units"])
        self.assertEqual(
            store.balances([PLAYER_ACCOUNT])[PLAYER_ACCOUNT], opening + expected["net_change_units"]
        )

    def test_the_escrow_account_is_empty_again_after_settlement(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-INT-0005", RED)
        table.spin("R4-INT-0006")
        self.assertEqual(store.balances([ESCROW_ACCOUNT])[ESCROW_ACCOUNT], 0)

    def test_chips_are_conserved_across_the_three_accounts(self) -> None:
        store, table = self.open()
        before = sum(store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT, ESCROW_ACCOUNT]).values())
        self.bet(table, "R4-INT-0007", RED)
        table.spin("R4-INT-0008")
        after = sum(store.balances([PLAYER_ACCOUNT, HOUSE_ACCOUNT, ESCROW_ACCOUNT]).values())
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------------------
# authority, idempotency and history
# ---------------------------------------------------------------------------------------


class ServerAuthorityTests(SliceTestCase):
    def test_client_authoritative_field_names_are_recognised_everywhere_in_a_payload(self) -> None:
        self.assertEqual(prohibited_client_fields({"bet": {"pocket": 7}}), ["pocket"])
        self.assertEqual(prohibited_client_fields({"a": [{"balance_units": 1}]}), ["balance_units"])
        self.assertEqual(prohibited_client_fields({"request_id": "R4-OK-0001"}), [])
        for name in ("pocket", "payout_units", "balance_units", "won", "result"):
            self.assertIn(name, CLIENT_AUTHORITY_FIELDS)

    def test_the_draw_is_taken_exactly_once_per_round(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-ONCE-0001", RED)
        table.spin("R4-ONCE-0002")
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)
        self.assertEqual(store.verify_chain(), [])

    def test_a_repeated_spin_replays_without_consuming_entropy(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-IDEM-0001", RED)
        first = table.spin("R4-IDEM-0002")
        consumed = self.entropy.consumed
        second = table.spin("R4-IDEM-0002")
        self.assertTrue(second["replayed"])
        self.assertFalse(first["replayed"])
        self.assertEqual(second["result"], first["result"])
        self.assertEqual(self.entropy.consumed, consumed)
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)

    def test_a_repeated_bet_is_recorded_once(self) -> None:
        _, table = self.open()
        first = self.bet(table, "R4-IDEM-0003", RED)
        second = self.bet(table, "R4-IDEM-0003", RED)
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(table.state()["round"]["bet_count"], 1)
        self.assertEqual(table.state()["reserved_units"], RED["stake_units"])

    def test_a_reused_request_identifier_with_a_different_payload_fails_closed(self) -> None:
        _, table = self.open()
        self.bet(table, "R4-IDEM-0004", RED)
        with self.assertRaises(TableError) as caught:
            self.bet(table, "R4-IDEM-0004", STRAIGHT_ZERO)
        self.assertEqual(caught.exception.code, "REQUEST_ID_CONFLICT")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(table.state()["round"]["bet_count"], 1)

    def test_recent_results_follow_the_stored_commit_order(self) -> None:
        store, table = self.open()
        pockets = []
        for index in range(3):
            self.bet(table, f"R4-HIST-B{index:04d}", RED)
            pockets.append(table.spin(f"R4-HIST-S{index:04d}")["result"]["pocket"])
            table.new_round(f"R4-HIST-N{index:04d}")

        listed = table.state()["recent_results"]
        self.assertEqual([item["pocket"] for item in listed], pockets)
        # Rebuilt straight from the durable audit chain and draw records, it must agree.
        rebuilt = table.reload_history()
        self.assertEqual(rebuilt, listed)
        self.assertEqual(store.count("draw_record"), 3)

    def test_the_notice_is_present_and_names_no_purchase_or_exchange_path(self) -> None:
        _, table = self.open()
        state = table.state()
        self.assertEqual(state["notice"], NOTICE)
        self.assertEqual(state["notice"]["cash_value"], "NONE")
        self.assertEqual(state["currency"], "VIRTUAL_CHIP")
        serialized = json.dumps(state, ensure_ascii=False).lower()
        for forbidden in ("withdraw", "redeem", "purchase", "checkout", "payment", "top-up", "환전", "결제"):
            self.assertNotIn(forbidden, serialized, forbidden)


# ---------------------------------------------------------------------------------------
# concurrency
# ---------------------------------------------------------------------------------------


class ConcurrencyTests(SliceTestCase):
    def _race(self, store, call, workers=8):
        """Run ``call`` on ``workers`` threads released together; return results and errors."""

        results: list = []
        errors: list = []
        guard = threading.Lock()
        start = threading.Barrier(workers)

        def worker() -> None:
            try:
                start.wait(timeout=10)
                value = call()
            except TableError as refusal:
                with guard:
                    errors.append(refusal)
            except Exception as exc:  # noqa: BLE001 - reported as a failure below
                with guard:
                    errors.append(exc)
            else:
                with guard:
                    results.append(value)
            finally:
                # sqlite binds a connection to its opening thread; releasing it here keeps
                # the database file unlocked so the temporary directory can be removed.
                store.release_thread_connection()

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(any(thread.is_alive() for thread in threads), "a worker did not finish")
        return results, errors

    def test_concurrent_duplicate_spins_produce_exactly_one_draw(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-RACE-0001", RED)
        results, errors = self._race(store, lambda: table.spin("R4-RACE-0002"))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        pockets = {item["result"]["pocket"] for item in results}
        self.assertEqual(len(pockets), 1, "the racing callers disagreed about the pocket")
        self.assertEqual(sum(1 for item in results if not item["replayed"]), 1)
        self.assertEqual(store.count("draw_record"), 1)
        self.assertEqual(store.count("ledger_transaction"), 1)
        self.assertEqual(store.verify_chain(), [])

    def test_concurrent_duplicate_bets_reserve_the_stake_once(self) -> None:
        store, table = self.open()
        results, errors = self._race(store, lambda: table.place_bet("R4-RACE-0003", dict(RED)))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        self.assertEqual(table.state()["round"]["bet_count"], 1)
        self.assertEqual(table.state()["reserved_units"], RED["stake_units"])

    def test_distinct_concurrent_bets_are_all_recorded_and_balance_is_never_overdrawn(self) -> None:
        store, table = self.open(config=TableConfig(opening_player_units=100, opening_house_units=100_000))
        counter = iter(range(100))
        guard = threading.Lock()

        def place():
            with guard:
                index = next(counter)
            return table.place_bet(f"R4-RACE-D{index:04d}", {"type": "red", "selections": [], "stake_units": 30})

        results, errors = self._race(store, place)
        # Four bets of 30 fit inside 100 chips; the rest must be refused, not overdrawn.
        self.assertEqual(len(results), 3)
        self.assertTrue(all(error.code == "INSUFFICIENT_CHIPS" for error in errors), errors)
        state = table.state()
        self.assertEqual(state["round"]["bet_count"], 3)
        self.assertEqual(state["reserved_units"], 90)
        self.assertGreaterEqual(state["available_units"], 0)


# ---------------------------------------------------------------------------------------
# restart
# ---------------------------------------------------------------------------------------


class RestartTests(SliceTestCase):
    def test_balances_and_result_history_survive_a_restart(self) -> None:
        store, table = self.open()
        pockets = []
        for index in range(2):
            self.bet(table, f"R4-RST-B{index:04d}", RED)
            pockets.append(table.spin(f"R4-RST-S{index:04d}")["result"]["pocket"])
            table.new_round(f"R4-RST-N{index:04d}")
        balance = table.state()["balance_units"]
        store.close()

        _, reopened = self.open()
        state = reopened.state()
        self.assertEqual(state["balance_units"], balance)
        self.assertEqual([item["pocket"] for item in state["recent_results"]], pockets)
        self.assertEqual(state["round"]["phase"], "OPEN")
        self.assertEqual(state["round"]["bets"], [])
        self.assertEqual(state["reserved_units"], 0)

    def test_a_restart_does_not_reissue_the_opening_chips(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-RST-1001", RED)
        table.spin("R4-RST-1002")
        settled = table.state()["balance_units"]
        store.close()
        _, reopened = self.open()
        self.assertEqual(reopened.state()["balance_units"], settled)

    def test_a_request_identifier_served_before_the_restart_is_refused_afterwards(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-RST-2001", RED)
        table.spin("R4-RST-2002")
        store.close()

        reopened_store, reopened = self.open()
        self.bet(reopened, "R4-RST-2003", RED)
        with self.assertRaises(TableError) as caught:
            reopened.spin("R4-RST-2002")
        self.assertEqual(caught.exception.status, 409)
        self.assertIn(caught.exception.code, {"DRAW_DENIED", "REQUEST_ID_ALREADY_USED"})
        # The round that tried to reuse the identifier is closed, not left spinnable.
        self.assertEqual(reopened.state()["round"]["phase"], "VOIDED")
        self.assertEqual(reopened_store.count("draw_record"), 1)

    def test_a_new_instance_never_reuses_a_committed_round_identifier(self) -> None:
        store, table = self.open()
        self.bet(table, "R4-RST-3001", RED)
        first_round = table.spin("R4-RST-3002")["result"]["round_id"]
        store.close()
        _, reopened = self.open()
        self.assertNotEqual(reopened.state()["round"]["round_id"], first_round)


# ---------------------------------------------------------------------------------------
# transport: a real loopback server
# ---------------------------------------------------------------------------------------


class HttpTestCase(SliceTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.store, self.table = self.open()
        self.server = create_server(self.table, host="127.0.0.1", port=0)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        serve_in_background(self.server)
        self.host, self.port = self.server.server_address[0], self.server.server_address[1]

    def request(self, method, path, body=None, *, raw=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        self.addCleanup(connection.close)
        payload = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
        sent = dict(headers or {})
        if payload is not None:
            sent.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=payload, headers=sent)
        response = connection.getresponse()
        content = response.read()
        return response, content

    def json_request(self, method, path, body=None, **kwargs):
        response, content = self.request(method, path, body, **kwargs)
        return response, json.loads(content.decode("utf-8"))


class HttpApiTests(HttpTestCase):
    def test_state_is_served_with_the_notice_and_the_security_headers(self) -> None:
        response, payload = self.json_request("GET", "/api/state")
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["notice"], NOTICE)
        self.assertEqual(payload["state"]["round"]["phase"], "OPEN")
        for name, value in SECURITY_HEADERS:
            self.assertEqual(response.getheader(name), value, name)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")

    def test_a_full_bet_and_spin_round_trip_over_http(self) -> None:
        _, placed = self.json_request("POST", "/api/bets", {"request_id": "R4-HTTP-0001", "bet": RED})
        self.assertTrue(placed["accepted"])
        self.assertEqual(placed["state"]["round"]["bet_count"], 1)

        response, spun = self.json_request("POST", "/api/spin", {"request_id": "R4-HTTP-0002"})
        self.assertEqual(response.status, 200)
        self.assertEqual(spun["state"]["round"]["phase"], "SETTLED")
        self.assertIn(spun["result"]["pocket"], range(37))
        self.assertEqual(find_floats(spun), [])

        _, opened = self.json_request("POST", "/api/new-round", {"request_id": "R4-HTTP-0003"})
        self.assertEqual(opened["state"]["round"]["phase"], "OPEN")

    def test_a_duplicate_spin_over_http_replays_the_same_result(self) -> None:
        self.json_request("POST", "/api/bets", {"request_id": "R4-HTTP-0101", "bet": RED})
        _, first = self.json_request("POST", "/api/spin", {"request_id": "R4-HTTP-0102"})
        _, second = self.json_request("POST", "/api/spin", {"request_id": "R4-HTTP-0102"})
        self.assertTrue(second["replayed"])
        self.assertEqual(second["result"], first["result"])
        self.assertEqual(self.store.count("draw_record"), 1)

    def test_every_declared_route_is_reachable_by_its_declared_method_only(self) -> None:
        for path, method in ROUTES.items():
            other = "POST" if method == "GET" else "GET"
            response, payload = self.json_request(other, path)
            self.assertEqual(response.status, 405, path)
            self.assertEqual(payload["error"]["code"], "METHOD_NOT_ALLOWED")


class HttpRefusalTests(HttpTestCase):
    def test_an_unknown_path_is_a_json_404(self) -> None:
        response, payload = self.json_request("GET", "/api/does-not-exist")
        self.assertEqual(response.status, 404)
        self.assertEqual(payload["error"]["code"], "NOT_FOUND")
        self.assertEqual(payload["notice"], NOTICE)

    def test_an_unsupported_method_is_refused(self) -> None:
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            response, payload = self.json_request(method, "/api/state")
            self.assertEqual(response.status, 405, method)
            self.assertEqual(payload["error"]["code"], "METHOD_NOT_ALLOWED")

    def test_an_oversized_body_is_refused_without_being_read(self) -> None:
        oversized = b'{"request_id":"R4-HTTP-0201","bet":' + b"0" * (MAX_BODY_BYTES + 64) + b"}"
        response, payload = self.json_request("POST", "/api/bets", raw=oversized)
        self.assertEqual(response.status, 413)
        self.assertEqual(payload["error"]["code"], "PAYLOAD_TOO_LARGE")

    def test_a_body_without_a_declared_length_is_refused(self) -> None:
        response, payload = self.json_request(
            "POST", "/api/spin", raw=b"", headers={"Transfer-Encoding": "chunked"}
        )
        self.assertEqual(response.status, 411)
        self.assertEqual(payload["error"]["code"], "LENGTH_REQUIRED")

    def test_malformed_and_non_object_json_are_refused(self) -> None:
        for raw in (b"{not json", b"[1,2,3]", b'"a string"', b"\xff\xfe"):
            response, payload = self.json_request("POST", "/api/spin", raw=raw)
            self.assertEqual(response.status, 400, raw)
            self.assertEqual(payload["error"]["code"], "BAD_JSON")

    def test_a_floating_point_number_is_refused_by_the_parser(self) -> None:
        response, payload = self.json_request(
            "POST",
            "/api/bets",
            raw=b'{"request_id":"R4-HTTP-0301","bet":{"type":"red","selections":[],"stake_units":1.5}}',
        )
        self.assertEqual(response.status, 400)
        self.assertEqual(payload["error"]["code"], "BAD_JSON")
        self.assertEqual(self.table.state()["round"]["bet_count"], 0)

    def test_a_forged_result_or_balance_field_is_refused(self) -> None:
        for body in (
            {"request_id": "R4-HTTP-0401", "pocket": 17},
            {"request_id": "R4-HTTP-0402", "balance_units": 999_999},
            {"request_id": "R4-HTTP-0403", "bet": dict(RED, **{"payout_units": 900})},
        ):
            response, payload = self.json_request("POST", "/api/spin", body)
            self.assertEqual(response.status, 400, body)
            self.assertEqual(payload["error"]["code"], "CLIENT_AUTHORITY_DENIED")
        self.assertEqual(self.table.state()["balance_units"], 1_000)

    def test_an_unexpected_top_level_field_is_refused(self) -> None:
        response, payload = self.json_request(
            "POST", "/api/spin", {"request_id": "R4-HTTP-0501", "nudge": True}
        )
        self.assertEqual(response.status, 400)
        self.assertEqual(payload["error"]["code"], "BAD_REQUEST")

    def test_a_refusal_body_carries_no_traceback_path_or_internal_detail(self) -> None:
        probes = (
            ("GET", "/api/nope", None, None),
            ("POST", "/api/bets", {"request_id": "R4-HTTP-0601", "bet": {"type": "nope", "selections": [], "stake_units": 1}}, None),
            ("POST", "/api/spin", None, b"{"),
        )
        for method, path, body, raw in probes:
            response, content = self.request(method, path, body, raw=raw)
            text = content.decode("utf-8")
            self.assertGreaterEqual(response.status, 400)
            for leak in ("Traceback", "File \"", "sqlite", ".py", str(self.workspace), "site-packages"):
                self.assertNotIn(leak, text, f"{path} leaked {leak!r}")


class HttpStaticTests(HttpTestCase):
    def test_the_index_is_served_from_the_static_directory(self) -> None:
        response, content = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "text/html; charset=utf-8")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        self.assertIn("No cash value", content.decode("utf-8"))

    def test_path_traversal_spellings_are_all_refused(self) -> None:
        traversals = (
            "/../CLAUDE.md",
            "/../../CLAUDE.md",
            "/static/../../CLAUDE.md",
            "/%2e%2e/CLAUDE.md",
            "/%2e%2e%2f%2e%2e%2fCLAUDE.md",
            "/....//CLAUDE.md",
            "/.git/config",
            "/index.html/../../../CLAUDE.md",
        )
        for path in traversals:
            response, content = self.request("GET", path)
            self.assertEqual(response.status, 404, path)
            self.assertNotIn("Operating Contract", content.decode("utf-8", "replace"), path)

    def test_a_file_outside_the_extension_allowlist_is_not_served(self) -> None:
        secret = STATIC_ROOT / "notes.txt"
        secret.write_text("this must never be served", encoding="utf-8")
        self.addCleanup(secret.unlink, True)
        response, _ = self.request("GET", "/notes.txt")
        self.assertEqual(response.status, 404)
        self.assertNotIn(".txt", ALLOWED_STATIC_SUFFIXES)


# ---------------------------------------------------------------------------------------
# binding, isolation and the absence of an account surface
# ---------------------------------------------------------------------------------------


class BindingAndIsolationTests(SliceTestCase):
    def test_the_server_refuses_to_bind_a_non_loopback_host(self) -> None:
        _, table = self.open()
        for host in ("0.0.0.0", "", "example.com", "192.168.0.1"):
            with self.assertRaises(ValueError, msg=host):
                create_server(table, host=host, port=0)

    def test_the_bound_address_is_loopback(self) -> None:
        _, table = self.open()
        server = create_server(table, host="127.0.0.1", port=0)
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        self.assertIn("127.0.0.1", LOOPBACK_HOSTS)

    def test_the_default_database_lives_outside_the_repository(self) -> None:
        import os

        previous = os.environ.pop("ROULETTE_WEB_DB", None)
        try:
            default = pathlib.Path(default_database_path()).resolve()
        finally:
            if previous is not None:
                os.environ["ROULETTE_WEB_DB"] = previous
        self.assertFalse(default.is_relative_to(ROOT), f"{default} is inside the repository")

    def test_the_environment_variable_overrides_the_database_location(self) -> None:
        import os

        previous = os.environ.get("ROULETTE_WEB_DB")
        os.environ["ROULETTE_WEB_DB"] = str(self.workspace / "override.sqlite3")
        try:
            self.assertEqual(default_database_path(), str(self.workspace / "override.sqlite3"))
        finally:
            if previous is None:
                os.environ.pop("ROULETTE_WEB_DB", None)
            else:
                os.environ["ROULETTE_WEB_DB"] = previous

    def test_no_module_in_the_slice_imports_a_network_client_or_third_party_package(self) -> None:
        """The slice must start on the standard library and never reach off the machine."""

        import ast

        package = ROOT / "apps" / "roulette_web"
        allowed_third_party = {"studio_core"}
        banned_top_level = {"urllib.request", "requests", "httpx", "aiohttp", "smtplib", "ftplib", "socketserver"}
        for module in sorted(package.rglob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module)
            for name in imported:
                self.assertNotIn(name, banned_top_level, f"{module.name} imports {name}")
                root = name.split(".")[0]
                self.assertTrue(
                    root in allowed_third_party or root in sys.stdlib_module_names,
                    f"{module.name} imports non-standard-library {name!r}",
                )

    def test_the_slice_exposes_no_account_authentication_or_purchase_route(self) -> None:
        """No such feature exists in the code, only in prose describing its absence.

        The scan therefore looks at what the program *is* -- identifiers and the strings it
        actually emits -- and not at docstrings or comments. A design note saying "there is
        no sign-in here" is evidence for this criterion, and a scanner that flagged it
        would be a scanner people learn to ignore.
        """

        self.assertEqual(set(ROUTES), {"/api/state", "/api/bets", "/api/spin", "/api/new-round"})
        forbidden = ("password", "api_key", "credential", "login", "signup", "checkout", "withdraw", "redeem")
        for path in sorted((ROOT / "apps" / "roulette_web").rglob("*")):
            if not path.is_file():
                continue
            if path.suffix == ".py":
                surface = "\n".join(_executable_surface(path.read_text(encoding="utf-8")))
            elif path.suffix in {".html", ".css", ".js", ".json"}:
                surface = path.read_text(encoding="utf-8")
            else:
                continue
            for term in forbidden:
                self.assertNotIn(term, surface.lower(), f"{path.name} names {term!r}")


if __name__ == "__main__":
    unittest.main()
