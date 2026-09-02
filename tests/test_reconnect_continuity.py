"""R2-NET-0003: reconnect and round continuity over a real loopback HTTP server.

What these tests are trying to break
------------------------------------
Four things, each of which would be a real defect in a system that settles money:

* **Rehydration inventing state.** A reconnect must be able to produce only what the server
  has committed. Every rehydration assertion here compares the HTTP snapshot against the
  durable store read independently, so a value that came from anywhere else fails.
* **Bets coming back from the dead.** An open round's bets are not durable. After a restart
  they must be gone -- not "usually gone", and not silently re-accepted by a round that has
  already locked.
* **A lost settlement response being paid twice.** This is the expensive one. The tests lose
  the response for real -- the request is written to the socket and the socket is closed
  without ever reading the answer -- and then retry under the same ``request_id``. Entropy
  consumption, draw-record count, ledger-transaction count and the player balance are all
  measured before and after.
* **The client deciding something.** ``app.js`` is scanned for authority arithmetic and for
  the reconnect behaviour it is supposed to have.

On determinism
--------------
Nothing here sleeps for a fixed period and hopes. The entropy source is a fixed byte stream,
the clock is pinned, and the one place that has to wait -- for a server thread to finish
committing a request whose response was thrown away -- waits on the *condition* (the draw
record appearing in the store) with a deadline, so the outcome depends on what the server
did rather than on how fast it did it. ``test_recovery_is_stable_under_repetition`` runs the
whole lost-response scenario repeatedly and asserts the measurements never move.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from apps.roulette_web.server import (  # noqa: E402
    ROUTES,
    SECURITY_HEADERS,
    create_server,
    open_table,
    serve_in_background,
)
from apps.roulette_web.table import (  # noqa: E402
    BETS_ACCEPTED_IN,
    PLAYER_ACCOUNT,
    TableConfig,
)
from studio_core.config import ROOT  # noqa: E402
from studio_core.integrity import verify_file  # noqa: E402
from studio_core.rng import DeterministicTestEntropySource, RngEnvironment  # noqa: E402

FIXED_CLOCK = "2026-09-01T00:00:00Z"
ENTROPY_STREAM = bytes([7, 11, 13, 17, 19, 23])

RED_BET = {"type": "red", "selections": [], "stake_units": 25}
STRAIGHT_BET = {"type": "straight", "selections": [0], "stake_units": 10}

#: How long a committed-but-unanswered request may take to appear in the store before the
#: test gives up. Generous on purpose: the assertion is "it committed", not "it was fast".
COMMIT_DEADLINE_SECONDS = 15.0


class ReconnectTestCase(unittest.TestCase):
    """One isolated database, one deterministic entropy stream, servers on demand."""

    def setUp(self) -> None:
        self.workspace = pathlib.Path(tempfile.mkdtemp(prefix="r2net-test-"))
        self.addCleanup(shutil.rmtree, self.workspace, True)
        self.database = self.workspace / "slice" / "roulette-web.sqlite3"
        self.entropy = DeterministicTestEntropySource(ENTROPY_STREAM)
        self.store = None
        self.table = None
        self.server = None

    # -- lifecycle -----------------------------------------------------------------------

    def start(self):
        """Open the store and table over the shared database and serve them on loopback."""

        store, table = open_table(
            self.database,
            config=TableConfig(opening_player_units=1_000, opening_house_units=100_000),
            clock=lambda: FIXED_CLOCK,
            entropy_source=self.entropy,
            environment=RngEnvironment.NON_PRODUCTION,
        )
        server = create_server(table, host="127.0.0.1", port=0)
        # A client that hangs up before reading makes the handler's final write fail. That
        # is the scenario under test, not a defect, so the server's default traceback is
        # silenced on this instance only -- production behaviour is untouched.
        server.handle_error = lambda request, client_address: None
        serve_in_background(server)
        self.store, self.table, self.server = store, table, server
        self.host, self.port = server.server_address[0], server.server_address[1]
        return store, table, server

    def stop(self) -> None:
        """Shut the process down the way a restart would: server first, then the store."""

        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.store is not None:
            self.store.close()
            self.store = None
        self.table = None

    def restart(self):
        """Stop everything and open a new process-equivalent over the same database."""

        self.stop()
        return self.start()

    def tearDown(self) -> None:
        self.stop()

    # -- transport -----------------------------------------------------------------------

    def api(self, method, path, body=None):
        """Issue one request on its own connection, as a reconnecting client would."""

        import http.client

        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            payload = json.dumps(body).encode("utf-8") if body is not None else None
            headers = {"Accept": "application/json"}
            if payload is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            text = response.read().decode("utf-8")
            return response.status, (json.loads(text) if text else None)
        finally:
            connection.close()

    def send_and_abort(self, path, body) -> None:
        """Write a whole request to the socket and hang up without reading the answer.

        This is the real failure being modelled: the server receives and acts on the
        request, and the client never learns what happened.
        """

        payload = json.dumps(body).encode("utf-8")
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii") + payload
        sock = socket.create_connection((self.host, self.port), timeout=10)
        try:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
        finally:
            sock.close()

    def await_commit(self, request_id):
        """Wait until ``request_id`` has a committed draw record, or fail with a deadline."""

        deadline = time.monotonic() + COMMIT_DEADLINE_SECONDS
        while time.monotonic() < deadline:
            record = self.store.draw_record(request_id)
            if record is not None:
                return record
            time.sleep(0.01)
        self.fail(f"the server never committed a draw for {request_id!r}")

    # -- measurement ---------------------------------------------------------------------

    def ledger_state(self):
        """Return the numbers a second payout would necessarily change."""

        return {
            "draws": self.store.count("draw_record"),
            "settlements": self.store.count("ledger_transaction"),
            "balance": self.store.balances([PLAYER_ACCOUNT])[PLAYER_ACCOUNT],
            "entropy": self.entropy.consumed,
        }

    def place_and_spin(self, *, bet_id, spin_id, bet=None):
        """Place one bet and settle the round over HTTP, returning the spin payload."""

        status, placed = self.api("POST", "/api/bets", {"request_id": bet_id, "bet": bet or RED_BET})
        self.assertEqual(status, 200, placed)
        status, spun = self.api("POST", "/api/spin", {"request_id": spin_id})
        self.assertEqual(status, 200, spun)
        return spun


# ---------------------------------------------------------------------------------------
# AC-001, AC-004: rehydration reads committed state and nothing else
# ---------------------------------------------------------------------------------------


class RehydrationTests(ReconnectTestCase):
    def test_reconnect_snapshot_matches_the_durable_store(self) -> None:
        self.start()
        spun = self.place_and_spin(bet_id="R2NET-BET-0001", spin_id="R2NET-SPIN-0001")

        # A brand new connection, as a client that dropped and came back would use.
        status, payload = self.api("GET", "/api/state")
        self.assertEqual(status, 200)
        state = payload["state"]

        stored = self.store.balances([PLAYER_ACCOUNT])[PLAYER_ACCOUNT]
        self.assertEqual(state["balance_units"], stored)
        self.assertEqual(
            state["recent_results"][-1]["round_id"], spun["result"]["round_id"]
        )
        self.assertEqual(state["recent_results"][-1]["pocket"], spun["result"]["pocket"])

    def test_rehydration_after_restart_is_rebuilt_from_durable_state(self) -> None:
        self.start()
        spun = self.place_and_spin(bet_id="R2NET-BET-0002", spin_id="R2NET-SPIN-0002")
        before = self.ledger_state()

        self.restart()

        status, payload = self.api("GET", "/api/state")
        self.assertEqual(status, 200)
        state = payload["state"]
        after = self.ledger_state()

        # The balance survived the restart because it was committed, not remembered.
        self.assertEqual(state["balance_units"], before["balance"])
        self.assertEqual(after["draws"], before["draws"])
        self.assertEqual(after["settlements"], before["settlements"])
        # AC-004: the committed outcome is still observable, rebuilt from the audit chain.
        self.assertIn(
            spun["result"]["round_id"], [item["round_id"] for item in state["recent_results"]]
        )
        # A restart opens a fresh round rather than resuming a settled one.
        self.assertEqual(state["round"]["phase"], BETS_ACCEPTED_IN.value)
        self.assertEqual(state["round"]["bets"], [])

    def test_recent_results_match_the_audit_chain_after_restart(self) -> None:
        self.start()
        self.place_and_spin(bet_id="R2NET-BET-0003", spin_id="R2NET-SPIN-0003")
        self.api("POST", "/api/new-round", {"request_id": "R2NET-ROUND-0003"})
        self.place_and_spin(bet_id="R2NET-BET-0004", spin_id="R2NET-SPIN-0004")

        self.restart()
        status, payload = self.api("GET", "/api/state")
        self.assertEqual(status, 200)

        # Independently derive the committed order from the store's own audit events.
        expected = []
        for event in self.store.audit_events():
            if event.get("action") != "ROULETTE_RNG_DRAW":
                continue
            for reference in event.get("resource_refs", []):
                if isinstance(reference, str) and reference.startswith("round://"):
                    expected.append(reference.removeprefix("round://"))
                    break
        self.assertEqual(
            [item["round_id"] for item in payload["state"]["recent_results"]], expected
        )


# ---------------------------------------------------------------------------------------
# AC-002: a reconnect cannot resurrect betting
# ---------------------------------------------------------------------------------------


class BettingResurrectionTests(ReconnectTestCase):
    def test_uncommitted_open_round_bets_do_not_survive_a_restart(self) -> None:
        self.start()
        status, _ = self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0010", "bet": RED_BET})
        self.assertEqual(status, 200)
        status, _ = self.api(
            "POST", "/api/bets", {"request_id": "R2NET-BET-0011", "bet": STRAIGHT_BET}
        )
        self.assertEqual(status, 200)

        status, before = self.api("GET", "/api/state")
        self.assertEqual(before["state"]["round"]["bet_count"], 2)
        self.assertEqual(before["state"]["reserved_units"], 35)
        opening_balance = self.store.balances([PLAYER_ACCOUNT])[PLAYER_ACCOUNT]

        self.restart()

        status, payload = self.api("GET", "/api/state")
        self.assertEqual(status, 200)
        state = payload["state"]
        # Nothing was committed for those bets, so there is nothing to bring back.
        self.assertEqual(state["round"]["bets"], [])
        self.assertEqual(state["round"]["bet_count"], 0)
        self.assertEqual(state["round"]["total_stake_units"], 0)
        self.assertEqual(state["reserved_units"], 0)
        self.assertEqual(state["balance_units"], opening_balance)
        self.assertEqual(self.store.count("ledger_transaction"), 0)

    def test_a_bet_is_refused_once_the_round_has_left_open(self) -> None:
        self.start()
        self.place_and_spin(bet_id="R2NET-BET-0012", spin_id="R2NET-SPIN-0012")

        status, payload = self.api("GET", "/api/state")
        self.assertFalse(payload["state"]["round"]["accepts_bets"])

        # A reconnecting client that replayed a queued bet must not be able to place it.
        status, refused = self.api(
            "POST", "/api/bets", {"request_id": "R2NET-BET-0013", "bet": RED_BET}
        )
        self.assertEqual(status, 409)
        self.assertEqual(refused["error"]["code"], "PHASE_DENIED")
        self.assertEqual(self.store.count("ledger_transaction"), 1)

    def test_reconnect_does_not_move_the_round_or_the_balance(self) -> None:
        self.start()
        self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0014", "bet": RED_BET})
        before = self.ledger_state()
        status, first = self.api("GET", "/api/state")

        for _ in range(5):
            status, again = self.api("GET", "/api/state")
            self.assertEqual(status, 200)
            self.assertEqual(again["state"]["round"]["phase"], first["state"]["round"]["phase"])
            self.assertEqual(again["state"]["balance_units"], first["state"]["balance_units"])
        self.assertEqual(self.ledger_state(), before)


# ---------------------------------------------------------------------------------------
# AC-003: a lost settlement response never pays twice
# ---------------------------------------------------------------------------------------


class LostSettlementResponseTests(ReconnectTestCase):
    def test_aborted_spin_response_is_replayed_by_the_same_request_id(self) -> None:
        self.start()
        status, _ = self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0020", "bet": RED_BET})
        self.assertEqual(status, 200)

        # The response is genuinely lost: written to the socket, never read.
        self.send_and_abort("/api/spin", {"request_id": "R2NET-SPIN-0020"})
        record = self.await_commit("R2NET-SPIN-0020")
        committed = self.ledger_state()

        status, replayed = self.api("POST", "/api/spin", {"request_id": "R2NET-SPIN-0020"})
        self.assertEqual(status, 200, replayed)
        self.assertTrue(replayed["replayed"])
        self.assertEqual(replayed["result"]["pocket"], record.pocket)
        self.assertEqual(replayed["result"]["proof_hash"], record.proof_hash)
        # No second draw, no extra entropy, no second settlement, no balance movement.
        self.assertEqual(self.ledger_state(), committed)
        self.assertEqual(committed["draws"], 1)
        self.assertEqual(committed["settlements"], 1)

    def test_retry_after_restart_with_an_empty_round_is_refused_before_the_store(self) -> None:
        """A restarted server opens an empty round, so the retry never reaches the store.

        ``NO_BETS`` rather than ``REQUEST_ID_ALREADY_USED`` is what actually comes back here,
        because ``RouletteTable.spin`` checks that the current round has bets before it calls
        ``submit_round``. It still fails closed, which is the property that matters, and the
        reconnect contract declares both codes rather than only the one that reads better.
        """

        self.start()
        status, _ = self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0021", "bet": RED_BET})
        self.assertEqual(status, 200)
        self.send_and_abort("/api/spin", {"request_id": "R2NET-SPIN-0021"})
        self.await_commit("R2NET-SPIN-0021")
        committed = self.ledger_state()

        self.restart()

        status, refused = self.api("POST", "/api/spin", {"request_id": "R2NET-SPIN-0021"})
        self.assertEqual(status, 400, refused)
        self.assertEqual(refused["error"]["code"], "NO_BETS")
        self.assertEqual(self.ledger_state(), committed)

        # AC-004: the outcome the client lost is still readable from the snapshot.
        status, payload = self.api("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertTrue(payload["state"]["recent_results"])

    def test_retry_after_restart_with_a_started_round_is_refused_by_the_store(self) -> None:
        """When the fresh round does have bets, the durable store is what refuses.

        Not with ``REQUEST_ID_ALREADY_USED``: round identifiers carry a per-instance token, so
        a restarted table always presents the reused identifier against a *different* round.
        The store sees one request_id with two request fingerprints and refuses the conflict,
        which surfaces as ``DRAW_DENIED``. That is the stronger of the two refusals -- it
        declines to serve an unrelated committed result -- and it is what the contract
        declares.
        """

        self.start()
        status, _ = self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0023", "bet": RED_BET})
        self.assertEqual(status, 200)
        self.send_and_abort("/api/spin", {"request_id": "R2NET-SPIN-0023"})
        self.await_commit("R2NET-SPIN-0023")
        committed = self.ledger_state()

        self.restart()

        # The player has started betting again on the restarted server.
        status, _ = self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0024", "bet": RED_BET})
        self.assertEqual(status, 200)
        status, refused = self.api("POST", "/api/spin", {"request_id": "R2NET-SPIN-0023"})
        self.assertEqual(status, 409, refused)
        self.assertEqual(refused["error"]["code"], "DRAW_DENIED")
        # The store refused rather than drawing again for the new round.
        self.assertEqual(self.ledger_state(), committed)
        # The committed outcome is still readable under its original identifier.
        self.assertIsNotNone(self.store.draw_record("R2NET-SPIN-0023"))

    def test_repeated_retries_never_move_the_ledger(self) -> None:
        self.start()
        self.api("POST", "/api/bets", {"request_id": "R2NET-BET-0022", "bet": RED_BET})
        self.send_and_abort("/api/spin", {"request_id": "R2NET-SPIN-0022"})
        self.await_commit("R2NET-SPIN-0022")
        committed = self.ledger_state()

        for _ in range(4):
            status, replayed = self.api("POST", "/api/spin", {"request_id": "R2NET-SPIN-0022"})
            self.assertEqual(status, 200)
            self.assertTrue(replayed["replayed"])
            self.assertEqual(self.ledger_state(), committed)

        self.restart()
        # Every after-restart refusal is fail-closed; which code appears depends on the fresh
        # round, so the invariant asserted here is the ledger, not the wording.
        for _ in range(4):
            status, refused = self.api("POST", "/api/spin", {"request_id": "R2NET-SPIN-0022"})
            self.assertIn(status, (400, 409))
            self.assertIn(
                refused["error"]["code"], {"NO_BETS", "DRAW_DENIED", "PHASE_DENIED"}
            )
            self.assertEqual(self.ledger_state(), committed)

    def test_recovery_is_stable_under_repetition(self) -> None:
        """The whole lost-response scenario, run repeatedly, must measure identically."""

        self.start()
        observations = []
        for index in range(3):
            if index:
                status, _ = self.api(
                    "POST", "/api/new-round", {"request_id": f"R2NET-ROUND-003{index}"}
                )
                self.assertEqual(status, 200)
            before = self.ledger_state()
            self.api("POST", "/api/bets", {"request_id": f"R2NET-BET-003{index}", "bet": RED_BET})
            spin_id = f"R2NET-SPIN-003{index}"
            self.send_and_abort("/api/spin", {"request_id": spin_id})
            self.await_commit(spin_id)
            after_commit = self.ledger_state()

            status, replayed = self.api("POST", "/api/spin", {"request_id": spin_id})
            self.assertEqual(status, 200)
            after_replay = self.ledger_state()

            observations.append(
                {
                    "draws_added": after_commit["draws"] - before["draws"],
                    "settlements_added": after_commit["settlements"] - before["settlements"],
                    "replay_changed_anything": after_replay != after_commit,
                    "replayed_flag": replayed["replayed"],
                }
            )

        self.assertEqual(
            observations,
            [
                {
                    "draws_added": 1,
                    "settlements_added": 1,
                    "replay_changed_anything": False,
                    "replayed_flag": True,
                }
            ]
            * 3,
        )


# ---------------------------------------------------------------------------------------
# AC-005: the client decides nothing
# ---------------------------------------------------------------------------------------


class ClientAuthorityTests(ReconnectTestCase):
    def test_authority_fields_are_refused_on_the_recovery_path(self) -> None:
        self.start()
        for path, body in (
            ("/api/spin", {"request_id": "R2NET-SPIN-0040", "balance_units": 999_999}),
            ("/api/spin", {"request_id": "R2NET-SPIN-0041", "pocket": 17}),
            ("/api/bets", {"request_id": "R2NET-BET-0040", "bet": dict(RED_BET, payout_units=500)}),
        ):
            with self.subTest(body=body):
                status, refused = self.api("POST", path, body)
                self.assertEqual(status, 400)
                self.assertEqual(refused["error"]["code"], "CLIENT_AUTHORITY_DENIED")
        self.assertEqual(self.store.count("draw_record"), 0)
        self.assertEqual(self.store.count("ledger_transaction"), 0)

    def test_client_script_reconnects_without_computing_anything(self) -> None:
        script = (ROOT / "apps/roulette_web/static/app.js").read_text(encoding="utf-8")

        # The reconnect behaviour this unit is supposed to have.
        for marker in ("function rehydrate(", "function recoverLostSpin(", "/api/state", "/api/spin"):
            self.assertIn(marker, script)
        # Drafts are dropped rather than re-submitted into a round that has moved on.
        self.assertIn("ui.drafts = []", script)
        self.assertIn("accepts_bets", script)
        # The retry reuses the held identifier instead of minting a new one.
        self.assertIn("recoverLostSpin(requestId)", script)
        # Every after-restart refusal is read as one recovery signal.
        for code in ("NO_BETS", "DRAW_DENIED", "PHASE_DENIED", "REQUEST_ID_ALREADY_USED"):
            self.assertIn(code, script)

        # No route this unit was told not to add, and no client-side authority or storage.
        for forbidden in (
            "/api/resume",
            "localStorage",
            "sessionStorage",
            "document.cookie",
            "Math.random",
            "WebSocket",
        ):
            self.assertNotIn(forbidden, script)


# ---------------------------------------------------------------------------------------
# AC-007, AC-008, AC-009, AC-010, AC-011: the shape of the change itself
# ---------------------------------------------------------------------------------------


class ChangeShapeTests(unittest.TestCase):
    def test_no_new_route_was_added(self) -> None:
        self.assertEqual(
            set(ROUTES), {"/api/state", "/api/bets", "/api/spin", "/api/new-round"}
        )
        self.assertNotIn("/api/resume", ROUTES)
        self.assertEqual(len(SECURITY_HEADERS), 7)

    def test_no_new_runtime_module_was_added(self) -> None:
        modules = sorted(
            path.name for path in (ROOT / "apps/roulette_web").glob("*.py")
        )
        self.assertEqual(modules, ["__init__.py", "server.py", "table.py"])
        self.assertFalse((ROOT / "apps/roulette_web/reconnect.py").exists())

    def test_frozen_paths_still_match_their_declared_hashes(self) -> None:
        """AC-009: the files that would cascade into R4-ART-0007 are untouched."""

        task = json.loads((ROOT / "tasks/R2-NET-0003.json").read_text(encoding="utf-8"))
        pinned = {item["uri"].removeprefix("repo://"): item["content_hash"] for item in task["inputs"]}
        contract = _load_reconnect_contract()
        for relative in contract["frozen_paths"]["paths"]:
            with self.subTest(path=relative):
                self.assertIn(relative, pinned, f"{relative} must be pinned by the task")
                decision = verify_file(ROOT / relative, pinned[relative], label=relative)
                self.assertTrue(decision.matches, decision.message)

    def test_repin_scope_is_exactly_the_declared_contracts(self) -> None:
        """AC-010: only the three named contracts pin the validator, and all agree."""

        contract = _load_reconnect_contract()
        declared = set(contract["repin_scope"]["contracts"])
        actual = set()
        for path in sorted((ROOT / "tasks").glob("*.json")):
            task = json.loads(path.read_text(encoding="utf-8"))
            for item in task.get("inputs", []):
                if item["uri"] == "repo://scripts/validate_baseline.py":
                    actual.add(f"tasks/{path.name}")
        self.assertEqual(actual, declared)

        for relative in sorted(declared):
            task = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            pin = next(
                item for item in task["inputs"] if item["uri"] == "repo://scripts/validate_baseline.py"
            )
            decision = verify_file(
                ROOT / "scripts/validate_baseline.py", pin["content_hash"], label=relative
            )
            self.assertTrue(decision.matches, f"{relative}: {decision.message}")

    def test_the_reconnect_contract_matches_the_implementation(self) -> None:
        """AC-011: the published declaration is compared against the running constants."""

        from scripts.validate_baseline import validate_r2_reconnect

        summary = validate_r2_reconnect()
        self.assertEqual(summary["new_http_routes"], 0)
        self.assertEqual(summary["new_runtime_modules"], 0)
        self.assertEqual(summary["frozen_paths_verified"], 9)


class ReconnectValidatorNegativeTests(unittest.TestCase):
    """A validator that cannot fail is not a check. Each case breaks one declared fact."""

    def setUp(self) -> None:
        from scripts.validate_baseline import R2_NET_INPUT_FILES

        self.workspace = pathlib.Path(tempfile.mkdtemp(prefix="r2net-negative-"))
        self.addCleanup(shutil.rmtree, self.workspace, True)
        for relative in R2_NET_INPUT_FILES:
            destination = self.workspace / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

    def mutate(self, replacements) -> None:
        path = self.workspace / "games/roulette/reconnect-contract.yaml"
        text = path.read_text(encoding="utf-8")
        for old, new in replacements:
            self.assertIn(old, text)
            text = text.replace(old, new, 1)
        path.write_text(text, encoding="utf-8", newline="")

    def assert_rejected(self, needle) -> None:
        from scripts.validate_baseline import BaselineValidationError, validate_r2_reconnect

        with self.assertRaises(BaselineValidationError) as caught:
            validate_r2_reconnect(self.workspace)
        self.assertIn(needle, str(caught.exception))

    def test_a_declared_new_route_is_rejected(self) -> None:
        self.mutate([("new_http_routes: 0", "new_http_routes: 1")])
        self.assert_rejected("new_http_routes")

    def test_a_wrong_route_count_is_rejected(self) -> None:
        self.mutate([("route_count: 4", "route_count: 5")])
        self.assert_rejected("route_count")

    def test_a_wrong_betting_guard_is_rejected(self) -> None:
        self.mutate([("accept_bets_only_in: OPEN", "accept_bets_only_in: LOCKED")])
        self.assert_rejected("accept_bets_only_in")

    def test_permitting_bet_restoration_is_rejected(self) -> None:
        self.mutate([("bets_restored_on_reconnect: false", "bets_restored_on_reconnect: true")])
        self.assert_rejected("bets_restored_on_reconnect")

    def test_permitting_a_second_settlement_is_rejected(self) -> None:
        self.mutate([("second_ledger_settlement: prohibited", "second_ledger_settlement: allowed")])
        self.assert_rejected("second_ledger_settlement")

    def test_declaring_only_one_after_restart_refusal_is_rejected(self) -> None:
        self.mutate([("    - NO_BETS\n", "")])
        self.assert_rejected("after_restart_refusal_codes")

    def test_permitting_client_state_merging_is_rejected(self) -> None:
        self.mutate(
            [("client_supplied_state_merged_on_reconnect: false", "client_supplied_state_merged_on_reconnect: true")]
        )
        self.assert_rejected("client_supplied_state_merged_on_reconnect")

    def test_a_dropped_frozen_path_is_rejected(self) -> None:
        self.mutate([("    - docs/status/R2-STATUS.md\n", "")])
        self.assert_rejected("frozen_paths")

    def test_an_unpinned_frozen_path_is_rejected(self) -> None:
        task = self.workspace / "tasks/R2-NET-0003.json"
        contract = json.loads(task.read_text(encoding="utf-8"))
        contract["inputs"] = [
            item for item in contract["inputs"] if item["uri"] != "repo://docs/status/R2-STATUS.md"
        ]
        task.write_text(json.dumps(contract, ensure_ascii=False, indent=2), encoding="utf-8", newline="")
        self.assert_rejected("docs/status/R2-STATUS.md")

    def test_a_modified_frozen_file_is_rejected(self) -> None:
        target = self.workspace / "apps/roulette_web/server.py"
        target.write_text(
            target.read_text(encoding="utf-8") + "\n# drifted\n", encoding="utf-8", newline=""
        )
        self.assert_rejected("apps/roulette_web/server.py")

    def test_a_client_that_computes_is_rejected(self) -> None:
        target = self.workspace / "apps/roulette_web/static/app.js"
        target.write_text(
            target.read_text(encoding="utf-8").replace("function rehydrate(", "function rehydrated("),
            encoding="utf-8",
            newline="",
        )
        self.assert_rejected("app.js")


def _load_reconnect_contract():
    import yaml

    with (ROOT / "games/roulette/reconnect-contract.yaml").open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


if __name__ == "__main__":
    unittest.main()
