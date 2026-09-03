# R4-FIX-0008 validation report

- Task: `tasks/R4-FIX-0008.json` (`READY`, owner `A-02`, risk `HIGH`)
- Base commit: `dd480594a433a662033e5e8fde560141a999a008`, branch `codex/r4-settlement-failure-recovery`
- Fixed file: `apps/roulette_web/table.py`
- Regression suite: `tests/test_settlement_failure_recovery.py`
- Author: `A-02` (implementer, `claude-fable-5-1`, no model substitution, no subagents).
  **This document is the implementer's self-check record. It is not a review, not independent
  verification and not an approval.**

## 0. Revision history

| Artifact rev | State | What happened |
| --- | --- | --- |
| 1.1.0 (INITIAL) | rejected | Pre-commit wedge fixed (AC-001..005). An `after_commit` fault voided the *local* round while the durable round was SETTLED; the report listed this as a MEDIUM risk and the original `PostCommitFaultTests` only asserted "terminal" and called `reload_history` by hand. An independent Codex probe **and** a separate read-only Fable code-reviewer rejected that: state showed `VOIDED`, `result: null`, empty `recent_results` and a same-id retry answered `PHASE_DENIED` although the draw and settlement existed. The issuer added AC-006 during that run. |
| 1.2.0 (REWORK, this document) | submitted for review | AC-006 implemented: post-commit faults reconcile against storage and expose the SETTLED round; strengthened tests. Pre-commit behaviour of 1.1.0 is unchanged. **Correction awaits final review; the preliminary rejection is not lifted by the author.** |

## 1. What is claimed and what is not

Claimed: the commands in section 5 were actually run in this working tree with the results shown;
the INITIAL regression suite failed against the unmodified `table.py`; the strengthened post-commit
tests fail against the INITIAL revision (section 4b) and the whole suite passes against 1.2.0.

Not claimed: Claude code review (separate Fable reviewer), Codex independent verification (`A-50`),
browser QA, art or rights decisions, `A-00`/`USER` final gate, R5 readiness. All of these are
`NOT_RUN` from this unit's point of view. The preliminary reviewer rejection of 1.1.0 is recorded
above; whether 1.2.0 answers it is for that reviewer and `A-50` to decide.

## 2. The defect

`RouletteTable.spin` wraps `DurableRoundStore.submit_round`. The store's `_write_transaction`
rolls back on any `BaseException`, and `submit_round` re-raises everything it catches. `spin` only
handled the two typed refusals (`RngDenied` -> `DRAW_DENIED`, `DurableStateError` -> `COMMIT_DENIED`)
through `_fail_round`. Any other exception escaping the store left the in-memory round in
`SPINNING` (fault at `after_draw`) or `SETTLING` (`after_ledger`, `before_commit`) with
`_reserved_units` still holding the stake. From then on every `place_bet`, `spin` and `new_round`
was refused (`PHASE_DENIED` / `ROUND_IN_PROGRESS`) for the life of the process, even though the
store had committed nothing.

A second, latent problem sat inside `_fail_round` itself: it transitioned before releasing the
reservation, and `SETTLING` declares no exit but `SETTLED`, so the forced-void path depended on the
`TableError` fallback ordering.

A third problem (AC-006, found in review of 1.1.0): the same handler treated a fault raised *after*
the store had committed (`after_commit`) as if nothing had committed, so a player whose round had
durably settled was shown a voided round with no result, and a same-id retry was refused instead
of replayed.

## 3. The fix (`apps/roulette_web/table.py`, three hunks)

1. `spin`: after the two existing typed handlers, an `except BaseException:` block calls
   `self._recover_after_submit_failure(current, request_id, settled)` and then bare-`raise`s. The
   original exception object, type and traceback continue unchanged; nothing is translated into a
   `TableError` and nothing becomes a success. The two typed mappings are untouched and run first.
2. `_fail_round`: releases `_reserved_units` first (so it can never be the skipped step), returns
   early if the round is already terminal, otherwise transitions to `VOIDED` and, when the phase
   machine refuses (`SETTLING`), forces `current.phase = RoundPhase.VOIDED` as before.
3. (1.2.0) Three private methods, no new public surface:
   - `_reconcile_committed`: returns `None` unless the local settlement factory ran, the public
     `draw_record(request_id)` returns a record whose `request_id` **and** `round_id` equal the
     current round, and the store's own `submit_round` replay (the restart read-back path: proof
     re-verified, no entropy, no second settlement, `replayed=True`) returns the same request and
     round with `settlement_transaction_id` equal to the transaction this round built. Any
     mismatch is a record this round cannot vouch for and is not adopted.
   - `_adopt_committed`: sets the result from the replayed `CommittedRound` plus the local
     outcomes, transitions `SETTLING -> SETTLED` (declared), releases the reservation, appends the
     recent-history entry and records the spin journal entry so a same-id retry replays.
   - `_recover_after_submit_failure`: runs the two above; **any** exception from reconciliation or
     adoption falls through to `_fail_round`, and a failure inside `_fail_round` still ends with
     the reservation released and the phase terminal. Nothing raised here can replace the error
     being reported. Pre-commit faults reach `_fail_round` exactly as in 1.1.0 (no record exists).

No store, RNG, server, API or client code changed; reconciliation uses only `draw_record`,
`submit_round` (replay) and `balances`, never a private SQLite query.

No new `TableError` codes were added (`_r4_declared_error_codes` parity with
`games/roulette/playable-slice-contract.yaml` is unchanged). No public method signature changed.
`server.py`, `app.js`, CSS, HTML and assets are untouched.

Design consequences kept deliberately and listed in section 7:

- If storage cannot be read during reconciliation, the table cannot tell a rolled-back commit
  from a committed one and fails closed (local `VOIDED`, reservation released, original error).
  The durable round, if it exists, is intact and `reload_history` recovers it once storage
  answers; this ambiguity is documented, not claimed reconciled.
- A `SETTLING -> VOIDED` force does not append a history entry (pre-existing behaviour).
- Store-owned and left unchanged: `submit_round` durably voids a sampled-then-rolled-back round
  only for `Exception`; a `BaseException` such as `KeyboardInterrupt` is rolled back but not
  durably voided, so only the table-side phase guard prevents a redraw of that round in-process.

## 4. Regression suite and pre-fix evidence (AC-005) -- INITIAL revision, historical

The first eight tests of `tests/test_settlement_failure_recovery.py` were written and run **before**
`table.py` was changed and are kept as-is except for the one noted below.
It drives the real `open_table` / `DurableRoundStore` with a temporary workspace, the deterministic
entropy source and a one-shot `fault_hook` that raises exactly once at the requested stage.

| Test | Covers |
| --- | --- |
| `test_the_injected_stages_are_the_ones_the_store_declares` | the three pre-commit stages are in the store's `FAULT_STAGES` |
| `test_an_unclassified_failure_at_any_pre_commit_stage_voids_the_round_and_frees_the_table` | `RuntimeError` and `sqlite3.OperationalError` x `after_draw`/`after_ledger`/`before_commit`: same exception object propagates, nothing committed, round terminal, reservation 0, retry refused without a draw, next round settles (AC-001/002/003) |
| `test_the_stage_that_failed_determines_the_phase_the_round_had_reached` | the walk prefix recorded before the fault, final phase `VOIDED` |
| `test_a_failure_inside_the_table_settlement_itself_is_recovered_the_same_way` | `ValueError` from `_settle_round` (patched) is recovered identically |
| `test_a_keyboard_interrupt_during_commit_propagates_and_releases_the_table` | `KeyboardInterrupt` at each pre-commit stage propagates unchanged and releases the table (AC-003) |
| `test_a_durable_state_error_before_commit_is_still_reported_as_commit_denied` | existing `COMMIT_DENIED` 409 mapping unchanged |
| `test_an_rng_refusal_after_draw_is_still_reported_as_draw_denied` | existing `DRAW_DENIED` mapping unchanged |
| `test_a_failure_after_the_commit_keeps_exactly_one_settlement_and_frees_the_table` | **removed in 1.2.0**: it asserted only "terminal", called `reload_history` by hand and required a same-id retry to be `PHASE_DENIED`, i.e. it encoded the rejected behaviour. Replaced by section 4b, which is strictly stronger; no other assertion changed. |

Pre-fix run against the unmodified `table.py` (base `dd48059`):

```
python -m unittest tests.test_settlement_failure_recovery -v
Ran 8 tests ... FAILED (failures=14)
```

The 14 failures (counting subtests) were: 6 in the unclassified-failure test (2 exception types x
3 stages), 3 in the stage/phase test, 1 in the in-table settlement test, 3 in the
`KeyboardInterrupt` test, 1 in the `after_commit` test. Each reported the round left in
`SPINNING` (`after_draw`) or `SETTLING` (`after_ledger`, `before_commit`, `after_commit`) with
`reserved_units == 25`, and `new_round` refused with `ROUND_IN_PROGRESS`. The 3 tests that passed
pre-fix are the stage-declaration test and the two typed-mapping regressions, which confirms the
typed paths were already correct and that the suite exercises the gap rather than the existing
handlers. No test assertion was weakened between the pre-fix and post-fix runs.

Post-fix run of the same suite: `Ran 8 tests ... OK`.

## 4b. Strengthened post-commit tests (AC-006) -- REWORK revision

`PostCommitFaultTests` (5 tests, 8 subtests) inject at `after_commit` and inspect the **immediate**
snapshot; `reload_history` is only compared against it, never used to repair it.

| Test | Asserts |
| --- | --- |
| `test_a_fault_after_the_commit_reconciles_to_the_settled_round` (x `RuntimeError`, `sqlite3.OperationalError`, `KeyboardInterrupt`) | same exception instance propagates; snapshot is `SETTLED` (never `VOIDED`) with walk `LOCKED,SPINNING,SETTLING,SETTLED`; `result.pocket/proof_hash/settled_at/round_id` equal `store.draw_record`; settlement transaction exists for the round; `balance_units == opening + net_change`, house matches store, `reserved_units == 0`; `recent_results == [round]` and equals `reload_history()`; same-id `spin` replays (`replayed: True`, identical result); new-id spin/bet `PHASE_DENIED`; entropy, draw, ledger transaction and ledger entry counts unchanged; next round settles (2 draws, 2 transactions, chain clean) |
| `test_the_reconciled_result_is_what_the_store_replays` | adopted pocket/proof/transaction id/audit refs/balance equal an explicit `submit_round` replay, which consumes no entropy |
| `test_a_stored_record_for_another_round_is_not_adopted` | `draw_record` patched to return the real record under another `round_id`: original error kept, local `VOIDED` with `result: null`, reservation 0, durable round intact, no redraw, next round settles |
| `test_a_reconciliation_read_failure_keeps_the_original_error_and_fails_closed` (x `draw_record` outage, `submit_round` replay outage) | the outage does not replace the fault; local fail-closed `VOIDED`, reservation 0, durable round intact and recoverable by `reload_history`, retry refused without a draw |
| `test_a_failure_inside_the_cleanup_itself_still_preserves_the_original_error` | `_transition` raising on the terminal step: original error still the one raised, phase terminal, reservation 0, `new_round` opens |

Evidence the new tests catch the rejected behaviour, run in-process against the INITIAL semantics
(`_recover_after_submit_failure` replaced by a plain `_fail_round` call, which is exactly what the
1.1.0 handler did), without touching files:

```
PostCommitFaultTests under INITIAL emulation: Ran 5 tests, FAILED (failures=5, errors=1)
  reconcile x3 subtests: AssertionError: 'VOIDED' != 'SETTLED'
  store-replay test: result is None; other-round test: draw_record never consulted;
  cleanup-defect test: RuntimeError('cleanup defect') replaced the injected fault
```

The read-outage test passes under both revisions because fail-closed is the required outcome
there; it exists to keep a false SETTLED from slipping through, not to demonstrate the defect.

## 5. Commands run on the fixed revision

| Command | Result |
| --- | --- |
| INITIAL: `python -m unittest tests.test_settlement_failure_recovery -v` (pre-fix, base `dd48059`) | FAIL (8 tests, failures=14) -- pre-commit defect demonstrated |
| INITIAL: same, post-fix 1.1.0 | PASS (8 tests) -- historical; the post-commit test in that run is the one since removed |
| REWORK: `PostCommitFaultTests` under INITIAL emulation (section 4b) | FAIL (5 tests, failures=5, errors=1) -- AC-006 defect demonstrated |
| REWORK: `python -m unittest tests.test_settlement_failure_recovery -v` | PASS (12 tests, OK) |
| REWORK: `python -m unittest tests.test_roulette_web_server tests.test_reconnect_continuity tests.test_durable_state tests.test_roulette_web_ui` | before repin: 211 tests, 2 failures + 1 error, all the stale `table.py` pin in `tasks/R2-NET-0003.json`; after repin: PASS (211 tests) |
| REWORK: `python scripts/scan_secrets.py` | PASS (no plaintext credential material, 228 files) |
| REWORK: `python -m unittest discover -s tests` (after metadata repin, before this artifact/handoff were rewritten) | 905 tests, errors=5, skipped=4 -- all five were the 1.1.0 artifact of this unit still pinning the old `table.py` hash |
| REWORK: `python scripts/validate_baseline.py` (same state) | FAIL at the same stale `ART-R4-FIX-0008` pin only |
| REWORK: `python -m unittest discover -s tests` (final metadata) | PASS (905 tests, OK, skipped=4) |
| REWORK: `python scripts/validate_baseline.py` (final metadata) | PASS (exit 0) |

The "before rewrite" rows are recorded so the sequence is honest: the handoff must carry `PASS`
for both required commands and can only be written after the code, tests and metadata are final,
so both commands were re-run on the final tree after the packet was written.

## 6. Transitive hash closure (AC-004)

`table.py` is pinned by canonical-LF `content_hash` in several historical task inputs and
artifact component fields, and those files are in turn pinned by later units. Exactly 21 hash
*values* in the same 10 existing files changed (the 1.1.0 values were replaced by 1.2.0 values in
place by byte-preserving string replacement, with the replacement count checked to be exactly 21);
every other byte of those files is identical to `HEAD`. No prose, status, rights, approval,
reviewer, assertion or validator line was touched.

| File | Field(s) | Points at | New value (prefix) |
| --- | --- | --- | --- |
| `artifacts/R4-UI-0006-artifact.json` | `specification.component_hash:apps/roulette_web/table.py` | `table.py` | `4721edb1` |
| `tasks/R2-NET-0003.json` | `inputs[]` content_hash | `table.py` | `4721edb1` |
| `tasks/R2-LOAD-0004.json` | `inputs[]` content_hash x2 | `table.py`, `tasks/R2-NET-0003.json` | `4721edb1`, `bba297b4` |
| `tasks/R2-SEC-0005.json` | `inputs[]` content_hash x3 | `table.py`, `tasks/R2-NET-0003.json`, `tasks/R2-LOAD-0004.json` | `4721edb1`, `bba297b4`, `6914fd6e` |
| `artifacts/R2-NET-0003-artifact.json` | `source.input_hash`, `specification.task_contract_hash` | `tasks/R2-NET-0003.json` | `bba297b4` |
| `artifacts/R2-LOAD-0004-artifact.json` | `source.input_hash`, `specification.task_contract_hash` | `tasks/R2-LOAD-0004.json` | `6914fd6e` |
| `artifacts/R2-SEC-0005-artifact.json` | `specification.task_contract_hash` only | `tasks/R2-SEC-0005.json` | `0c7f1739` |
| `tasks/R2-QA-0006.json` | `inputs[]` content_hash x6 | R2-NET-0003 task+artifact, R2-LOAD-0004 task+artifact, R2-SEC-0005 task+artifact | `bba297b4`, `0d506dfa`, `6914fd6e`, `83bb2809`, `0c7f1739`, `87e8240a` |
| `artifacts/R2-QA-0006-artifact.json` | `source.input_hash`, `specification.task_contract_hash` | `tasks/R2-QA-0006.json` | `56103d62` |
| `tasks/SYS-QA-0015.json` | `inputs[]` content_hash | `artifacts/R4-UI-0006-artifact.json` | `50008c0f` |

Full values (1.2.0): `table.py` `sha256:4721edb1d14d64829f750f6e403e5b72dc992be58fe4db22454f238939e1dd16`
(1.1.0 was `6dfe0772...`, base `22397b7d...`); `tests/test_settlement_failure_recovery.py`
`sha256:3fa1ae41df07105d6cac63ff31a7f4b27f0e43f02b38df6f582ddfc57a1d7840` (1.1.0 was `cef6626b...`).
`tasks/R4-FIX-0008.json` was changed by the issuer (AC-006) and now hashes
`sha256:f38928a7af50a3e554297519ddcea42d08095fb0b2e9f132efb37b63c5e6a7d9`; the artifact fields
`source.input_hash` / `task_contract_hash` follow it. The task file itself was not edited by A-02.

Deliberately **not** changed, with the reason:

- `artifacts/R2-SEC-0005-artifact.json` `source.input_hash` points at
  `docs/operations/R2-followup-units.md` (asserted by `tests/test_security_verification.py`), not at
  the task file, so it is not part of the closure. An intermediate repin pass touched it by mistake
  and it was restored to its `HEAD` value before any validation run reported here.
- `artifacts/R4-UI-0006-artifact.json` `source.input_hash` points at `operations/collaboration.yaml`
  and is unaffected.
- `artifacts/SYS-QA-0015-artifact.json` historical fields such as
  `r4_ui_0006_artifact_hash_after_repin` were already stale at `HEAD` and are historical prose of
  that unit; they are not validated and were left alone rather than rewritten.
- `tasks/R4-ART-0007.json` / `artifacts/R4-ART-0007-artifact.json` do not pin `table.py`, so the
  R4-ART provenance repin that AC-004 pre-authorised was **not needed** and no art metadata changed.
- `tasks/R4-FIX-0008.json` inputs (`AGENTS.md`, `operations/collaboration.yaml`) are unchanged.

## 7. Remaining risks and deferred items

| Severity | Risk | Owner |
| --- | --- | --- |
| CLOSED in 1.2.0, pending review | The 1.1.0 MEDIUM item (local `VOIDED` after `after_commit`) was a correctness defect, not an accepted risk. Fixed per AC-006; the rejecting reviewer and `A-50` have not yet re-examined it. | `A-50` |
| MEDIUM | Storage-read outage during post-commit reconciliation: the table fails closed (local `VOIDED`, original error) while the durable round may be `SETTLED`. The player sees no result for that round until `reload_history`/restart; balances are store-derived so nothing is lost or double-paid. Not claimed reconciled. | `A-02` / `A-50` |
| LOW | If `_snapshot` fails *after* the round was adopted (storage read while building the response), the round is `SETTLED` with its result but has no journal entry, so a same-id retry is `PHASE_DENIED` rather than a replay. A refusal, not a false success. | `A-02` |
| LOW | `SETTLING -> VOIDED` forced transitions still add no history entry (pre-existing). | `A-02` |
| LOW | Store-owned, unchanged: `submit_round` skips the durable void for `BaseException` (`KeyboardInterrupt`) after a sampled-then-rolled-back draw; only the table phase guard blocks a redraw in the same process. Durable handling after restart is store behaviour outside this unit. | `A-50` |
| LOW | apply_patch wrote LF line endings into a CRLF working copy of `table.py`; the git index (`text=auto`) normalises to LF, `git diff` shows only the intended hunks, and canonical hashing is EOL-independent. Codex should confirm the committed blob is clean. | `A-50` |
| INFO | Client reconnect, rebet and HTTP method-handling defects remain deferred to separate units per the task's `open_decisions`. | `A-50` |

## 8. Separation of roles

- `A-02` (this document): implementation, regression tests, self-check runs. **Not** a review.
- Claude code review: a separate read-only Fable reviewer rejected 1.1.0 on `after_commit`;
  review of 1.2.0 is `NOT_RUN` here.
- Codex independent verification (`A-50`): `NOT_RUN` here; the handoff requests it.
- Browser QA, art/rights, `A-00`/`USER` final gate: `NOT_RUN`, unchanged by this unit.

Nothing in this unit was committed or pushed by the implementer; Codex owns the Git workflow.
