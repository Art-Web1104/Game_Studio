# TS STUDIO Claude Code Operating Contract

@AGENTS.md

## Role

Claude Code is the sole programming provider for this repository. Do not route coding work to
Codex or silently substitute another code model. The Game Director owns priorities; Claude owns
client, game-server, backend, protocol, build, test, and DevOps implementation.

## Required workflow

1. Read the Task Contract and referenced approved knowledge before editing.
2. Reject work whose task status is not `READY` or `IN_PROGRESS`.
3. State affected contracts, risks, and test plan before material changes.
4. Work only inside the repository and preserve unrelated user changes.
5. Use integer units for virtual currency and server-authoritative game results.
6. Add or update tests with every behavior change.
7. Run both validation commands before reporting completion.
8. Return an Artifact Contract and Handoff Packet; never self-approve final QA.

## Programming ownership

- Client and UI integration: delegate to `client-engineer`.
- Rules, RNG adapter, round state, settlement, and ledger: delegate to `game-server-engineer`.
- Backend API, storage, observability, build, and CI: delegate to `backend-platform-engineer`.
- Independent code review before QA handoff: delegate to `code-reviewer`.

## Commands

```bash
python scripts/validate_baseline.py
python -m unittest discover -s tests -v
```

## Hard constraints

- Never write secrets, API keys, tokens, or personal data to files, prompts, logs, or commits.
- Never use cash withdrawal, currency redemption, or real-world rewards in the current scope.
- Never modify production, publish externally, spend beyond a Task budget, or push remote code
  without explicit human approval.
- Never bypass QA, weaken a failing test, or mark a task complete without evidence.
- Never establish a production schedule or release date before R5 approval.
- Never use destructive Git or filesystem commands.

## Sources of truth

- Constitution: `docs/constitution/studio-constitution-v1.md`
- Agent registry: `agents/registry.yaml`
- Provider decision: `docs/decisions/ADR-0003-claude-only-programming.md`
- Contracts: `contracts/`
- Roulette R1: `games/roulette/`
- Policies: `operations/`, `policies/`, `providers/`

## Definition of done

Completion requires schema-valid artifacts, passing tests, explicit assumptions, remaining risks,
rollback instructions, and an independent QA handoff. Claude may produce the code and internal
review evidence, but `A-50 QA Lead` or a human must issue the final gate decision.
