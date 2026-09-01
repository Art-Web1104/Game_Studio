-- R2-DBC-0002 durable-state schema, version 1.
--
-- Published form of studio_core.durable_state.SCHEMA_STATEMENTS. The baseline validator
-- rejects any drift between this file and the statements the implementation executes, so a
-- reviewer can read the storage contract without reading the module.
--
-- Isolation:    SQLite serializable; every authoritative write opens BEGIN IMMEDIATE.
-- Journal mode: WAL          Durability pragma: synchronous=FULL
-- Foreign keys: ON           Busy timeout: 5000 ms
--
-- Currency is integer minimum units only; typeof() CHECK constraints reject a float even
-- when it arrives through raw SQL. Entropy bytes and seed material are never columns here.
--
-- Write order for a settlement is entries first, then the ledger_transaction row. A CHECK
-- constraint can only see one row, so the zero-sum rule is enforced by a trigger that fires
-- once the transaction row arrives and can count and total its entries. The deferred foreign
-- key is what makes that order legal, and ledger_entry_precedes_its_transaction closes the
-- other end: once a transaction row exists, no entry may be added to unbalance it.

CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE audit_event (
    event_seq           INTEGER PRIMARY KEY,
    event_id            TEXT NOT NULL UNIQUE,
    audit_ref           TEXT NOT NULL UNIQUE,
    event_hash          TEXT NOT NULL UNIQUE,
    previous_event_hash TEXT,
    action              TEXT NOT NULL,
    round_id            TEXT,
    recorded_at         TEXT NOT NULL,
    body_json           TEXT NOT NULL,
    CHECK (typeof(event_seq) = 'integer' AND event_seq > 0)
);

CREATE TRIGGER audit_event_is_append_only_update
BEFORE UPDATE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TRIGGER audit_event_is_append_only_delete
BEFORE DELETE ON audit_event
BEGIN
    SELECT RAISE(ABORT, 'audit_event is append-only');
END;

CREATE TABLE account (
    account_id    TEXT PRIMARY KEY,
    account_type  TEXT NOT NULL,
    balance_units INTEGER NOT NULL,
    CHECK (account_type IN ('PLAYER', 'BET_ESCROW', 'HOUSE_BANKROLL', 'SYSTEM_CLEARING')),
    CHECK (typeof(balance_units) = 'integer'),
    CHECK (account_type <> 'PLAYER' OR balance_units >= 0)
);

CREATE TABLE ledger_transaction (
    transaction_id      TEXT PRIMARY KEY,
    idempotency_key     TEXT NOT NULL UNIQUE,
    round_id            TEXT NOT NULL,
    transaction_type    TEXT NOT NULL,
    currency            TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    audit_event_seq     INTEGER NOT NULL REFERENCES audit_event(event_seq),
    payload_json        TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    CHECK (transaction_type IN ('BET_RESERVE', 'BET_CANCEL', 'ROUND_SETTLEMENT', 'ROUND_VOID')),
    CHECK (currency = 'VIRTUAL_CHIP')
);

CREATE TABLE ledger_entry (
    entry_seq      INTEGER PRIMARY KEY,
    transaction_id TEXT NOT NULL
                   REFERENCES ledger_transaction(transaction_id) DEFERRABLE INITIALLY DEFERRED,
    account_id     TEXT NOT NULL REFERENCES account(account_id),
    account_type   TEXT NOT NULL,
    amount_units   INTEGER NOT NULL,
    CHECK (account_type IN ('PLAYER', 'BET_ESCROW', 'HOUSE_BANKROLL', 'SYSTEM_CLEARING')),
    CHECK (typeof(amount_units) = 'integer' AND amount_units <> 0)
);

CREATE TRIGGER ledger_entry_precedes_its_transaction
BEFORE INSERT ON ledger_entry
BEGIN
    SELECT RAISE(ABORT, 'a settled ledger transaction cannot gain further entries')
    WHERE EXISTS (SELECT 1 FROM ledger_transaction WHERE transaction_id = NEW.transaction_id);
END;

CREATE TRIGGER ledger_transaction_must_balance
AFTER INSERT ON ledger_transaction
BEGIN
    SELECT RAISE(ABORT, 'a ledger transaction requires at least two entries')
    WHERE (SELECT COUNT(*) FROM ledger_entry WHERE transaction_id = NEW.transaction_id) < 2;
    SELECT RAISE(ABORT, 'ledger entries must sum to zero')
    WHERE (SELECT SUM(amount_units) FROM ledger_entry WHERE transaction_id = NEW.transaction_id) <> 0;
END;

CREATE TRIGGER ledger_transaction_is_immutable_update
BEFORE UPDATE ON ledger_transaction
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger transaction is immutable');
END;

CREATE TRIGGER ledger_transaction_is_immutable_delete
BEFORE DELETE ON ledger_transaction
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger transaction is immutable');
END;

CREATE TRIGGER ledger_entry_is_immutable_update
BEFORE UPDATE ON ledger_entry
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger entry is immutable');
END;

CREATE TRIGGER ledger_entry_is_immutable_delete
BEFORE DELETE ON ledger_entry
BEGIN
    SELECT RAISE(ABORT, 'a posted ledger entry is immutable');
END;

CREATE TABLE draw_record (
    request_id                TEXT PRIMARY KEY,
    round_id                  TEXT NOT NULL UNIQUE,
    request_fingerprint       TEXT NOT NULL,
    pocket                    INTEGER NOT NULL,
    proof_hash                TEXT NOT NULL,
    audit_event_seq           INTEGER NOT NULL REFERENCES audit_event(event_seq),
    settlement_transaction_id TEXT REFERENCES ledger_transaction(transaction_id),
    payload_json              TEXT NOT NULL,
    created_at                TEXT NOT NULL,
    CHECK (typeof(pocket) = 'integer' AND pocket BETWEEN 0 AND 36)
);

CREATE TRIGGER draw_record_is_immutable
BEFORE UPDATE OF request_id, round_id, pocket, proof_hash, payload_json ON draw_record
BEGIN
    SELECT RAISE(ABORT, 'an authoritative draw record is immutable');
END;

CREATE TABLE round_void (
    round_id        TEXT PRIMARY KEY,
    reason          TEXT NOT NULL,
    audit_event_seq INTEGER NOT NULL REFERENCES audit_event(event_seq),
    created_at      TEXT NOT NULL
);
