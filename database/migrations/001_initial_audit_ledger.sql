-- Migration 001: Initial audit ledger schema
-- Gavel OS — cryptographically chained audit ledger

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    description TEXT        NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Core audit ledger: each row is an immutable, hash-chained event.
-- previous_hash references the current_hash of the immediately preceding row
-- (ordered by id). The genesis row has previous_hash = 'genesis'.
CREATE TABLE IF NOT EXISTS audit_ledger (
    id             BIGSERIAL    PRIMARY KEY,
    tenant_id      TEXT         NOT NULL DEFAULT 'default',
    previous_hash  TEXT         NOT NULL,
    current_hash   TEXT         NOT NULL UNIQUE,
    event_json     JSONB        NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_audit_ledger_tenant_created
    ON audit_ledger (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_ledger_created
    ON audit_ledger (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_ledger_event_actor
    ON audit_ledger ((event_json->>'actor'));

CREATE INDEX IF NOT EXISTS idx_audit_ledger_event_recipe
    ON audit_ledger ((event_json->>'recipe_id'));

-- Prevent any UPDATE or DELETE on the ledger — it is append-only.
CREATE OR REPLACE RULE audit_ledger_no_update AS
    ON UPDATE TO audit_ledger DO INSTEAD NOTHING;

CREATE OR REPLACE RULE audit_ledger_no_delete AS
    ON DELETE TO audit_ledger DO INSTEAD NOTHING;

INSERT INTO schema_migrations (version, description)
VALUES (1, 'Initial audit ledger schema')
ON CONFLICT (version) DO NOTHING;

COMMIT;
