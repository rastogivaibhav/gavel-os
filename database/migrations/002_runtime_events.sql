-- Migration 002: Runtime events table
-- Stores structured runtime telemetry from enforcers for fast querying.
-- The audit_ledger is the tamper-evident record; this table is the
-- queryable projection for dashboards and alerting.

BEGIN;

CREATE TABLE IF NOT EXISTS runtime_events (
    id              BIGSERIAL    PRIMARY KEY,
    event_type      TEXT         NOT NULL,
    event_time      TIMESTAMPTZ  NOT NULL,
    host_id         TEXT         NOT NULL,
    runtime_os      TEXT         NOT NULL,
    runtime_arch    TEXT         NOT NULL,
    agent_id        TEXT,
    target          TEXT         NOT NULL,
    verdict         TEXT         NOT NULL,
    reason_code     TEXT         NOT NULL,
    metadata        JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_runtime_events_host_time
    ON runtime_events (host_id, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_runtime_events_verdict
    ON runtime_events (verdict, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_runtime_events_type_time
    ON runtime_events (event_type, event_time DESC);

CREATE INDEX IF NOT EXISTS idx_runtime_events_target
    ON runtime_events (target, event_time DESC);

-- Partition hint: for high-volume deployments, partition by event_time (monthly).
-- Not applied here to keep the migration simple; add via ALTER TABLE in a later migration.

INSERT INTO schema_migrations (version, description)
VALUES (2, 'Runtime events table')
ON CONFLICT (version) DO NOTHING;

COMMIT;
