-- Migration 003: Tenants and escalation workflow tables

BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE tenants IS 'Registered tenants for multi-tenant isolation';

INSERT INTO tenants (id, name)
VALUES ('default', 'Default Tenant')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE audit_ledger ENABLE ROW LEVEL SECURITY;
COMMENT ON TABLE audit_ledger IS 'Immutable audit ledger with SHA-256 chaining and tenant isolation';

CREATE TABLE IF NOT EXISTS escalations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    tool_call_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    api_ref TEXT NOT NULL,
    operation TEXT NOT NULL,
    environment TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    ticket_number TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deadline TIMESTAMPTZ NOT NULL,
    parameters JSONB,
    risk_level TEXT DEFAULT 'medium'
);

CREATE INDEX IF NOT EXISTS idx_escalations_tenant_id
    ON escalations(tenant_id);

CREATE INDEX IF NOT EXISTS idx_escalations_status
    ON escalations(status);

CREATE INDEX IF NOT EXISTS idx_escalations_deadline
    ON escalations(deadline);

CREATE INDEX IF NOT EXISTS idx_escalations_tool_call_id
    ON escalations(tenant_id, tool_call_id);

CREATE TABLE IF NOT EXISTS escalation_approvers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    approver_role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_escalation_approvers_tenant
    ON escalation_approvers(tenant_id);

CREATE TABLE IF NOT EXISTS escalation_approvals (
    id TEXT PRIMARY KEY,
    escalation_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_escalation_approvals_escalation
        FOREIGN KEY (escalation_id) REFERENCES escalations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_escalation_approvals_escalation_id
    ON escalation_approvals(escalation_id);

CREATE INDEX IF NOT EXISTS idx_escalation_approvals_tenant
    ON escalation_approvals(tenant_id);

CREATE TABLE IF NOT EXISTS escalation_notifications (
    id TEXT PRIMARY KEY,
    escalation_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'sent',
    sent_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_escalation_notifications_escalation
        FOREIGN KEY (escalation_id) REFERENCES escalations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_escalation_notifications_escalation_id
    ON escalation_notifications(escalation_id);

CREATE INDEX IF NOT EXISTS idx_escalation_notifications_tenant
    ON escalation_notifications(tenant_id);

ALTER TABLE escalations ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_approvers ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalation_notifications ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE escalations IS 'Tool proposal escalation records with approval workflow';
COMMENT ON TABLE escalation_approvers IS 'Users authorized to approve escalations for a tenant';
COMMENT ON TABLE escalation_approvals IS 'Approval decisions on escalations';
COMMENT ON TABLE escalation_notifications IS 'Notification log for escalation events';

INSERT INTO schema_migrations (version, description)
VALUES (3, 'Tenants and escalation workflow tables')
ON CONFLICT (version) DO NOTHING;

COMMIT;
