-- Core schema for Gavel OS audit ledger and governance
-- Migration 001: Foundation tables and indexes

CREATE TABLE IF NOT EXISTS schema_version (
    version INT PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    description TEXT
);

CREATE TABLE IF NOT EXISTS audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    request_id VARCHAR(255) NOT NULL,
    decision_type VARCHAR(50) NOT NULL,
    decision_value VARCHAR(50) NOT NULL,
    identity_context JSONB NOT NULL,
    resource_context JSONB NOT NULL,
    verdict_details JSONB,
    previous_hash VARCHAR(64),
    current_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_audit_ledger_tenant_id ON audit_ledger(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_ledger_created_at ON audit_ledger(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_ledger_request_id ON audit_ledger(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_ledger_decision_type ON audit_ledger(decision_type);

-- Insert initial schema version
INSERT INTO schema_version (version, description) VALUES (1, 'Core schema: audit_ledger')
ON CONFLICT (version) DO NOTHING;
