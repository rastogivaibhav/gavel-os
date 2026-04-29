-- Multi-tenancy support
-- Add tenant_id column to existing tables
-- This migration assumes audit_ledger table exists from previous setup

BEGIN;

-- Ensure tenants table exists for reference
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Add comment documenting tenant table
COMMENT ON TABLE tenants IS 'Registered tenants for multi-tenant isolation';

-- Ensure default tenant exists
INSERT INTO tenants (id, name) VALUES ('default', 'Default Tenant')
    ON CONFLICT (id) DO NOTHING;

-- Add tenant_id to audit_ledger if not exists
ALTER TABLE audit_ledger
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

-- Add index for tenant-based queries
CREATE INDEX IF NOT EXISTS idx_audit_ledger_tenant_id
    ON audit_ledger(tenant_id);

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_audit_ledger_tenant_created
    ON audit_ledger(tenant_id, created_at DESC);

-- Add foreign key constraint (may be skipped if audit_ledger exists without FK)
-- This is commented out to avoid breaking existing databases
-- ALTER TABLE audit_ledger
--     ADD CONSTRAINT fk_audit_ledger_tenant
--     FOREIGN KEY (tenant_id) REFERENCES tenants(id)
--     ON DELETE RESTRICT
--     ON UPDATE CASCADE;

-- Audit ledger should have RLS to prevent cross-tenant data access
-- Note: This requires row-level security to be enabled on the database
-- Enable RLS if not already enabled
ALTER TABLE audit_ledger ENABLE ROW LEVEL SECURITY;

-- Create RLS policy for tenant isolation (if not exists)
-- Note: This prevents all access unless explicitly granted
-- Individual row access policies should be created per application role
COMMENT ON TABLE audit_ledger IS 'Immutable audit ledger with SHA-256 chaining and tenant isolation';

COMMIT;
