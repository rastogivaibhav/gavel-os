/**
 * types.ts — TypeScript interfaces that exactly mirror the Gavel Pydantic models.
 *
 * Source of truth for each interface:
 *   GavelHealthResponse      → control-plane/api/main.py  health_check()
 *   ValidateRequest/Response → control-plane/api/routes/external.py  ValidateRequest
 *   AuditEntry               → control-plane/api/routes/audit.py  query_audit_ledger()
 *   RuntimeEventEnvelope     → control-plane/api/runtime_contract.py  RuntimeEventEnvelope
 *   PolicySet/Rule/Condition → control-plane/srp/policy.py
 *   Proposal/CallerContext   → control-plane/srp/models.py
 */

// ── Health ────────────────────────────────────────────────────────────────────

export interface GavelHealthResponse {
  status: 'healthy' | 'degraded';
  service: string;
  version: string;
  components: {
    audit_ledger: string;
    policy_loader: string;
    verdict_engine: string;
    machine_auth: string;
    grpc_authz: string;
    opa_policy_engine: string;
    database: string;
    redis: string;
  };
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export interface TokenRequest {
  role?: string;
  customer_id?: string;
  tenant_id?: string;
  clearance_level?: number;
  department?: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// ── Policy validation (external/validate) ────────────────────────────────────
// Mirrors ValidateRequest in control-plane/api/routes/external.py

export interface ValidateRequest {
  action: string;
  method?: string;
  target_tenant_id?: string;
  required_clearance?: number;
}

export interface ValidateResponse {
  is_allowed: boolean;
  reason: string;
}

// ── Audit ledger ──────────────────────────────────────────────────────────────
// Mirrors LedgerQueryParams and the response shape from audit.py

export interface LedgerQueryParams {
  start_date: string;   // ISO 8601
  end_date: string;
  actor?: string;
  tenant_id?: string;
}

export interface AuditEvent {
  recipe_id: string;
  step_id: string;
  actor: string;
  action: string;
  target_system: string;
  outcome: string;
  timestamp: string;
}

export interface AuditEntry {
  id: number;
  previous_hash: string;
  current_hash: string;
  event: AuditEvent;
}

export interface LedgerQueryResponse {
  count: number;
  entries: AuditEntry[];
}

export interface ChainVerifyResponse {
  is_valid: boolean;
  corrupted_entries: number[];
  verified_at: string;
}

// ── Runtime telemetry ─────────────────────────────────────────────────────────
// Mirrors RuntimeEventEnvelope in control-plane/api/runtime_contract.py

export type RuntimeEventType =
  | 'agent_detected'
  | 'policy_verdict'
  | 'network_verdict'
  | 'component_health'
  | 'audit_append_result'
  | 'authz_failure';

export type RuntimeVerdict = 'ALLOW' | 'DENY' | 'AUDIT' | 'INFO' | 'DEGRADED';
export type RuntimeOS = 'linux' | 'windows' | 'macos';

export interface RuntimeEventEnvelope {
  event_type: RuntimeEventType;
  event_time: string;
  host_id: string;
  runtime_os: RuntimeOS;
  runtime_arch: string;
  agent_id?: string;
  target: string;
  verdict: RuntimeVerdict;
  reason_code: string;
  metadata: Record<string, unknown>;
}

// ── Policy models ─────────────────────────────────────────────────────────────
// Mirrors PolicySet / PolicyRule / PolicyCondition in control-plane/srp/policy.py

export type PolicyEffect = 'ALLOW' | 'BLOCK' | 'ESCALATE';

// Mirrors PolicyCondition — all fields optional, all list fields min_length=1
export interface PolicyCondition {
  tenants?: string[];
  roles?: string[];
  environments?: Array<'dev' | 'staging' | 'prod'>;
  api_refs?: string[];
  operations?: string[];
  max_numeric_parameters?: Record<string, number>;
}

// Mirrors PolicyRule
export interface PolicyRule {
  id: string;
  description: string;
  effect: PolicyEffect;
  condition: PolicyCondition;
  priority?: number;   // default 1000 in Python
}

// Mirrors PolicySet (model_config = ConfigDict(extra="forbid"))
export interface PolicySet {
  name: string;
  version: string;
  rules: PolicyRule[];
}

// ── Proposal models ───────────────────────────────────────────────────────────
// Mirrors Proposal / CallerContext / ToolCall in control-plane/srp/models.py

export interface CallerContext {
  tenant_id: string;
  caller_id: string;
  role?: string;
  session_id?: string;
  ip_address?: string;
  user_agent?: string;
}

export interface ToolCall {
  api_ref: string;
  operation: string;
  parameters?: Record<string, unknown>;
  recipe_id?: string;
  tool_name?: string;
}

// Mirrors Literal["dev","staging","prod"] and Literal["openai","crew",...]
export type ProposalEnvironment = 'dev' | 'staging' | 'prod';
export type ProposalOrigin = 'openai' | 'crew' | 'langgraph' | 'openclaw' | 'internal' | 'other';

export interface Proposal {
  caller: CallerContext;
  tool_call: ToolCall;
  environment: ProposalEnvironment;
  origin: ProposalOrigin;
  replay_nonce: string;
}

// ── Verdict ───────────────────────────────────────────────────────────────────
// Mirrors Verdict / VerdictReason in control-plane/srp/models.py

export type VerdictType = 'ALLOW' | 'BLOCK' | 'ESCALATE';

export interface VerdictReason {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface VerdictResponse {
  proposal_id: string;
  verdict: VerdictType;
  reasons: VerdictReason[];
  policy_ids: string[];
  timestamp: string;
}
