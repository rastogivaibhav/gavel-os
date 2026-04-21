# Enterprise Features

## Security

### Authentication

| Method | Mechanism | Use case |
|---|---|---|
| Machine key | HMAC `compare_digest` | Enforcer → control plane (all enforcer endpoints) |
| Bearer JWT | RS256, auto-generated RSA-2048 | REST API clients |
| API key | HMAC `compare_digest` | Service accounts, Prometheus scrape |
| Admin secret | Header + env var | Admin JWT minting only |

### JWT key rotation

Set `JWKS_URL` to an external JWKS endpoint. Tokens signed by any key in the JWKS are accepted alongside the local key. The local key is always tried first (zero network latency on the hot path). Remote keys are cached with configurable TTL (`JWKS_CACHE_TTL_SECONDS`, default 300s).

The public key is available at `GET /auth/jwks` and `GET /.well-known/jwks.json` for downstream services to verify tokens without calling back to the control plane.

### gRPC TLS

The ext_authz gRPC server (port 50051) supports three modes:

| Mode | Configuration | Use case |
|---|---|---|
| Server TLS | `GRPC_TLS_CERT_PATH` + `GRPC_TLS_KEY_PATH` | Standard production |
| mTLS | + `GRPC_CA_CERT_PATH` | High-assurance, verifies Envoy client cert |
| Insecure | `GRPC_INSECURE=true` (dev only) | Local development |

`GRPC_INSECURE=true` causes `sys.exit(1)` if `ENV != development`. There is no way to accidentally run insecure in production.

### Fail-closed enforcement

When the control plane is unreachable, the enforcer denies all connections by default. This is the correct security posture — availability is sacrificed in favour of security. `GAVEL_FAIL_OPEN=true` inverts this and must never be set in production.

---

## Audit & Compliance

### Cryptographic audit ledger

Every enforcement decision and agent action is written to a SHA-256 hash-chained PostgreSQL table:

```
current_hash = SHA-256(previous_hash + event_json)
```

Properties:
- **Tamper-evident:** Modifying any historical entry breaks the chain from that point forward
- **Append-only:** PostgreSQL `NO UPDATE / NO DELETE` rules prevent modification at the database level
- **Verifiable:** `POST /audit/verify` walks the entire chain and reports any corrupted entries

For high-assurance environments, use a dedicated PostgreSQL role with `INSERT`-only privileges on `audit_ledger` to prevent superuser bypass.

### Audit query API

```bash
# Query by actor and time range
curl -X POST http://localhost:8000/audit/ledger \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "start_date": "2026-01-01T00:00:00Z",
    "end_date": "2026-12-31T23:59:59Z",
    "actor": "agent-1",
    "tenant_id": "acme"
  }'

# Verify chain integrity
curl -X POST http://localhost:8000/audit/verify \
  -H "Authorization: Bearer $TOKEN" \
  -d '{}'
```

---

## Observability

### Prometheus metrics

The control plane exposes Prometheus metrics at `GET /metrics`. Authentication required (`X-API-Key: <METRICS_SECRET_KEY>`).

Key metrics:
- `http_requests_total` — request count by endpoint and status
- `http_request_duration_seconds` — latency histograms
- `gavel_policy_decisions_total` — ALLOW/DENY/AUDIT counts
- `gavel_audit_ledger_appends_total` — ledger write throughput

### OpenTelemetry tracing

Set `ENABLE_OTLP=true` and `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces to Jaeger, Datadog, or any OTLP-compatible collector. FastAPI, asyncpg, and Redis are all instrumented.

### Real-time telemetry

Connect to `WebSocket /ws/telemetry` for a real-time stream of all enforcement events. Useful for building dashboards and alerting integrations.

Event types: `agent_detected`, `policy_verdict`, `network_verdict`, `component_health`, `audit_append_result`, `authz_failure`.

---

## Multi-tenancy

The runtime contract includes `tenant_id` on all requests. OPA policies can enforce tenant isolation:

```rego
allow if {
    input.identity.tenant_id == input.resource.target_tenant_id
    input.identity.is_authenticated == true
    input.identity.clearance_level >= input.resource.required_clearance
}
```

The audit ledger is partitioned by `tenant_id` — queries are always scoped to a single tenant.

---

## RBAC

The JWT claim model supports role-based access control:

| Role | Capabilities |
|---|---|
| `admin` | Full access; requires `X-Admin-Secret` to mint |
| `customer` | Standard API access; clearance-level gated |
| `runtime_machine` | Enforcer-to-control-plane; machine-key authenticated |
| `external` | Restricted; blocked from production by default policy |
| `anonymous` | No access |

Clearance levels (1–5) provide fine-grained resource access control independent of role.

---

## Rate limiting

All enforcer-facing endpoints are rate-limited per `X-Gavel-Host-Id` to prevent a misbehaving enforcer from DoS-ing the control plane:

| Endpoint | Default limit | Env var |
|---|---|---|
| `/external/runtime/validate` | 200/minute | `RATE_LIMIT_VALIDATE` |
| `/external/heartbeat` | 4/minute | `RATE_LIMIT_HEARTBEAT` |
| `/internal/telemetry/push` | 300/minute | `RATE_LIMIT_TELEMETRY` |
| `/external/runtime/policy` | 30/minute | `RATE_LIMIT_POLICY` |

Limits are enforced in Redis when `REDIS_URL` is set, shared across all control plane replicas.

---

## High availability

The control plane is stateless — all state is in PostgreSQL and Redis. Scale horizontally:

```bash
kubectl scale deployment gavel-control-plane --replicas=5 -n gavel-system
```

The Kubernetes deployment includes topology spread constraints to distribute replicas across nodes. The Helm chart supports configurable replica counts.

---

## Compliance readiness

| Framework | Coverage |
|---|---|
| OWASP Agentic Top 10 | 9/10 risks addressed (ASI-06 out of scope) |
| NIST AI RMF | Audit trail, access control, monitoring |
| EU AI Act (high-risk systems) | Audit logging, human oversight escalation path |
| SOC 2 Type II | Audit ledger, access controls, monitoring |

Gavel does not provide compliance certifications. It provides the technical controls that compliance frameworks require. Certification requires independent audit.

---

## Known limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| macOS enforcement is audit-only | Cannot block connections on macOS | System Extension enforcement planned for v1.1 |
| Audit ledger not tamper-proof against DB superuser | PostgreSQL superuser can bypass `NO UPDATE/NO DELETE` | Use INSERT-only role in high-assurance environments |
| IPv6 not supported in Linux eBPF enforcer | IPv6 connections not intercepted | IPv6 support planned for v1.1 |
| Windows WFP uses PowerShell subprocess | Restricted execution policy may block enforcement | Native WFP callout planned for v1.1 |
