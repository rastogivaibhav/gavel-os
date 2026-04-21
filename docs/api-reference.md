# API Reference

The control plane exposes a REST API at port 8000 and a gRPC ext_authz interface at port 50051.

Interactive documentation is available at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` (ReDoc) when the control plane is running.

---

## Authentication

All endpoints except public paths require one of:

| Method | Header | Notes |
|---|---|---|
| Bearer JWT | `Authorization: Bearer <token>` | Issued by `POST /auth/token` |
| API key | `X-API-Key: <key>` | Set via `API_SECRET_KEY` env var |
| Machine key | `X-Gavel-Machine-Key: <key>` | Enforcer-to-control-plane only |

Public paths (no auth required): `/`, `/health`, `/readyz`, `/docs`, `/redoc`, `/openapi.json`, `/auth/token`, `/auth/jwks`, `/.well-known/jwks.json`

---

## Auth

### `POST /auth/token`

Issue a JWT token.

**Request:**
```json
{
  "role": "customer",
  "customer_id": "cust-123",
  "tenant_id": "default",
  "clearance_level": 1,
  "department": "external"
}
```

Admin tokens require `X-Admin-Secret: <ADMIN_SECRET_KEY>` header.

**Response:**
```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

### `GET /auth/jwks`

Return the public key set for JWT verification.

**Response:**
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "a1b2c3d4e5f6g7h8",
    "n": "<base64url>",
    "e": "AQAB"
  }]
}
```

Cache-Control header is set to `public, max-age=<JWKS_CACHE_TTL_SECONDS>`.

---

## Health

### `GET /health`

Component health check. Returns 200 when healthy, 503 when degraded.

**Response:**
```json
{
  "status": "healthy",
  "service": "gavel-control-plane",
  "version": "1.0.0",
  "components": {
    "audit_ledger": "connected",
    "policy_loader": "loaded",
    "verdict_engine": "ready",
    "machine_auth": "configured",
    "grpc_authz": "ready",
    "opa_policy_engine": "ready",
    "database": "connected",
    "redis": "connected"
  }
}
```

### `GET /readyz`

Kubernetes readiness probe. Returns 200 when all critical components are initialized.

---

## External (REST clients)

### `POST /external/validate`

Evaluate a policy decision for an action. Requires Bearer JWT or API key.

**Request:**
```json
{
  "action": "read.data",
  "method": "GET",
  "target_tenant_id": "default",
  "required_clearance": 1
}
```

**Response:**
```json
{
  "is_allowed": true,
  "reason": "Authorized by OPA"
}
```

---

### `POST /external/ingest`

Append an event to the audit ledger. Requires Bearer JWT or API key.

**Request:**
```json
{
  "recipe_id": "my-workflow",
  "step_id": "step-1",
  "action": "read.customer_data",
  "target_system": "crm.api",
  "outcome": "SUCCESS",
  "payload_hash": "sha256:abc123..."
}
```

**Response:**
```json
{
  "status": "ingested",
  "entry_id": 42,
  "hash": "sha256:def456..."
}
```

---

## External (Enforcer / Machine key)

All endpoints below require `X-Gavel-Machine-Key`.

### `POST /external/heartbeat`

Enforcer liveness signal. Called every 30 seconds.

**Request:**
```json
{
  "host_id": "prod-host-1-amd64",
  "runtime_os": "linux",
  "runtime_arch": "amd64",
  "runtime_mode": "enforce",
  "enforcement_capable": true,
  "component": "linux-runtime"
}
```

**Response:** `MachineHeartbeatResponse` with `reason_code: "HEARTBEAT_OK"` or `"CONTROL_PLANE_DEGRADED"`.

---

### `POST /external/runtime/validate`

Policy decision for a specific network action. Called per connection attempt.

**Request:**
```json
{
  "host_id": "prod-host-1-amd64",
  "runtime_os": "linux",
  "runtime_arch": "amd64",
  "runtime_mode": "enforce",
  "enforcement_capable": true,
  "action": "api.example.com",
  "method": "CONNECT",
  "target_tenant_id": "default",
  "required_clearance": 1,
  "agent_id": "cursor"
}
```

**Response:**
```json
{
  "is_allowed": true,
  "reason": "Authorized by OPA",
  "reason_code": "POLICY_ALLOW",
  "runtime_mode": "enforce",
  "enforcement_capable": true,
  "auth_status": "authenticated",
  "control_plane_status": "online",
  "host_id": "prod-host-1-amd64",
  "agent_id": "cursor",
  "runtime_os": "linux",
  "runtime_arch": "amd64"
}
```

---

### `POST /external/runtime/policy`

Fetch the current runtime policy for this host.

**Response:** `MachinePolicyResponse` with `monitored_pids`, `blocked_ipv4`, `blocked_targets`, `monitored_processes`, `proxy_ipv4`, `proxy_port`.

---

### `POST /external/detect_agent`

Report detection of an AI agent process.

---

## Audit

### `POST /audit/ledger`

Query audit ledger entries.

**Request:**
```json
{
  "start_date": "2026-01-01T00:00:00Z",
  "end_date": "2026-12-31T23:59:59Z",
  "tenant_id": "default",
  "actor": "agent-1"
}
```

**Response:**
```json
{
  "count": 3,
  "entries": [
    {
      "id": 1,
      "previous_hash": "genesis",
      "current_hash": "sha256:abc...",
      "event": {
        "recipe_id": "...",
        "actor": "agent-1",
        "action": "read.data",
        "outcome": "SUCCESS",
        "timestamp": "2026-04-21T10:00:00Z"
      }
    }
  ]
}
```

---

### `POST /audit/verify`

Verify chain integrity.

**Request:**
```json
{
  "start_date": "2020-01-01T00:00:00Z",
  "end_date": "2030-12-31T00:00:00Z"
}
```

**Response:**
```json
{
  "is_valid": true,
  "corrupted_entries": [],
  "verified_at": "2026-04-21T10:00:00Z"
}
```

---

## Telemetry

### `WebSocket /ws/telemetry`

Real-time event stream. Requires Bearer JWT, API key, or machine key.

Events are JSON objects with `type` and `payload` fields. Event types: `agent_detected`, `policy_verdict`, `network_verdict`, `component_health`, `AUDIT_LOG`, `FIREWALL_ALERT`.

### `POST /internal/telemetry/push`

Push a telemetry event from an enforcer. Requires machine key.

---

## Metrics

### `GET /metrics`

Prometheus metrics scrape endpoint. Requires `X-API-Key: <METRICS_SECRET_KEY>`.
