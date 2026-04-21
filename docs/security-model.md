# Security Model

## Trust Boundaries

Gavel operates across two trust boundaries:

**Boundary 1: OS kernel ↔ userspace**
The enforcer's eBPF programs (Linux) and WFP callouts (Windows) run at the kernel level. Agent processes cannot bypass kernel-level enforcement from userspace, regardless of what the agent does to its own process memory, environment, or loaded libraries.

**Boundary 2: Enforcer host ↔ control plane**
The enforcer and control plane run as separate processes, typically on separate hosts. The enforcer authenticates to the control plane using a pre-shared machine key. The control plane never trusts the enforcer's self-reported identity beyond what the machine key proves.

## Authentication

### Machine key (enforcer → control plane)

All enforcer-facing endpoints require the `X-Gavel-Machine-Key` header. The value is compared using `hmac.compare_digest` to prevent timing attacks. The key is set via `GAVEL_MACHINE_KEY` on both the enforcer host and the control plane.

**Rotation:** Generate a new key, deploy it to the control plane first, then roll it out to enforcers. The overlap window is safe because the old key is still accepted until the control plane is updated.

### JWT (REST API clients)

RS256-signed JWTs issued by `POST /auth/token`. Claims:

| Claim | Purpose |
|---|---|
| `role` | PBAC role (`customer`, `admin`, `runtime_machine`) |
| `clearance_level` | Numeric clearance for resource access control |
| `tenant_id` | Tenant isolation |
| `department` | Organisational context |
| `kid` | Key ID for JWKS-based verification |

Admin tokens require `X-Admin-Secret` header in addition to the standard request. This prevents token minting escalation if the JWT signing key is compromised.

### JWKS

The public key is available at `GET /auth/jwks` and `GET /.well-known/jwks.json`. Downstream services should cache this response (`Cache-Control: public, max-age=300`) and verify tokens locally without calling back to the control plane on every request.

## Fail-Closed Default

When the control plane is unreachable, the enforcer **denies** all connections by default (`CONTROL_PLANE_UNAVAILABLE`). This is the correct posture for a security enforcement system — availability is sacrificed in favour of security.

`GAVEL_FAIL_OPEN=true` inverts this. It must never be set in production.

## Audit Ledger Integrity

The audit ledger uses SHA-256 hash chaining:

```
current_hash = SHA-256(previous_hash + event_json)
```

Properties:
- **Tamper-evident:** Modifying any historical entry breaks the chain from that point forward, detectable via `POST /audit/verify`.
- **Append-only:** PostgreSQL `NO UPDATE / NO DELETE` rules prevent modification at the database level.
- **Not tamper-proof:** A PostgreSQL superuser with direct database access can bypass the rules. For high-assurance environments, use a dedicated role with `INSERT`-only privileges on `audit_ledger`.

## gRPC TLS

The gRPC ext_authz server (port 50051) requires TLS in production. Configuration:

| Mode | Env vars | Use case |
|---|---|---|
| Server TLS | `GRPC_TLS_CERT_PATH`, `GRPC_TLS_KEY_PATH` | Standard production |
| mTLS | + `GRPC_CA_CERT_PATH` | High-assurance, verifies Envoy client cert |
| Insecure | `GRPC_INSECURE=true` (dev only) | Local development only |

`GRPC_INSECURE=true` causes `sys.exit(1)` if `ENV != development`.

## Rate Limiting

Enforcer-facing endpoints are rate-limited per `X-Gavel-Host-Id` to prevent a misbehaving or compromised enforcer from DoS-ing the control plane:

| Endpoint | Default limit |
|---|---|
| `/external/runtime/validate` | 200/minute per host |
| `/external/heartbeat` | 4/minute per host |
| `/internal/telemetry/push` | 300/minute per host |
| `/external/runtime/policy` | 30/minute per host |

Limits are enforced in Redis when `REDIS_URL` is set (shared across replicas). In-memory fallback for single-instance deployments.

## Known Limitations

- **macOS enforcement is audit-only.** The macOS runtime cannot block connections. Do not rely on Gavel for enforcement on macOS hosts.
- **The audit ledger is tamper-evident, not tamper-proof.** A database superuser can bypass the `NO UPDATE / NO DELETE` rules.
- **The control plane is a single point of failure** unless deployed with multiple replicas behind a load balancer. The enforcer's fail-closed default means a control plane outage blocks all agent network activity.
- **IPv6 is not supported** in the Linux eBPF enforcer. The eBPF program operates on IPv4 addresses only.
- **The Windows WFP enforcer uses PowerShell** for firewall rule management. PowerShell execution policy restrictions on hardened hosts may prevent enforcement.

## Reporting Vulnerabilities

See [SECURITY.md](../SECURITY.md).
