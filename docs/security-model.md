# Security Model

## Trust Boundaries

Gavel operates across two trust boundaries:

**Boundary 1: OS kernel ↔ userspace**
Linux eBPF and Windows Firewall rules provide OS-mediated controls **for the operations and identities that are actually covered**. The current Linux prototype enforces selected IPv4 connect attempts for explicitly monitored PIDs. It does **not** automatically cover all child processes, IPv6, UDP, filesystem access or kernel-management actions. An agent can bypass uncovered paths, and an agent with sufficient privilege may tamper with enforcement until stronger integrity controls are delivered. Do not interpret the existence of a kernel hook as complete mediation.

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

## Linux enforcement-required startup (not full fail-closed containment)

**Starting with the proposed M0 security branch**, the Linux executable requires enforcement by default:

- Normal startup requires an enforce-ready preflight, a successfully fetched and nonempty policy, and a successful real eBPF attachment. A failure exits with a **nonzero status** and an explicit security error; there is no automatic audit-only daemon fallback.
- `--audit-only` is an explicit operator opt-in to **unprotected observation**. It must not be used for a protected agent.
- `--preflight` reports readiness requirements only; `enforcement_attached=false` until the program is actually attached. An actual successful attach and denial test is separate proof.
- `enforcement_attached=true` is exposed in runtime component health metadata only after attachment succeeds.
- A control-plane outage **before startup** prevents enforced mode from starting. An outage **after attachment** does not dynamically revoke/deny all traffic: the already loaded static policy remains in effect. No automatic secure policy refresh or invalidation is implemented yet.
- `GAVEL_FAIL_OPEN` is **not** an eBPF kernel-denial switch. Do not use tool/gateway policy settings to infer OS enforcement behavior.

**Safety boundary:** Refusing to start the enforcer does *not* stop a separate AI-agent process that someone launches independently. Nor is a kernel hook guaranteed to remain attached after the enforcer stops: cleanup currently detaches it. A future enforced workload launcher, independent workload supervisor or host quarantine is required before claiming \"fail-closed for a running agent\". Disable or stop protected agent launch independently whenever GavelOS is not verified active.

**Operator commands:**

```sh
# Inspects prerequisites and policy, without proving kernel attachment:
./gavel-enforcer --preflight

# Enforces by default; exits nonzero if policy or kernel hook fails:
./gavel-enforcer

# Deliberately unprotected, diagnostic use ONLY:
./gavel-enforcer --audit-only
```

See [Agent Security Boundary Programme](AGENT_SECURITY_BOUNDARY_PROGRAM.md), [Kernel Enforcement Proof](KERNEL_ENFORCEMENT_PROOF.md), and issue #3 for the remaining hard fail-closed/agent-launch guarantees.

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
- **Control-plane outage:** Linux enforced startup now aborts when required policy cannot be obtained, but already-running eBPF filters keep their last-loaded policy, and independently running agents are not quarantined. Do not claim an outage blocks all agent network activity.
- **IPv6 is not supported** in the Linux eBPF enforcer. The eBPF program operates on IPv4 addresses only.
- **The Windows WFP enforcer uses PowerShell** for firewall rule management. PowerShell execution policy restrictions on hardened hosts may prevent enforcement.

## Reporting Vulnerabilities

See [SECURITY.md](../SECURITY.md).
