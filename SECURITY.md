# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `1.0.x` | ✅ Active |
| `0.x.x` | ❌ End of life |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by emailing **security@gavel-os.io** with:

1. A description of the vulnerability and its potential impact
2. Steps to reproduce or a proof-of-concept (if safe to share)
3. Affected versions and components
4. Any suggested mitigations you have identified

You will receive an acknowledgement within **48 hours** and a status update within **7 days**.

We follow coordinated disclosure: we ask that you give us **90 days** to investigate and release a fix before public disclosure. We will credit researchers in the release notes unless you prefer to remain anonymous.

## Scope

The following are in scope:

- `enforcer/` — Go OS-level enforcement runtime (Linux eBPF, Windows ETW/WFP)
- `control-plane/` — Python FastAPI control plane
- `control-plane/auth/` — JWT and machine-key authentication
- `control-plane/sentinel/` — OPA policy engine integration
- Authentication bypass or privilege escalation in any component
- Policy bypass that allows an agent to circumvent enforcement
- Cryptographic weaknesses in the audit ledger chain

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report to the upstream project)
- Denial-of-service attacks requiring physical access to the host
- Issues in the commercial Gavel product (separate disclosure channel)

## Security Architecture

Gavel's security model relies on the following trust boundaries:

- **Enforcer ↔ Control Plane**: Authenticated via `GAVEL_MACHINE_KEY` (HMAC comparison). All enforcer-facing endpoints require machine authentication.
- **REST API**: RS256 JWT tokens issued by the control plane. Admin token minting requires `X-Admin-Secret`.
- **gRPC ext_authz**: Envoy sidecar channel. TLS required in production (see `GRPC_TLS_CERT_PATH`).
- **Audit Ledger**: SHA-256 hash-chained PostgreSQL table with `NO UPDATE / NO DELETE` rules. Tamper-evident but not tamper-proof against a database administrator with direct access.
- **OPA Policies**: Evaluated server-side. Policy files should be treated as trusted configuration — restrict write access.

## Known Limitations

- macOS enforcement is **audit-only**. The macOS runtime cannot block network connections; it can only observe and report them. Do not rely on Gavel for enforcement on macOS hosts.
- The audit ledger's `NO UPDATE / NO DELETE` rules are enforced at the PostgreSQL rule level, not the row-security level. A superuser with direct database access can bypass them. For high-assurance environments, use a dedicated PostgreSQL role with `INSERT`-only privileges on `audit_ledger`.
- `GAVEL_FAIL_OPEN=true` disables fail-closed behavior. Never set this in production.
