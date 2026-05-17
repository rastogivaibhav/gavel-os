# Architecture

## The Problem

Every current AI agent governance toolkit operates at the **application layer**. The policy engine and the agent run in the same process, in the same trust boundary. A compromised agent or a successful prompt injection attack owns the governance layer too.

Gavel explores enforcement at the **OS/runtime layer** below the application trust boundary, so policy decisions can be evaluated outside the agent process instead of relying only on in-process middleware.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  Host Machine                                                    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Userspace                                               │   │
│  │                                                          │   │
│  │  AI Agent Process          Application Middleware        │   │
│  │  (LangChain, CrewAI,  ──►  (AGT, Guardrails, etc.)      │   │
│  │   AutoGen, etc.)           [same trust boundary]         │   │
│  │         │                                                │   │
│  │         │ network attempt                                │   │
│  └─────────┼────────────────────────────────────────────────┘   │
│            │                                                     │
│  ┌─────────▼────────────────────────────────────────────────┐   │
│  │  Kernel / OS Layer  [experimental enforcement]           │   │
│  │                                                          │   │
│  │  Linux:   eBPF cgroup socket hook                        │   │
│  │  Windows: ETW process monitor + WFP network filter       │   │
│  │  macOS:   audit-only (System Extension planned)          │   │
│  └─────────┬────────────────────────────────────────────────┘   │
│            │ policy check (machine-key authenticated)            │
└────────────┼────────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│  Gavel Control Plane  (separate process / host)                │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  OPA/Rego    │  │  Verdict     │  │  Audit Ledger        │ │
│  │  Policy      │  │  Engine      │  │  (SHA-256 chained    │ │
│  │  Engine      │  │  (SRP)       │  │   PostgreSQL)        │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  JWT + JWKS  │  │  gRPC        │  │  WebSocket           │ │
│  │  Auth        │  │  ext_authz   │  │  Telemetry           │ │
│  │  (RS256)     │  │  (Envoy)     │  │  (OpenTelemetry)     │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

## Components

### Enforcer (Go)

The enforcer runs on each host where AI agents operate. It observes or intercepts host activity depending on platform maturity and consults the control plane for policy decisions.

**Linux** — partial enforcement prototype using eBPF cgroup socket programs and centrally synced runtime policy.

**Windows** — experimental ETW process monitoring plus WFP outbound block-rule integration.

**macOS** — Audit-only mode. The enforcer connects to the control plane, receives policy, and reports events, but cannot block connections. System Extension enforcement is a planned increment.

### Control Plane (Python/FastAPI)

The control plane is the policy authority. It runs as a separate service, isolated from agent processes.

**OPA/Rego policy engine** — evaluates authorization decisions against Rego policies. The `sentinel/api/authz` package governs REST API access. The `sentinel/runtime/policy` package governs network-level enforcement decisions.

**SRP Verdict Engine** — deterministic proposal evaluation for structured tool-call governance. Evaluates `Proposal` objects against a `PolicySet` and returns a `Verdict` (ALLOW / BLOCK / ESCALATE).

**Audit Ledger** — SHA-256 hash-chained PostgreSQL table. Each entry's `current_hash` is `SHA-256(previous_hash + event_json)`. The table has `NO UPDATE / NO DELETE` rules. Chain integrity can be verified via `POST /audit/verify`.

**gRPC ext_authz** — implements the Envoy `ext_authz` interface on port 50051. Envoy sidecars can route authorization decisions through Gavel for service mesh deployments.

### Authentication

**Machine key** — enforcers authenticate to the control plane using a shared secret (`GAVEL_MACHINE_KEY`) passed in the `X-Gavel-Machine-Key` header. Compared with `hmac.compare_digest` to prevent timing attacks.

**JWT (RS256)** — REST API clients authenticate with RS256-signed JWTs. The control plane issues tokens at `POST /auth/token`. The public key is available at `GET /auth/jwks` for downstream verification without calling back to the control plane.

**JWKS key rotation** — set `JWKS_URL` to accept tokens signed by a remote key set. The local key is always tried first (zero network latency on the hot path); remote keys are tried on failure.

## Enforcement Decision Flow

```
Enforcer detects outbound connection attempt
    │
    ▼
POST /external/runtime/validate
    (X-Gavel-Machine-Key: <secret>)
    │
    ▼
AuthMiddleware — verifies machine key
    │
    ▼
evaluate_runtime_decision()
    │
    ├── control_plane_status_from_app()
    │       checks: audit_ledger, policy_loader, verdict_engine, OPA
    │       if degraded → DENY (fail-closed)
    │
    └── OPAValidationEngine.check_routing_allowance()
            input.identity = machine runtime context
            input.resource = {action, method, required_clearance}
            │
            ├── ALLOW → enforcer permits connection
            └── DENY  → enforcer blocks connection + writes audit entry
```

## Fail-Closed Behaviour

By default, if the control plane is unreachable, the enforcer **denies** the connection (`CONTROL_PLANE_UNAVAILABLE`). This is the correct default for a security enforcement system.

To override: `GAVEL_FAIL_OPEN=true`. Never set this in production.

## Audit Ledger Chain

```
Entry 1:  previous_hash = "genesis"
          event_json    = {...}
          current_hash  = SHA-256("genesis" + event_json)

Entry 2:  previous_hash = current_hash of Entry 1
          event_json    = {...}
          current_hash  = SHA-256(previous_hash + event_json)

Entry N:  ...
```

Any modification to a historical entry breaks the chain from that point forward. `POST /audit/verify` walks the entire chain and reports corrupted entries.
