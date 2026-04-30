<div align="center">

# Gavel

### OS-level enforcement for AI agents. The trust boundary that application middleware cannot provide.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)](CHANGELOG.md)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](enforcer/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](control-plane/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#platform-support)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP%20Agentic%20Top%2010-Addressed-success)](#owasp-agentic-top-10-coverage)
[![CI](https://img.shields.io/github/actions/workflow/status/gavel-os/gavel/ci.yml?label=CI)](https://github.com/gavel-os/gavel/actions)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fgavel--os-blue?logo=docker)](https://ghcr.io/gavel-os/gavel-control-plane)

</div>

---

## The problem every AI team is about to hit

Every AI agent governance toolkit today — including excellent ones like [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) — operates at the **application layer**. The policy engine and the agent run in the **same process**, inside the **same trust boundary**.

That means:

- A prompt injection attack that hijacks the agent also hijacks the governance layer
- A compromised agent process can patch or bypass the middleware entirely
- Swapping the agent framework removes the governance layer with it

Microsoft's own documentation is explicit about this:

> *"This toolkit provides application-level governance (Python middleware), not OS kernel-level isolation. The policy engine and agents run in the same process."*

**Gavel enforces at the OS level — below the application trust boundary — where no userspace process can reach it.**

```
Without Gavel                          With Gavel
─────────────────────────────          ──────────────────────────────────────
Agent ──► [Middleware] ──► Action      Agent ──► Action attempt
          (same process,                              │
           bypassable)                               ▼
                                        [eBPF / ETW / WFP]  ← kernel-level
                                                     │
                                                     ▼
                                         Control Plane Policy Check
                                                     │
                                              ALLOW / DENY / AUDIT
```

---

## What Gavel is

Gavel is an **OS-level enforcement runtime** for AI agents. It intercepts agent network activity and process behavior at the kernel before any action reaches the network, then evaluates it against a central policy engine.

**Linux** — eBPF cgroup socket programs attach to the cgroup hierarchy. All outbound connections from monitored processes pass through the hook before reaching the network stack. No userspace bypass is possible.

**Windows** — ETW (Event Tracing for Windows) monitors process creation. WFP (Windows Filtering Platform) applies outbound block rules at the network stack level. DNS-resolved hostnames are periodically refreshed.

**macOS** — Audit-only mode. The runtime connects to the control plane, receives policy, and reports events. System Extension enforcement is on the roadmap.

Gavel is **not** a prompt guardrail, LLM content filter, or replacement for application-layer governance. It is the enforcement layer that sits below all of that — the last line that cannot be bypassed.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Host Machine                                                         │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Userspace                                                       │ │
│  │                                                                  │ │
│  │  AI Agent (LangChain / CrewAI / AutoGen / OpenAI Agents SDK)    │ │
│  │       │                                                          │ │
│  │       │  Application middleware (AGT, Guardrails, etc.)         │ │
│  │       │  [same trust boundary — bypassable]                     │ │
│  │       │                                                          │ │
│  └───────┼──────────────────────────────────────────────────────────┘ │
│          │ network attempt                                             │
│  ┌───────▼──────────────────────────────────────────────────────────┐ │
│  │  Kernel / OS Layer  [cannot be bypassed from userspace]          │ │
│  │                                                                  │ │
│  │  Linux:   eBPF cgroup socket hook (cilium/ebpf)                 │ │
│  │  Windows: ETW process monitor + WFP network filter              │ │
│  │  macOS:   audit-only (System Extension planned)                 │ │
│  └───────┬──────────────────────────────────────────────────────────┘ │
└──────────┼────────────────────────────────────────────────────────────┘
           │ machine-key authenticated policy check
           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Gavel Control Plane  (Python / FastAPI)                              │
│                                                                       │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────┐ │
│  │  OPA / Rego     │  │  SRP Verdict     │  │  Audit Ledger       │ │
│  │  Policy Engine  │  │  Engine          │  │  SHA-256 chained    │ │
│  │  (sentinel/)    │  │  (srp/)          │  │  PostgreSQL         │ │
│  └─────────────────┘  └──────────────────┘  └─────────────────────┘ │
│                                                                       │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────┐ │
│  │  RS256 JWT      │  │  gRPC ext_authz  │  │  WebSocket          │ │
│  │  + JWKS         │  │  (Envoy TLS)     │  │  Telemetry          │ │
│  └─────────────────┘  └──────────────────┘  └─────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Language | Role |
|---|---|---|
| `enforcer/` | Go | OS-level runtime: eBPF (Linux), ETW+WFP (Windows), audit-only (macOS) |
| `control-plane/api/` | Python | FastAPI control plane: policy decisions, auth, telemetry, audit |
| `control-plane/sentinel/` | Python | OPA/Rego policy engine wrapper |
| `control-plane/srp/` | Python | Deterministic verdict engine + YAML policy DSL |
| `control-plane/auth/` | Python | RS256 JWT with JWKS, machine-key auth |
| `policies/` | Rego / YAML | Default and production policy sets |
| `deploy/` | YAML | Kubernetes, Helm, systemd, launchd, Envoy |

---

## Quickstart

**Prerequisites:** Docker + Docker Compose.

Optional (depending on what you run):
- Go 1.21+ (to build the enforcer)
- `jq` (for the token examples below)
- `openssl` (if you want to generate secrets manually instead of using the start scripts)

By default, `docker-compose.yml` exposes the control plane at **`http://localhost:18000`**
(override with `GAVEL_API_PORT` in `.env` / your environment).

### 1. Clone and configure

```bash
git clone https://github.com/gavel-os/gavel
cd gavel
```

### 2. Start the control plane

Recommended (creates `.env` with generated secrets on first run):

```bash
# Linux/macOS
./start.sh
```

```powershell
# Windows
.\start.ps1
```

Manual (if you prefer to manage `.env` yourself):

```bash
cp .env.example .env
```

Generate secrets and write them to `.env`:

```bash
MACHINE_KEY=$(openssl rand -hex 32)
API_KEY=$(openssl rand -hex 32)
ADMIN_KEY=$(openssl rand -hex 32)

sed -i "s/^GAVEL_MACHINE_KEY=$/GAVEL_MACHINE_KEY=$MACHINE_KEY/" .env
sed -i "s/^API_SECRET_KEY=$/API_SECRET_KEY=$API_KEY/" .env
sed -i "s/^ADMIN_SECRET_KEY=$/ADMIN_SECRET_KEY=$ADMIN_KEY/" .env
```

```bash
docker compose up -d
```

Starts PostgreSQL, Redis, OPA, and the control plane. Verify in ~15 seconds:

```bash
curl http://localhost:18000/health
```

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "audit_ledger": "connected",
    "policy_loader": "loaded",
    "verdict_engine": "ready",
    "opa_policy_engine": "ready",
    "grpc_authz": "ready"
  }
}
```

### 3. Get a token and test a policy decision

```bash
TOKEN=$(curl -s -X POST http://localhost:18000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"role":"customer","clearance_level":2}' | jq -r .access_token)

# Allowed
curl -s -X POST http://localhost:18000/external/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"read.data","method":"GET","required_clearance":1}' | jq .

# Denied — blocked action
curl -s -X POST http://localhost:18000/external/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"data.delete","method":"EXECUTE","required_clearance":1}' | jq .
```

### 4. Access the Control Plane Dashboard

Open your browser to **`http://localhost:18000`** to access the web-based control plane UI:

- **Dashboard** — System health, component status, recent events
- **Audit Ledger** — Forensic analysis with SHA-256 chain verification
- **Policies** — Deployed policy inventory and versions
- **Policy Editor** — Interactive REGO editor with validation & testing
- **Live Monitor** — Real-time decision stream via WebSocket

Full UI documentation: [docs/UI_SETUP.md](docs/UI_SETUP.md)

### 5. Run the Linux enforcer

```bash
cd enforcer
GOOS=linux GOARCH=amd64 go build -o gavel-enforcer .

# Preflight — shows what this host can enforce
sudo ./gavel-enforcer -preflight

# Start
export GAVEL_ENGINE_URL=http://localhost:18000
export GAVEL_MACHINE_KEY=<your-machine-key>
sudo ./gavel-enforcer
```

### 6. Run the Windows enforcer

```powershell
cd enforcer
$env:GOOS = 'windows'; $env:GOARCH = 'amd64'
go build -o gavel-enforcer.exe .

$env:GAVEL_ENGINE_URL = "http://localhost:18000"
$env:GAVEL_MACHINE_KEY = "<your-machine-key>"
.\gavel-enforcer.exe
```

---

## Platform support

| OS | Architecture | Mode | Status |
|---|---|---|---|
| Linux | `amd64` | `enforce` | ✅ GA |
| Linux | `arm64` | `enforce` | ✅ GA |
| Windows | `amd64` | `enforce` | ✅ GA |
| Windows | `arm64` | `enforce` | ✅ GA |
| macOS | `amd64` | `audit_only` | ✅ GA |
| macOS | `arm64` | `audit_only` | ✅ GA |

macOS System Extension enforcement (full block capability) is planned for v1.1.

---

## Policy

Gavel supports two policy formats. They operate at different layers and complement each other.

**OPA/Rego** — governs network-level enforcement and REST API authorization. Evaluated by the OPA engine on every decision.

```rego
package sentinel.api.authz

default allow := false

allow if {
    input.identity.is_authenticated == true
    input.identity.clearance_level >= input.resource.required_clearance
    not blocked_action
}

blocked_action if {
    input.resource.action in data.blocked_actions
}
```

**YAML** — governs structured tool-call proposals evaluated by the SRP VerdictEngine. Hot-reloaded without restart.

```yaml
name: my-policy
version: "1.0.0"
rules:
  - id: block-data-delete
    description: "Block any agent attempting to delete or drop data"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete, drop, truncate]

  - id: escalate-financial-writes
    description: "Escalate financial operations for human review"
    effect: ESCALATE
    priority: 300
    condition:
      api_refs: [payments.api, billing.api]
      operations: [write, transfer, refund]
      max_numeric_parameters:
        amount: 10000.0
```

See [docs/policy-authoring.md](docs/policy-authoring.md) for the full reference.

---

## Deployment

### Docker Compose (local / single-host)

```bash
docker compose up -d
```

### Kubernetes (DaemonSet + Deployment)

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
# Create secrets — see deploy/kubernetes/secret-template.yaml
kubectl apply -f deploy/kubernetes/
```

### Helm

```bash
helm install gavel ./deploy/helm/gavel \
  --namespace gavel-system \
  --create-namespace \
  --set controlPlane.existingSecret=gavel-secrets
```

### systemd (Linux bare-metal)

```bash
sudo cp deploy/systemd/gavel-enforcer.service /etc/systemd/system/
sudo systemctl enable --now gavel-enforcer
```

See [docs/deployment/kubernetes.md](docs/deployment/kubernetes.md) and [docs/deployment/systemd.md](docs/deployment/systemd.md) for full guides.

---

## OWASP Agentic Top 10 coverage

| Risk | ID | Gavel control |
|---|---|---|
| Agent Goal Hijacking | ASI-01 | OPA policy blocks unauthorized actions at kernel level |
| Excessive Capabilities | ASI-02 | Allowlist-based network enforcement via eBPF / WFP |
| Identity & Privilege Abuse | ASI-03 | Machine-key auth + JWT PBAC on all control plane decisions |
| Uncontrolled Code Execution | ASI-04 | Process monitoring + PID-scoped eBPF enforcement |
| Insecure Output Handling | ASI-05 | Audit ledger captures all actions with cryptographic chain |
| Memory Poisoning | ASI-06 | Out of scope for OS-layer enforcement |
| Unsafe Inter-Agent Comms | ASI-07 | Network-level enforcement blocks unauthorized destinations |
| Cascading Failures | ASI-08 | Fail-closed by default; `GAVEL_FAIL_OPEN=true` required to override |
| Human-Agent Trust Deficit | ASI-09 | SHA-256 chained audit ledger, tamper-evident |
| Rogue Agents | ASI-10 | Agent detection + network block via process monitoring |

---

## Integration with Microsoft Agent Governance Toolkit

Gavel is designed to work **alongside** AGT, not replace it. AGT governs at the application layer — fast, framework-native, excellent for policy logic. Gavel enforces at the OS layer — kernel-level, cannot be bypassed from userspace.

```python
# AGT handles application-layer policy
from agent_os import StatelessKernel, ExecutionContext, Policy

kernel = StatelessKernel()
ctx = ExecutionContext(
    agent_id="analyst-1",
    policies=[Policy.read_only(), Policy.rate_limit(100, "1m")],
)

# Gavel enforcer runs as a sidecar/service on the same host.
# Any network action the agent attempts is also evaluated at the kernel level,
# even if the AGT middleware is bypassed or patched.
```

---

## Repository structure

```
gavel/
├── enforcer/                   # Go OS-level enforcement runtime
│   ├── main.go                 # Linux eBPF enforcer entry point
│   ├── windows_enforcer.go     # Windows ETW + WFP enforcer
│   ├── darwin_runtime.go       # macOS audit-only runtime
│   ├── windows_runtime_components.go  # ETW/WFP provider interfaces
│   ├── runtime_helpers.go      # Shared preflight + config helpers
│   ├── runtime_policy_sync.go  # Control plane policy fetch
│   └── gavel.bpf.c             # eBPF cgroup socket program
│
├── control-plane/              # Python FastAPI control plane
│   ├── api/
│   │   ├── main.py             # App entry point, middleware, routes
│   │   ├── control_plane.py    # Decision helpers (REST + gRPC shared)
│   │   ├── grpc_server.py      # Envoy ext_authz gRPC server (TLS)
│   │   ├── runtime_contract.py # Typed enforcer ↔ control plane models
│   │   ├── middleware/
│   │   │   ├── auth.py         # JWT / API-key / machine-key middleware
│   │   │   └── rate_limit.py   # Per-host-id rate limiting (Redis-backed)
│   │   └── routes/
│   │       ├── external.py     # Enforcer-facing endpoints
│   │       ├── audit.py        # Audit ledger query + verify
│   │       ├── telemetry.py    # WebSocket real-time event stream
│   │       └── query.py        # OPA engine singleton
│   ├── auth/
│   │   └── jwt_handler.py      # RS256 JWT + JWKS + key rotation
│   ├── sentinel/
│   │   └── opa_engine.py       # OPA HTTP API client
│   └── srp/
│       ├── verdict_engine.py   # Deterministic proposal evaluation
│       ├── policy.py           # YAML policy DSL + evaluator
│       ├── models.py           # Proposal / Verdict / CallerContext
│       └── sdk/
│           ├── models.py       # AuditEvent / LedgerEntry / LedgerQuery
│           └── impl/
│               ├── postgres_audit_ledger.py  # SHA-256 chained ledger
│               └── yaml_policy_loader.py     # Hot-reload policy loader
│
├── policies/
│   ├── rego/
│   │   ├── authz.rego          # API authorization policy
│   │   ├── runtime.rego        # Network enforcement policy
│   │   └── data.json           # Blocked actions, roles, targets
│   └── default.yaml            # Default YAML policy (VerdictEngine)
│
├── database/
│   ├── migrations/
│   │   ├── 001_initial_audit_ledger.sql
│   │   └── 002_runtime_events.sql
│   └── migrate.sh
│
├── deploy/
│   ├── kubernetes/             # Namespace, RBAC, Deployment, DaemonSet, NetworkPolicy
│   ├── helm/gavel/             # Helm chart v1.0.0
│   ├── systemd/                # gavel-enforcer.service, gavel-control-plane.service
│   ├── launchd/                # com.gavel.enforcer.plist
│   └── envoy/                  # envoy.yaml (ext_authz filter config)
│
├── tests/                      # Python test suite (104 tests, no infra required)
├── docs/                       # Architecture, policy authoring, deployment, API reference
├── docker-compose.yml          # Full local stack
├── .env.example                # All env vars documented
├── SECURITY.md
├── CONTRIBUTING.md
└── CHANGELOG.md
```

---

## Security

Gavel is a security product. The security model is documented in detail in [docs/security-model.md](docs/security-model.md) and [SECURITY.md](SECURITY.md).

Key properties:

- **Fail-closed by default.** If the control plane is unreachable, the enforcer denies all connections. `GAVEL_FAIL_OPEN=true` is required to override — never set this in production.
- **gRPC TLS required in production.** The ext_authz server refuses to start with `GRPC_INSECURE=true` outside `ENV=development`.
- **RS256 JWT with JWKS.** All tokens carry a `kid` header. Key rotation is supported via `JWKS_URL` with configurable TTL caching.
- **Cryptographic audit chain.** Each ledger entry is `SHA-256(previous_hash + event_json)`. Chain integrity is verifiable via `POST /audit/verify`.
- **Metadata contract enforced.** The runtime contract explicitly allowlists and blocklists metadata keys — sensitive fields (`prompt`, `file_contents`, `command_output`) are rejected at the Pydantic layer.

To report a vulnerability: **security@gavel-os.io**. Do not open a public issue.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, test commands, and PR process.

Highest-value contribution areas:

1. **macOS System Extension enforcement** — the biggest platform gap
2. **AGT adapter** — first-class Microsoft Agent Governance Toolkit integration
3. **Framework adapters** — LangChain, CrewAI, AutoGen, OpenAI Agents SDK
4. **Benchmark suite** — reproducible enforcement latency numbers
5. **OPA policy templates** — SQL injection, privilege escalation, data exfiltration patterns

---

## Documentation

| Document | Description |
|---|---|
| [Quickstart](docs/quickstart.md) | End-to-end in under 10 minutes |
| [Architecture](docs/architecture.md) | Trust boundaries, enforcement flow, audit chain |
| [Policy Authoring](docs/policy-authoring.md) | OPA/Rego + YAML policy reference |
| [Security Model](docs/security-model.md) | Auth, fail-closed, known limitations |
| [API Reference](docs/api-reference.md) | All endpoints |
| [Kubernetes Deployment](docs/deployment/kubernetes.md) | Raw manifests + Helm |
| [systemd Deployment](docs/deployment/systemd.md) | Linux bare-metal |

---

## Relationship to commercial Gavel

This repository is the complete open-source OS enforcement runtime and control plane core. It is production-usable as-is.

The commercial Gavel product adds:

- Semantic recipe/workflow governance engine (pgvector + three-tier cache)
- SI Marketplace with revenue-share partner model
- Enterprise connectors (Salesforce, ServiceNow, Workday, Oracle Retail)
- Managed SaaS deployment with SLA and dedicated support

---

## License

Apache License 2.0 (`Apache-2.0`). See [LICENSE](LICENSE).

---

<div align="center">

**[Documentation](docs/quickstart.md)** · **[API Reference](docs/api-reference.md)** · **[Security](SECURITY.md)** · **[Contributing](CONTRIBUTING.md)**

Built for the era of autonomous agents.

</div>
