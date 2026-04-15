# Gavel — OS-Level Enforcement Runtime for AI Agents

> **The layer that application-level governance cannot provide.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](enforcer/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](control-plane/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](#platform-support)
[![OWASP](https://img.shields.io/badge/OWASP%20Agentic%20Top%2010-Addressed-green)](#owasp-agentic-top-10)

---

## The Problem with Application-Layer Governance

Every current AI agent governance toolkit — including excellent ones like [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) — operates at the **application layer**. The policy engine and the agent run in the **same process**, in the **same trust boundary**.

This means:

- A compromised agent process can bypass the middleware entirely
- A prompt injection attack that hijacks the agent also hijacks the governance layer
- There is no enforcement if the agent framework is patched or replaced

Microsoft's own documentation states:

> *"This toolkit provides application-level governance (Python middleware), not OS kernel-level isolation. The policy engine and agents run in the same process."*

**Gavel solves this at the OS level.**

```
Without Gavel:
  Agent ──► [Application Middleware] ──► Action
             (same process, bypassable)

With Gavel:
  Agent ──► Action attempt
              │
              ▼
         [eBPF / ETW / WFP]   ← kernel-level, cannot be bypassed from userspace
              │
              ▼
         Control Plane Policy Check
              │
         ALLOW / DENY / AUDIT
```

---

## What Gavel Is

Gavel is an **OS-level enforcement runtime** for AI agents. It intercepts agent network activity and process behavior at the kernel level — before the action reaches the network — and evaluates it against a central policy engine.

**Linux:** eBPF cgroup socket programs intercept outbound connections at the kernel level. No userspace bypass is possible.

**Windows:** ETW (Event Tracing for Windows) monitors process creation and network events. WFP (Windows Filtering Platform) applies outbound block rules at the network stack level.

**macOS:** Audit-only mode with launchd packaging. System Extension enforcement is a planned increment.

### What Gavel Does NOT Do

- Gavel is **not** a prompt guardrail or LLM content filter
- Gavel does **not** replace application-layer governance — it complements it
- Gavel does **not** govern LLM inputs/outputs — it governs **agent actions**

For model-level safety, use tools like Azure AI Content Safety alongside Gavel.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Developer Machine                        │
│                                                             │
│  ┌──────────────┐    ┌──────────────────────────────────┐  │
│  │  AI Agent    │    │      Gavel Enforcer (Go)          │  │
│  │  (any        │    │                                   │  │
│  │  framework)  │    │  Linux: eBPF cgroup socket hook   │  │
│  └──────┬───────┘    │  Windows: ETW + WFP provider      │  │
│         │            │  macOS: audit_only + launchd       │  │
│         │ network    └──────────────┬───────────────────┘  │
│         │ attempt                   │ policy check          │
│         ▼                           ▼                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Gavel Control Plane (Python/FastAPI)     │  │
│  │                                                       │  │
│  │  • OPA/Rego policy evaluation                        │  │
│  │  • Machine-authenticated runtime contract            │  │
│  │  • gRPC ext_authz (Envoy sidecar)                   │  │
│  │  • Cryptographic audit ledger (SHA-256 chained)      │  │
│  │  • Real-time telemetry (WebSocket + OpenTelemetry)   │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Language | What It Does |
|---|---|---|
| `enforcer/` | Go | OS-level runtime: eBPF (Linux), ETW/WFP (Windows), launchd (macOS) |
| `control-plane/api/` | Python | FastAPI control plane: policy, auth, telemetry, audit |
| `control-plane/sentinel/` | Python | OPA policy engine wrapper |
| `control-plane/srp/` | Python | Verdict engine, policy DSL, lane executor |
| `control-plane/auth/` | Python | RS256 JWT, machine-key auth |
| `policies/` | YAML/Rego | Default and production policy sets |
| `deploy/` | YAML | Kubernetes, systemd, launchd, Helm |

---

## Quick Start

### 1. Run the Control Plane

```bash
git clone https://github.com/your-org/gavel-os
cd gavel-os/control-plane

# Copy and fill in environment variables
cp .env.example .env

# Start with Docker Compose (includes OPA, PostgreSQL, Redis)
docker compose up
```

The control plane starts at `http://localhost:8000`. Check `/health` to verify all components.

### 2. Run the Linux Enforcer

```bash
cd enforcer

# Build
GOOS=linux GOARCH=amd64 go build -o gavel-enforcer .

# Run preflight check
sudo ./gavel-enforcer -preflight

# Start with control plane connection
export GAVEL_ENGINE_URL=http://localhost:8000
export GAVEL_MACHINE_KEY=your-machine-key
sudo ./gavel-enforcer
```

### 3. Run the Windows Enforcer

```powershell
cd enforcer

# Build
$env:GOOS='windows'; $env:GOARCH='amd64'; go build -o gavel-enforcer.exe .

# Start
$env:GAVEL_ENGINE_URL = "http://localhost:8000"
$env:GAVEL_MACHINE_KEY = "your-machine-key"
.\gavel-enforcer.exe
```

### 4. Verify Governance

```bash
# Check a policy decision
curl -X POST http://localhost:8000/external/validate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"action": "data.delete", "method": "EXECUTE", "required_clearance": 2}'

# View audit ledger
curl http://localhost:8000/audit/ledger \
  -H "Authorization: Bearer <token>"
```

---

## Platform Support

| OS | Architecture | Mode | Status |
|---|---|---|---|
| Linux | `amd64` | `enforce` | ✅ Active |
| Linux | `arm64` | `enforce` | ✅ Active |
| Windows | `amd64` | `enforce` | ✅ Active |
| Windows | `arm64` | `enforce` | ✅ Active |
| macOS | `amd64` | `audit_only` | ✅ Active |
| macOS | `arm64` | `audit_only` | ✅ Active |

macOS enforcement (System Extension) is a planned increment. Do not claim enforcement parity on macOS.

---

## Integration with Microsoft Agent Governance Toolkit

Gavel is designed to work **alongside** AGT, not replace it.

AGT governs at the application layer (fast, framework-native, excellent for policy logic).
Gavel enforces at the OS layer (kernel-level, cannot be bypassed from userspace).

**Use them together:**

```python
# AGT handles application-layer policy
from agent_os import StatelessKernel, ExecutionContext, Policy

kernel = StatelessKernel()
ctx = ExecutionContext(
    agent_id="analyst-1",
    policies=[Policy.read_only(), Policy.rate_limit(100, "1m")],
)

# Gavel enforcer runs as a sidecar/service on the same host
# Any network action the agent attempts is also evaluated at the kernel level
# even if the AGT middleware is bypassed
```

See [docs/agt-integration.md](docs/agt-integration.md) for the full integration guide and reference architecture.

---

## OWASP Agentic Top 10

| Risk | ID | Gavel Control |
|---|---|---|
| Agent Goal Hijacking | ASI-01 | OPA policy blocks unauthorized actions at kernel level |
| Excessive Capabilities | ASI-02 | Allowlist-based network enforcement via eBPF/WFP |
| Identity & Privilege Abuse | ASI-03 | Machine-key auth + JWT PBAC on all control plane decisions |
| Uncontrolled Code Execution | ASI-04 | Process monitoring + PID-scoped eBPF enforcement |
| Insecure Output Handling | ASI-05 | Audit ledger captures all actions with cryptographic chain |
| Memory Poisoning | ASI-06 | Out of scope for OS-layer enforcement |
| Unsafe Inter-Agent Comms | ASI-07 | Network-level enforcement blocks unauthorized destinations |
| Cascading Failures | ASI-08 | Fail-closed by default; explicit `GAVEL_FAIL_OPEN=true` required |
| Human-Agent Trust Deficit | ASI-09 | SHA-256 chained audit ledger, tamper-evident |
| Rogue Agents | ASI-10 | Agent detection + kill via process monitoring + network block |

---

## Policy Configuration

Gavel supports OPA/Rego policies out of the box:

```rego
# sentinel/opa/authz.rego
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

YAML policies are also supported for simpler rule sets. See [policies/](policies/) for examples.

---

## Deployment

### Kubernetes (sidecar pattern)

```yaml
# The enforcer runs as a privileged init container or DaemonSet
# See deploy/kubernetes/ for full manifests
```

### systemd (Linux)

```bash
# Install as a managed service
sudo cp deploy/systemd/gavel-enforcer.service /etc/systemd/system/
sudo systemctl enable --now gavel-enforcer
```

### launchd (macOS)

```bash
# Install as a user-level launchd agent
./scripts/install_macos_service.sh arm64
```

---

## Contributing

We welcome contributions. The highest-value areas right now:

1. **macOS System Extension enforcement** — the biggest gap vs Linux/Windows
2. **AGT adapter** — a first-class integration that routes AGT policy decisions through Gavel's OS enforcer
3. **Framework adapters** — LangChain, CrewAI, AutoGen, OpenAI Agents SDK
4. **Benchmark suite** — reproducible enforcement latency numbers
5. **Additional OPA policy templates** — SQL injection, privilege escalation, data exfiltration patterns

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Do not open a public issue for security reports.

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

## Relationship to Commercial Gavel

This repository contains the open-source OS enforcement runtime and control plane core.

The commercial Gavel product adds:
- Semantic recipe/workflow governance engine (pgvector + three-tier cache)
- SI Marketplace with revenue-share partner model
- Enterprise connectors (Salesforce, ServiceNow, Workday, Oracle Retail)
- Managed SaaS deployment with SLA

The open-source layer is complete and production-usable without the commercial layer.
