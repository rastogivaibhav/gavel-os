# Product Positioning

## Elevator pitch

Gavel is the OS-level enforcement runtime for AI agents. Where every other governance tool runs inside the agent process — bypassable by design — Gavel enforces at the kernel level using eBPF on Linux and ETW/WFP on Windows. Agent actions are intercepted before they reach the network, evaluated against OPA/Rego policies, and allowed or blocked regardless of what the agent framework does.

## 30-second founder pitch

Every enterprise deploying AI agents is about to discover the same problem: their governance middleware runs in the same process as the agent. A single prompt injection attack, a patched library, or a compromised dependency removes the governance layer entirely. Gavel solves this by moving enforcement to the OS kernel — the one layer no userspace process can bypass. We're the eBPF-based enforcement runtime for the agentic era, and we're the only open-source project doing this at the OS level.

## Why now

Three forces are converging:

**1. Agents are taking real actions.** The shift from LLMs that answer questions to agents that execute code, call APIs, write to databases, and send emails happened in 2024. The blast radius of a compromised agent is now measured in data breaches and financial losses, not hallucinated text.

**2. Application-layer governance has a structural flaw.** The entire current generation of agent governance tooling — Microsoft AGT, Guardrails AI, LlamaGuard, NeMo Guardrails — runs in the same process as the agent. This is not a bug in their implementation; it is a fundamental architectural constraint. The OWASP Agentic Top 10 (published 2024) explicitly calls out this trust boundary problem.

**3. eBPF has matured.** The same technology that powers Cilium, Falco, and Datadog's eBPF agent is now stable enough to build production enforcement on. The kernel primitives exist. The Go tooling (cilium/ebpf) is production-grade. The timing is right.

## Competitive landscape

| Product | Layer | Can be bypassed by agent? | Blocks network? | Audit chain? |
|---|---|---|---|---|
| Microsoft AGT | Application (Python middleware) | Yes | No | No |
| Guardrails AI | Application (Python middleware) | Yes | No | No |
| LlamaGuard | Model (content filter) | Yes | No | No |
| Falco | Kernel (syscall monitoring) | No | No (alerts only) | No |
| **Gavel** | **OS kernel (eBPF / WFP)** | **No** | **Yes** | **Yes (SHA-256 chained)** |

Falco is the closest architectural cousin — it also uses eBPF — but it is a detection and alerting tool, not an enforcement runtime. It observes; Gavel blocks.

## Open-source moat

The open-source layer creates a distribution moat that is difficult to replicate:

- **eBPF expertise is rare.** Writing correct cgroup socket programs that handle the full Linux capability matrix (CAP_BPF vs CAP_SYS_ADMIN, cgroup v2 detection, memlock limits) is non-trivial. The enforcer preflight system alone represents significant engineering investment.
- **The runtime contract is a standard.** Once enterprises build their agent infrastructure against the Gavel runtime contract (the typed enforcer ↔ control plane protocol), switching costs are high.
- **Policy as code.** OPA/Rego policies committed to version control, reviewed in PRs, and tested in CI is a workflow that security teams understand. It creates stickiness.

## Enterprise buying reasons

1. **Compliance.** Regulated industries (finance, healthcare, government) need to demonstrate that AI agents cannot exfiltrate data or call unauthorized APIs. Application-layer governance does not satisfy auditors who understand the trust boundary problem. Kernel-level enforcement does.

2. **Incident response.** The cryptographic audit ledger provides a tamper-evident record of every agent action. When something goes wrong, the chain of custody is unambiguous.

3. **Defense in depth.** Gavel does not replace existing governance tooling — it adds a layer below it. Security teams understand defense in depth. Adding a kernel-level enforcement layer to an existing AGT deployment is a straightforward sell.

4. **Regulatory tailwinds.** The EU AI Act, NIST AI RMF, and emerging SEC guidance on AI systems all point toward mandatory audit trails and access controls for autonomous systems. Gavel provides both.
