# Developer Experience Review

## What works well

**Preflight system.** `sudo ./gavel-enforcer -preflight` is excellent. It outputs a structured JSON report of exactly what the host can and cannot enforce, with specific reason codes and recommended actions. This is the right first-run experience for a kernel-level tool — it tells you what you have before you commit to running it.

**Fail-closed with clear override.** The default is deny-on-control-plane-unavailable. The override is explicit (`GAVEL_FAIL_OPEN=true`). This is the correct security default and the correct developer experience — you know exactly what you're opting into.

**`docker compose up` works.** The full stack — PostgreSQL, Redis, OPA, control plane — starts from a clean clone with health-check dependencies. This is the baseline for any serious developer tool.

**Policy hot-reload.** The `YamlPolicyLoader` polls for file changes and reloads without restart. This is the right behavior for a policy engine — you should be able to iterate on policy without restarting the service.

## Gaps and improvements

### 1. No CLI

The biggest developer experience gap. There is no `gavel` CLI for common operations:

```bash
# What should exist:
gavel policy validate policies/default.yaml
gavel policy test --proposal '{"caller":{"tenant_id":"acme"},...}'
gavel audit query --start 2026-01-01 --actor agent-1
gavel audit verify
gavel enforcer preflight
gavel token mint --role customer --clearance 2
```

A CLI would dramatically reduce the friction of the first-run experience and make Gavel feel like a complete product rather than a set of HTTP endpoints.

**Recommendation:** Build a `gavel` CLI in Go (it can call the control plane REST API) and ship it as a single binary alongside the enforcer.

### 2. No sandbox / demo mode

There is no way to run Gavel in a mode that shows what it *would* block without actually blocking anything. This is critical for enterprise evaluations — security teams need to run Gavel in audit mode against their existing agent workloads before committing to enforcement.

The `audit_only` mode exists at the enforcer level, but there is no easy way to run the full stack in "show me what would happen" mode with a clear UI or report.

**Recommendation:** Add a `--dry-run` flag to the enforcer that logs all decisions without enforcing, and a `GET /audit/report` endpoint that summarizes what would have been blocked in a given time window.

### 3. First-run experience needs a single command

The current quickstart requires: clone, copy `.env.example`, edit secrets, `docker compose up`, wait, get token, test. That is five manual steps before you see anything work.

**Recommendation:** Add a `make quickstart` target that generates secrets, writes `.env`, starts the stack, waits for health, mints a token, and runs a sample policy decision — all in one command with colored output.

### 4. No framework adapters

The README mentions LangChain, CrewAI, AutoGen, and OpenAI Agents SDK as contribution areas. These adapters would dramatically lower the barrier to adoption — most developers want to add `from gavel import GavelMiddleware` to their existing agent code, not learn a new runtime contract.

**Recommendation:** Ship a `gavel-python` SDK package with adapters for the top three frameworks. The adapter should wrap the agent's tool execution and submit proposals to the VerdictEngine before execution.

### 5. API ergonomics: the validate endpoint

`POST /external/validate` requires a full JSON body with `action`, `method`, `target_tenant_id`, and `required_clearance`. For the common case (checking if an action is allowed), this is verbose.

**Recommendation:** Add a simpler `GET /external/allowed?action=read.data` endpoint for quick checks, with the full POST endpoint for production use.

### 6. Observability gap: no dashboard

The WebSocket telemetry stream exists, but there is no reference dashboard. Operators have no way to see what is being blocked, what agents are running, or whether the audit chain is intact without writing their own tooling.

**Recommendation:** Ship a minimal read-only dashboard (a single HTML file served by the control plane at `/ui`) that shows the real-time telemetry stream and the last 100 audit entries. This does not need to be a full React app — a simple server-side rendered page is enough to make the product feel complete.

## Demo flow recommendation

The ideal demo for a security-focused audience:

1. Start the stack with `make quickstart`
2. Show the preflight output — "here is what this host can enforce"
3. Run a LangChain agent that tries to call an unauthorized API
4. Show the enforcer blocking the connection in real-time
5. Show the audit ledger entry with the cryptographic hash
6. Run `POST /audit/verify` — chain is intact
7. Modify the policy to allow the action — hot-reload, no restart
8. Run the agent again — now it succeeds
9. Show the audit entry for the allowed action

This demo takes about 5 minutes and demonstrates every key capability: kernel-level enforcement, policy-as-code, hot-reload, tamper-evident audit.

## Benchmark targets

The product needs published latency numbers before enterprise evaluations. Target benchmarks:

- **Enforcement decision latency:** p50 / p95 / p99 for `POST /external/runtime/validate` under load
- **eBPF hook overhead:** nanoseconds per packet on Linux (measured with `bpftool`)
- **Control plane throughput:** decisions/second before degradation (single instance, 2-replica)
- **Audit ledger write throughput:** appends/second under concurrent load

These numbers belong in the README and are required for any serious enterprise security evaluation.
