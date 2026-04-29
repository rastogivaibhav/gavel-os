# Future Spec: OpenTelemetry Integration for Codex + Claude Code

**Date:** 2026-04-29  
**Status:** PAUSED — Deferred pending validation of incremental value over Gavel's kernel-level enforcement  
**Author:** Claude Code (Brainstorming session)  
**Project:** Gavel OS

---

## Executive Summary

This document captures a proposed telemetry ingestion system that would normalize logs from OpenAI Codex and Anthropic Claude Code into a vendor-agnostic schema, apply governance rules, and export to third-party platforms (Datadog, Splunk, Elastic, Grafana, etc.).

**Decision:** This work is **paused** because Gavel's kernel-level enforcement + audit ledger already provides the core security/audit value. The incremental benefit of application-level telemetry ingestion is conditional on specific use cases (behavioral anomaly detection, compliance redaction evidence, cost governance) that may not justify the engineering effort at this time.

---

## Context: Gavel's Existing Capabilities

Gavel provides:
- **OS-level enforcement** (eBPF on Linux, ETW+WFP on Windows, audit-only on macOS)
- **Tamper-evident audit ledger** (SHA-256 chained entries in PostgreSQL)
- **Network-level event capture** (all outbound connection attempts before they reach the network)
- **Policy engine** (OPA/Rego for authorization, YAML/SRP for deterministic verdicts)
- **Agent-agnostic** (works with any AI framework: LangChain, CrewAI, AutoGen, Claude Code, Codex, etc.)

**Limitation:** Gavel captures *enforcement decisions* (blocked/allowed/escalated), but not the full application context from the agent (which tool was called, what the response was, token usage, model selection).

---

## Proposed System: Architecture Overview

### Recommended Design: Approach 3 (Balanced)

```
Codex / Claude Code (OTLP export)
      ↓ (OTLP HTTP/gRPC)
OpenTelemetry Collector
  ├─ receivers: OTLP HTTP, OTLP gRPC
  ├─ processors: auth, resource enrichment, batching, memory limit
  └─ exporters: → FastAPI Service + Debug
      ↓
FastAPI Normalisation Service
  ├─ Dual pipelines:
  │   ├─ OTel ingestion (POST /api/v1/ai-telemetry/events)
  │   └─ Gavel audit ledger consumer
  ├─ Canonical schema (ai_agent_events, ai_agent_usage, ai_agent_tool_calls, ai_agent_sessions)
  ├─ Redaction processor (prompts, secrets, credentials, .env, SSH keys, customer data)
  ├─ Risk scoring engine (dangerous commands, secret exposure, production file edits, token anomalies)
  ├─ Alerting engine (real-time alerts for high-risk events)
  └─ Pluggable exporters (Datadog, Splunk, Elastic, Grafana, custom webhook)
      ↓
PostgreSQL (normalized events, audit trail, rule violations)
```

### Key Decisions Made During Brainstorming

| Decision | Outcome |
|----------|---------|
| **Primary driver** | Security / Audit (not cost, not observability) |
| **Dual pipelines** | Yes — Gavel enforcement ledger + OTel application telemetry |
| **Third-party app strategy** | Vendor-agnostic; support multiple backends equally (Datadog, Splunk, Elastic, etc.) |
| **Deployment model** | Lightweight distributed (OTel Collector + single FastAPI service + pluggable exporters) |
| **Scope** | Full Phase 1: ingestion, normalisation, redaction, risk scoring, alerting, exports |

---

## Incremental Value Analysis

### What This System Would Add Beyond Gavel

**✅ High-Value:**
- **Visibility into attempts** — see what dangerous commands the agent tried (even if Gavel blocked them at the kernel)
- **Behavioral audit trail** — full sequence of tool calls that led to a risky action
- **Anomaly detection** — detect if an agent is behaving unusually today
- **Compliance evidence** — prove that redaction was applied before storage

**❓ Medium-Value:**
- **Tool-level audit** — which MCP tools/shell commands/file operations succeeded vs. failed
- **Model/token context** — understand which models are being used, token burn per session
- **Cost governance** — per-team, per-repo token usage tracking

**❌ Lower Priority (Gavel covers):**
- **Network-level enforcement** — Gavel already blocks at the kernel
- **Basic audit trail** — Gavel already maintains tamper-evident ledger
- **Policy decisions** — Gavel already evaluates policy

### Decision Criteria for Future Resumption

Resume this work if ANY of:

1. **Behavioral anomaly detection is critical** — you need to detect repeated evasion attempts, unusual tool sequences, or abnormal token usage patterns.
2. **Compliance/redaction audit is required** — regulators or internal policy demand proof that sensitive data was redacted before storage/export.
3. **Cost chargeback/governance is a driver** — you need per-team, per-repo token cost visibility for capacity planning or billing.
4. **Tool-level behavioral audit is required** — you need complete visibility into what each agent attempted (not just what the kernel blocked).

**If none of these apply**, Gavel's kernel-level enforcement + audit ledger may be sufficient.

---

## Proposed Implementation Plan (If Resumed)

### Phase 1: MVP (Full Scope)

**Deliverables:**
1. **OpenTelemetry Collector** — config with OTLP receivers, auth, enrichment, batching
2. **FastAPI Normalisation Service** — dual pipeline ingestion, canonical schema, PostgreSQL storage
3. **Risk Scoring Engine** — dangerous shell commands, secret exposure, production file edits, high-token sessions
4. **Redaction Processor** — remove prompts, API keys, tokens, .env, SSH keys, customer data
5. **Export Adapters** — at least Datadog + Splunk + Elasticsearch (pluggable pattern for others)
6. **Alerting Engine** — real-time alerts via webhook/SNS for high-risk events
7. **Docker Compose setup** — local dev environment with OTel Collector, FastAPI, PostgreSQL
8. **Canonical schema** — `ai_agent_events`, `ai_agent_usage`, `ai_agent_tool_calls`, `ai_agent_sessions`

**Acceptance Criteria:**
- Codex telemetry ingested via OTLP
- Claude Code telemetry ingested via OTLP
- Events normalized to canonical schema
- Prompts/secrets redacted by default
- Risky commands flagged before export
- Alerts generated for high-risk events
- Data exported to at least Datadog, Splunk, Elasticsearch
- Local Docker Compose brings up full stack in <30 seconds
- No sensitive data stored by default

### Phase 2: Scale + Observability

- Kafka queueing for buffering
- ClickHouse for high-volume time-series
- Grafana dashboards (usage, cost, security)
- Retention policies + cold storage archival

### Phase 3: Advanced

- Semantic recipe/workflow analysis
- Integration with Gavel enforcement ledger for cross-layer audit
- Custom governance rule builder UI
- Billing/chargeback portal

---

## Tech Stack

| Component | Recommended |
|-----------|-------------|
| OTel Collector | OpenTelemetry Collector Contrib |
| Normalisation Service | FastAPI (Python 3.11+) |
| Primary Storage | PostgreSQL (normalized events, audit) |
| High-Volume Events | ClickHouse (optional, Phase 2) |
| Event Queue | Redis Streams or Kafka (optional, Phase 2) |
| Docker | Docker Compose for local dev, Kubernetes for production |

---

## Open Questions for Future Work

1. **Which Codex/Claude Code entry points should be instrumented?** (e.g., `codex interactive`, `codex exec`, `codex mcp-server`, `claude-code` CLI)
2. **How tightly should the dual pipeline integrate with Gavel?** (consume Gavel's ledger? Or just correlate by session_id?)
3. **Redaction granularity:** should we support org-level override for "show prompts for compliance review"?
4. **Cost model:** how to allocate token costs across teams/repos when multiple agents are active?
5. **Alerting escalation:** should high-risk alerts auto-escalate to security team via Slack/email, or just webhook?

---

## References

- **Gavel OS Repo:** This repository
- **OpenTelemetry Spec:** https://opentelemetry.io/docs/
- **OpenAI Codex Config Reference:** https://developers.openai.com/codex/config-advanced
- **Claude Code Monitoring:** https://code.claude.com/docs/en/monitoring-usage
- **Elastic Claude Code Monitoring Guide:** https://www.elastic.co/security-labs/claude-code-cowork-monitoring-otel-elastic

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-29 | **Pause work** | Gavel's kernel-level audit ledger already covers core security/audit. Incremental value of app-level telemetry is conditional on behavioral anomaly detection, compliance redaction proof, or cost governance — none of which are currently blocking. Defer until one of these becomes a priority. |
| 2026-04-29 | **Architecture: Approach 3** | Balanced design (OTel Collector + FastAPI service) provides clean separation of concerns, keeps governance logic centralized, and enables vendor-agnostic exporter strategy. |
| 2026-04-29 | **Scope: Full Phase 1** | If this work resumes, include ingestion, normalisation, redaction, risk scoring, alerting, and multi-backend export from the start. |
| 2026-04-29 | **Export strategy: Vendor-agnostic** | Support Datadog, Splunk, Elasticsearch, and Grafana equally; use pluggable exporter pattern. |

---

## Next Steps

1. **When to revisit:** Monitor whether behavioral anomaly detection, compliance redaction audit, or cost governance becomes a priority.
2. **Before resuming:** Validate that Gavel's kernel-level enforcement + audit ledger is insufficient for the use case.
3. **If resuming:** Start with Phase 1 using Approach 3 (OTel Collector + FastAPI service). Use the spec in this document as the starting point.

---

**Decision Owner:** Gavel Platform Team  
**Last Updated:** 2026-04-29  
**Status:** PAUSED
