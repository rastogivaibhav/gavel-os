# Gavel Architecture: Diagrams & Code-Based Flow Maps
## Visual Deep Dive for Technical Teams

**Version:** 1.0  
**Date:** April 2026  
**Audience:** Architects, Engineers, DevOps  

---

## Table of Contents

1. [System Architecture Mind Map](#system-architecture-mind-map)
2. [Policy Evaluation Flow](#policy-evaluation-flow)
3. [Enforcement Pipeline (per OS)](#enforcement-pipeline-per-os)
4. [Data Model & Schema](#data-model--schema)
5. [Integration Patterns](#integration-patterns)
6. [Deployment Topology Maps](#deployment-topology-maps)
7. [Request Lifecycle Sequence](#request-lifecycle-sequence)
8. [Code Examples & Patterns](#code-examples--patterns)

---

## System Architecture Mind Map

```
GAVEL SYSTEM ARCHITECTURE
│
├─── ENFORCEMENT LAYER (Host-Level)
│    │
│    ├─ Linux (eBPF)
│    │  ├─ Entry Point: cgroup_inet_egress hook
│    │  ├─ Scope: All TCP/UDP from cgroup
│    │  ├─ Language: C (eBPF bytecode)
│    │  ├─ Compilation: LLVM → kernel bytecode
│    │  └─ Deployment: Kernel ≥ 5.8
│    │
│    ├─ Windows (ETW + WFP)
│    │  ├─ Entry Point: ETW process creation event
│    │  ├─ Scope: All network connections
│    │  ├─ Language: Go (Windows API)
│    │  ├─ Integration: WFP (network filtering)
│    │  └─ Deployment: Windows Server 2016+
│    │
│    └─ macOS (Audit-only v1.0)
│       ├─ Entry Point: System calls via audit daemon
│       ├─ Scope: Read-only (no blocking)
│       ├─ Planned: System Extensions (v1.1)
│       └─ Deployment: macOS 10.15+
│
├─── CONTROL PLANE (Central Service)
│    │
│    ├─ Policy Engine
│    │  ├─ OPA/Rego
│    │  │  ├─ Purpose: Authorization & network policies
│    │  │  ├─ Evaluation: Real-time (per request)
│    │  │  ├─ Cache: Redis (policy results)
│    │  │  └─ Hot-reload: Yes (no restart)
│    │  │
│    │  └─ SRP Verdict Engine
│    │     ├─ Purpose: Deterministic tool proposal evaluation
│    │     ├─ Input: Structured tool calls (YAML)
│    │     ├─ Output: ALLOW | DENY | ESCALATE
│    │     └─ Rules: YAML-based (hot-reload)
│    │
│    ├─ Decision Engine
│    │  ├─ Merge OPA + SRP verdicts
│    │  ├─ Apply business logic
│    │  └─ Return: {verdict, reason, escalation_info}
│    │
│    ├─ Authentication & Authorization
│    │  ├─ RS256 JWT (tokens)
│    │  │  ├─ JWKS endpoint (public key discovery)
│    │  │  ├─ Key rotation (automatic)
│    │  │  └─ Token TTL: 1 hour (configurable)
│    │  │
│    │  ├─ Machine-key auth
│    │  │  ├─ Per-host unique key
│    │  │  ├─ HMAC-SHA256 signing
│    │  │  └─ Rotating nonce (prevent replay)
│    │  │
│    │  └─ API-key auth (development)
│    │     ├─ Long-lived keys
│    │     └─ Rate-limited per key
│    │
│    └─ Audit & Compliance
│       ├─ Ledger Storage
│       │  ├─ Database: PostgreSQL
│       │  ├─ Schema: SHA-256 chained
│       │  ├─ Consistency: ACID transactions
│       │  └─ Verification: Cryptographic chain proof
│       │
│       ├─ Event Logging
│       │  ├─ Log: All decisions (ALLOW/DENY/ESCALATE)
│       │  ├─ Metadata: {user, agent, resource, timestamp}
│       │  ├─ Reason: Which policy rule matched
│       │  └─ Immutability: Write-once (no updates)
│       │
│       └─ Audit Export
│          ├─ REST API (query)
│          ├─ PostgreSQL replication
│          ├─ Splunk HEC integration
│          └─ OpenTelemetry collector
│
├─── POLICY STORE
│    │
│    ├─ Rego Policies (OPA)
│    │  ├─ Location: policies/rego/
│    │  ├─ Files:
│    │  │  ├─ authz.rego (authorization rules)
│    │  │  ├─ runtime.rego (network enforcement)
│    │  │  └─ data.json (policy data)
│    │  └─ Evaluation: Hot-reload via OPA HTTP API
│    │
│    ├─ YAML Policies (SRP)
│    │  ├─ Location: policies/
│    │  ├─ Format: YAML rule definitions
│    │  ├─ Reloadable: Hot-reload (no restart)
│    │  └─ Features:
│    │     ├─ Condition matching
│    │     ├─ Effect (BLOCK/ESCALATE/AUDIT)
│    │     └─ Priority-based evaluation
│    │
│    └─ Policy Loader
│       ├─ Watches: File system changes
│       ├─ Validation: Schema validation pre-reload
│       ├─ Sync: Distributes to all enforcers
│       └─ Rollback: Automatic on validation fail
│
└─── INFRASTRUCTURE
     │
     ├─ Database
     │  ├─ PostgreSQL
     │  │  ├─ Tables: audit_ledger, runtime_events, policies
     │  │  ├─ Replication: Streaming WAL (optional HA)
     │  │  └─ Backup: Daily snapshots to S3/GCS
     │  │
     │  └─ Cache
     │     ├─ Redis
     │     ├─ Purpose: Policy result cache
     │     ├─ TTL: 5 minutes (per policy)
     │     └─ Strategy: LRU eviction
     │
     ├─ Networking
     │  ├─ Enforcer ↔ Control Plane
     │  │  ├─ Protocol: gRPC (binary, efficient)
     │  │  ├─ TLS: Required in production
     │  │  ├─ Auth: Machine-key + mTLS
     │  │  └─ Timeout: 2 seconds (enforcer timeout default)
     │  │
     │  └─ REST API (development)
     │     ├─ HTTP/2
     │     ├─ TLS required
     │     └─ Rate limit: 1000 req/min per host
     │
     └─ Observability
        ├─ Logging
        │  ├─ Level: INFO (default) → DEBUG
        │  ├─ Output: JSON logs (parse-friendly)
        │  └─ Aggregation: ELK / Splunk / Datadog
        │
        ├─ Metrics
        │  ├─ Prometheus format
        │  ├─ Metrics:
        │  │  ├─ policy_evaluation_duration_ms (histogram)
        │  │  ├─ policy_decisions_total (counter)
        │  │  ├─ audit_ledger_entries (gauge)
        │  │  └─ enforcer_connectivity (gauge)
        │  │
        │  └─ Scrape: Prometheus /metrics endpoint
        │
        └─ Tracing
           ├─ Format: OpenTelemetry
           ├─ Sampler: 10% (adjustable)
           └─ Exporter: Jaeger / Datadog / Splunk
```

---

## Policy Evaluation Flow

### Detailed Decision Tree

```
                    Network Connection Attempt
                              │
                              ▼
                    ┌──────────────────────┐
                    │  Enforcer intercepts │
                    │  (eBPF / ETW / audit)│
                    └──────────┬───────────┘
                               │
                    Extract connection info:
                    ├─ source_ip, source_port
                    ├─ destination_ip, destination_port
                    ├─ protocol (TCP/UDP)
                    ├─ process_pid, process_uid
                    └─ process_name
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Query Control Plane  │
                    │  gRPC /Validate      │
                    │                      │
                    │ Payload:             │
                    │ {source, dest,       │
                    │  process, policy_id} │
                    └──────────┬───────────┘
                               │
                    ┌──────────┴──────────┐
                    │ Control Plane      │
                    └──────────┬──────────┘
                               │
                    Step 1: Authenticate
                    ├─ Verify machine-key signature
                    ├─ Check rate limit (enforcer host)
                    └─ Extract identity context
                               │
                               ▼
                    Step 2: OPA Policy Evaluation
                    │
                    ├─ Query: input.destination in approved_destinations?
                    │  └─ Cache hit? → Skip evaluation
                    │  └─ Cache miss? → Evaluate OPA
                    │
                    ├─ OPA Evaluation:
                    │  ├─ Load policy (rego/runtime.rego)
                    │  ├─ Evaluate rules
                    │  ├─ Match conditions
                    │  └─ Return: ALLOW | DENY
                    │
                    └─ Cache result (5 min TTL)
                               │
                               ▼
                    Step 3: SRP Verdict Engine
                    │  (if structured proposal)
                    │
                    ├─ Is request a tool proposal?
                    │  ├─ Yes → Continue
                    │  └─ No  → Skip SRP
                    │
                    ├─ Evaluate YAML rules
                    │  ├─ Condition matching
                    │  ├─ Effect evaluation
                    │  └─ Return: ALLOW | DENY | ESCALATE
                    │
                    └─ Escalation check?
                       ├─ Create escalation ticket
                       └─ Notify security team
                               │
                               ▼
                    Step 4: Merge Decisions
                    │
                    ├─ OPA: ALLOW, SRP: ALLOW → ALLOW
                    ├─ OPA: ALLOW, SRP: DENY  → DENY
                    ├─ OPA: DENY,  SRP: *     → DENY
                    ├─ SRP: ESCALATE          → ESCALATE
                    │
                    └─ Final verdict
                               │
                               ▼
                    Step 5: Log to Audit Ledger
                    │
                    ├─ Create event:
                    │  {
                    │    timestamp,
                    │    agent_id,
                    │    action,
                    │    destination,
                    │    verdict,
                    │    matched_rule,
                    │    process_info
                    │  }
                    │
                    ├─ Compute hash:
                    │  event_hash = SHA256(previous_hash + event_json)
                    │
                    └─ Insert to PostgreSQL
                               │
                               ▼
                    Step 6: Return Decision to Enforcer
                    │
                    ├─ Response:
                    │  {
                    │    verdict: "ALLOW" | "DENY" | "ESCALATE",
                    │    reason: "matched policy rule X",
                    │    escalation_ticket_id: "TICKET-123"
                    │  }
                    │
                    └─ Enforcer receives decision
                               │
                               ▼
                    Step 7: Enforce at Kernel Level
                    │
                    ├─ If verdict = ALLOW
                    │  └─ eBPF returns 1 → packet proceeds
                    │
                    ├─ If verdict = DENY
                    │  └─ eBPF returns 0 → packet dropped
                    │     Agent gets: "connection refused"
                    │
                    └─ If verdict = ESCALATE
                       └─ DENY + Alert escalation team
                               │
                               ▼
                    ┌──────────────────────┐
                    │ End: Enforcement     │
                    │ Complete & Audited   │
                    └──────────────────────┘
```

---

## Enforcement Pipeline (per OS)

### Linux: eBPF Cgroup Socket Hook

```
Linux Network Stack & eBPF Integration

┌─────────────────────────────────────────────────────────────┐
│ Application Layer                                           │
│                                                             │
│  Claude Code / Codex Agent                                 │
│    │                                                        │
│    └─→ socket() → connect() → send()                       │
│                       │                                     │
│                       ▼                                     │
│    ┌────────────────────────────────────┐                  │
│    │ Berkeley Packet Filter (BPF)       │                  │
│    │ Entry: cgroup_inet_egress hook     │                  │
│    │                                    │                  │
│    │ Runs BEFORE kernel network stack   │                  │
│    │ (can drop packet here)             │                  │
│    └────────────────────┬───────────────┘                  │
│                         │                                   │
│         ┌───────────────┴───────────────┐                  │
│         │                               │                  │
│    eBPF action: allow (1)    eBPF action: drop (0)         │
│         │                               │                  │
│         ▼                               ▼                  │
│    Packet proceeds              User gets ECONNREFUSED     │
│    to network stack             or "connection refused"    │
│                                                             │
└─────────────────────────────────────────────────────────────┘

eBPF Program Structure (gavel.bpf.c):

    SEC("cgroup/inet_egress")
    int socket_filter(struct __sk_buff *skb) {
        
        // 1. Parse packet header
        struct iphdr *ip = parse_ip_header(skb);
        struct tcphdr *tcp = parse_tcp_header(skb);
        
        // 2. Extract connection tuple
        __u32 src_ip = ip->saddr;
        __u32 dst_ip = ip->daddr;
        __u16 dst_port = tcp->dest;
        
        // 3. Extract process context
        __u64 uid_gid = bpf_get_current_uid_gid();
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        
        // 4. Build policy query
        struct policy_query query = {
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .dst_port = dst_port,
            .pid = pid,
            .uid = uid_gid & 0xFFFFFFFF
        };
        
        // 5. Call userspace (via BPF ringbuffer)
        bpf_ringbuf_output(&ringbuffer, &query, sizeof(query), 0);
        
        // 6. Check local cache for cached decisions
        struct decision *cached = bpf_map_lookup_elem(&decision_cache, &query);
        if (cached) {
            if (cached->verdict == DENY) {
                return 0;  // Drop
            }
            return 1;      // Allow
        }
        
        // 7. Default: allow (enforcer is synchronously fast)
        return 1;
    }

Kernel ↔ Userspace Communication (Ringbuffer):

    Userspace Enforcer (Go)
    │
    ├─ Read from BPF ringbuffer
    │  (queries from kernel)
    │
    ├─ For each query:
    │  ├─ Call Control Plane: /validate
    │  │  (gRPC to control-plane:8443)
    │  │
    │  └─ Get decision: ALLOW | DENY
    │
    └─ Update eBPF map: decision_cache
       (so next packet can use cached result)
```

### Windows: ETW + WFP

```
Windows Event Tracing & Filtering Platform

┌─────────────────────────────────────────────────────────────┐
│ Application Layer                                           │
│                                                             │
│  Claude Code / Codex Agent                                 │
│    │                                                        │
│    └─→ WinSock2: socket() → WSAConnect() → send()          │
│                       │                                     │
│                       ▼                                     │
│    ┌────────────────────────────────────┐                  │
│    │ Event Tracing for Windows (ETW)    │                  │
│    │                                    │                  │
│    │ Events:                            │                  │
│    │ ├─ Process creation (PID)          │                  │
│    │ ├─ Process termination             │                  │
│    │ ├─ Network connect (IP:port)       │                  │
│    │ └─ DNS query (hostname)            │                  │
│    │                                    │                  │
│    │ Trace Listener (Userspace):        │                  │
│    │ └─→ Go enforcer consumes events    │                  │
│    └────────────────────┬───────────────┘                  │
│                         │                                   │
│                    For each event:                          │
│                    ├─ Enrich: agent_id, process context    │
│                    ├─ Call Control Plane                    │
│                    └─ Get decision: ALLOW | DENY           │
│                         │                                   │
│         ┌───────────────┴───────────────┐                  │
│         │                               │                  │
│    ALLOW (log only)        DENY (apply WFP rule)           │
│         │                               │                  │
│         ▼                               ▼                  │
│    Connection proceeds           Windows Filtering         │
│                                   Platform (WFP)           │
│                                   │                        │
│                                   ├─ Add firewall rule     │
│                                   │  (block agent PID)     │
│                                   │                        │
│                                   └─→ Connection refused   │
│                                                             │
└─────────────────────────────────────────────────────────────┘

WFP Rule Example (PowerShell):

    $ruleName = "Gavel-Agent-Block-$($agentId)"
    
    # 1. Get WFP layer
    $layer = Get-NetFirewallProfile | Where {$_.Name -eq "Domain"}
    
    # 2. Create rule
    $rule = @{
        DisplayName = $ruleName
        Direction = "Outbound"
        Action = "Block"
        Protocol = "TCP"
        LocalPort = "Any"
        RemoteAddress = "192.168.1.100"  # e.g., blocked IP
        RemotePort = "443"
        Program = "C:\path\to\agent.exe"  # or use Process ID
        PolicyStore = "ActiveStore"
    }
    
    # 3. Apply rule
    Add-NetIPsecRule @rule

ETW Event Consumer (Go):

    import "github.com/google/gopacket/pcap"
    
    etw := etw.NewSession("Gavel-Enforcer")
    
    // Subscribe to process creation events
    etw.Subscribe(etw.ProcessCreateEvent, func(e *Event) {
        query := PolicyQuery{
            AgentId:  e.ProcessName,
            Pid:      e.ProcessId,
            Uid:      e.UserId,
        }
        
        decision := enforcer.ValidateProcess(&query)
        if decision == DENY {
            // Apply WFP block rule
            enforcer.BlockProcessNetwork(e.ProcessId)
        }
    })
```

### macOS: Audit-Only (v1.0)

```
macOS System Audit Integration

┌─────────────────────────────────────────────────────────────┐
│ Application Layer                                           │
│                                                             │
│  Claude Code Agent                                          │
│    │                                                        │
│    └─→ socket() → connect() → send()                       │
│                       │                                     │
│                       ▼                                     │
│    ┌────────────────────────────────────┐                  │
│    │ System Audit (auditd)              │                  │
│    │                                    │                  │
│    │ Events (read-only):                │                  │
│    │ ├─ exec (process execution)        │                  │
│    │ ├─ network (DNS queries)           │                  │
│    │ ├─ open (file operations)          │                  │
│    │ └─ system calls (various)          │                  │
│    │                                    │                  │
│    │ Audit Log:                         │                  │
│    │ └─→ /var/log/audit.log             │                  │
│    └────────────────────┬───────────────┘                  │
│                         │                                   │
│                    Gavel Enforcer reads                     │
│                    audit log (tail -f)                      │
│                         │                                   │
│                    ├─ Parse event                           │
│                    ├─ Call Control Plane                    │
│                    └─ Log decision (no blocking)            │
│                         │                                   │
│                         ▼                                   │
│                    Audit Trail                              │
│                    (observability only)                     │
│                                                             │
│    NOTE: No blocking capability (v1.0)                     │
│    Planned: System Extension (v1.1)                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘

macOS Audit Log Format:

    header,282,1,connect(2),0,Mon Apr 29 14:30:22 2026 PDT
    subject,root,wheel,wheel,502,100066,100066,34816
    return,success,0
    data_host,HOSTNAME,::1
    data_ip,192.168.1.100,443
    file,/var/log/audit.log

Gavel macOS Enforcer (Go):

    func (e *Enforcer) MonitorAudit() {
        
        // Open audit log
        auditFile, _ := os.Open("/var/log/audit.log")
        defer auditFile.Close()
        
        // Tail file for new events
        scanner := bufio.NewScanner(auditFile)
        
        for scanner.Scan() {
            line := scanner.Text()
            
            // Parse audit line
            event := parseAuditEvent(line)
            
            // Query control plane
            decision := e.ValidateEvent(event)
            
            // Log decision (audit-only)
            e.Logger.WithFields(log.Fields{
                "agent_id": event.ProcessName,
                "action": event.Action,
                "decision": decision.Verdict,
            }).Info("Audit event processed")
        }
    }

Future: System Extension (v1.1)

    ┌─────────────────────────────────────┐
    │ System Extension (NEPacketProvider) │
    │                                     │
    │ ├─ Intercepts network packets      │
    │ ├─ (like eBPF on Linux)             │
    │ ├─ Requires user approval           │
    │ └─ Can block connections            │
    └─────────────────────────────────────┘
```

---

## Data Model & Schema

### PostgreSQL Audit Ledger

```sql
-- Core audit ledger table (SHA-256 chained)

CREATE TABLE audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    
    -- Ordering & Verification
    event_sequence BIGINT UNIQUE NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    
    -- Event Content
    event_json JSONB NOT NULL,
    event_hash VARCHAR(64) NOT NULL UNIQUE,
    
    -- Indexing for fast queries
    agent_id VARCHAR(256) NOT NULL,
    verdict VARCHAR(32) NOT NULL,  -- ALLOW, DENY, ESCALATE
    resource_type VARCHAR(128),     -- network, file, process
    action VARCHAR(128),            -- connect, read, execute
    
    -- Audit Fields
    created_at TIMESTAMPTZ DEFAULT now(),
    indexed_at TIMESTAMPTZ
);

-- Hash computation trigger (ensures chain integrity)
CREATE OR REPLACE FUNCTION compute_event_hash()
RETURNS TRIGGER AS $$
BEGIN
    NEW.event_hash := encode(
        digest(
            (NEW.previous_hash || NEW.event_json::text)::bytea,
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_ledger_hash
BEFORE INSERT ON audit_ledger
FOR EACH ROW
EXECUTE PROCEDURE compute_event_hash();

-- Example event JSON structure:
{
  "timestamp": "2026-04-29T14:30:22.123Z",
  "agent_id": "claude-code-1",
  "session_id": "sess_abc123",
  "user_id": "user_def456",
  
  "event": {
    "type": "network.connect",
    "action": "connect",
    "source": {
      "ip": "10.0.1.50",
      "port": 45678,
      "pid": 1234,
      "uid": 1000,
      "process_name": "claude-code"
    },
    "destination": {
      "ip": "93.184.216.34",  # example.com
      "hostname": "api.example.com",
      "port": 443,
      "protocol": "TCP"
    }
  },
  
  "policy": {
    "matched_rule": "enforce-api-whitelist",
    "rule_version": "1.2.3",
    "policy_set": "default"
  },
  
  "decision": {
    "verdict": "ALLOW",
    "reason": "destination in approved_apis list",
    "evaluated_by": "opa-engine",
    "evaluation_time_ms": 2
  },
  
  "escalation": {
    "required": false,
    "reason": null,
    "ticket_id": null
  }
}

-- Query: All DENY decisions in last hour
SELECT 
    event_time,
    agent_id,
    event_json->'event'->>'action' as action,
    event_json->'decision'->>'reason' as reason
FROM audit_ledger
WHERE verdict = 'DENY'
  AND event_time > now() - interval '1 hour'
ORDER BY event_time DESC;

-- Query: Detect suspicious behavior (multiple DENY in short period)
SELECT 
    agent_id,
    COUNT(*) as deny_count,
    MIN(event_time) as first_attempt,
    MAX(event_time) as last_attempt
FROM audit_ledger
WHERE verdict = 'DENY'
  AND event_time > now() - interval '1 hour'
GROUP BY agent_id
HAVING COUNT(*) > 5
ORDER BY deny_count DESC;

-- Verify audit chain (detect tampering)
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE (is_valid BOOLEAN, first_invalid_id BIGINT) AS $$
DECLARE
    current_row audit_ledger%ROWTYPE;
    expected_hash VARCHAR(64);
BEGIN
    FOR current_row IN 
        SELECT * FROM audit_ledger ORDER BY event_sequence ASC
    LOOP
        IF current_row.event_sequence > 1 THEN
            -- Verify hash matches
            expected_hash := encode(
                digest(
                    (current_row.previous_hash || current_row.event_json::text)::bytea,
                    'sha256'
                ),
                'hex'
            );
            
            IF expected_hash != current_row.event_hash THEN
                RETURN QUERY SELECT FALSE, current_row.id;
                RETURN;
            END IF;
        END IF;
    END LOOP;
    
    RETURN QUERY SELECT TRUE, NULL::BIGINT;
END;
$$ LANGUAGE plpgsql;
```

### Runtime Events Table

```sql
-- Lightweight event table for streaming/real-time analytics

CREATE TABLE runtime_events (
    id BIGSERIAL PRIMARY KEY,
    
    -- Event identification
    event_id UUID UNIQUE NOT NULL,
    event_type VARCHAR(128) NOT NULL,  -- network, policy, audit, error
    event_time TIMESTAMPTZ NOT NULL,
    
    -- Agent context
    agent_id VARCHAR(256) NOT NULL,
    session_id VARCHAR(256),
    user_email VARCHAR(256),
    
    -- Operation metadata
    resource_type VARCHAR(64),
    action VARCHAR(64),
    verdict VARCHAR(32),
    
    -- Timing
    duration_ms INTEGER,
    
    -- Payload (flexible structure)
    metadata JSONB,
    
    -- Lifecycle
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    
    -- Indexes for fast queries
    INDEX idx_agent_time (agent_id, event_time DESC),
    INDEX idx_verdict_time (verdict, event_time DESC),
    INDEX idx_event_type (event_type)
);

-- TTL: Keep for 7 days, archive older entries
ALTER TABLE runtime_events
SET (ttl_expression = 'event_time + INTERVAL ''7 days''');
```

---

## Integration Patterns

### Pattern 1: REST API → Control Plane

```
Development/Testing Pattern

┌──────────────────┐
│ CLI Tool / REST  │
│ Client           │
└────────┬─────────┘
         │
         │ POST /external/validate
         │ {agent_id, action, resource}
         │
         ▼
┌──────────────────────────────────────┐
│ Control Plane (FastAPI)              │
│                                      │
│ @router.post("/external/validate")   │
│ def validate(req: ValidateRequest):  │
│     # 1. Authenticate (JWT/machine-key)
│     # 2. Evaluate policy (OPA/SRP)
│     # 3. Log to audit ledger
│     # 4. Return decision
│     return {                          │
│         "verdict": "ALLOW",           │
│         "reason": "...",              │
│     }                                 │
└──────────────────────────────────────┘

Response:
{
    "verdict": "ALLOW",
    "reason": "destination in approved_ips",
    "decision_id": "dec_xyz789",
    "timestamp": "2026-04-29T14:30:22Z"
}
```

### Pattern 2: gRPC ext_authz → Envoy

```
Production Pattern (Kubernetes)

┌─────────────────┐
│ Envoy Proxy     │
│ (sidecar)       │
└────────┬────────┘
         │
         │ gRPC ext_authz
         │ (mTLS encrypted)
         │
         ▼
┌──────────────────────────────────────┐
│ Control Plane (FastAPI gRPC server)  │
│                                      │
│ @router.grpc_endpoint()              │
│ async def check(                     │
│     req: CheckRequest                │
│ ) -> CheckResponse:                  │
│     # 1. Extract identity            │
│     # 2. Evaluate policy             │
│     # 3. Return decision             │
│     return CheckResponse(            │
│         status=OK/PERMISSION_DENIED  │
│     )                                │
└──────────────────────────────────────┘

Envoy Config:
http_filters:
  - name: envoy.ext_authz
    typed_config:
      grpc_service:
        envoy_grpc:
          cluster_name: gavel-control-plane
        timeout: 2s  # 2 second timeout
      
      with_request_body: true
      check_settings:
        context_extensions:
          x-request-id: "%REQ(X-REQUEST-ID)%"
```

### Pattern 3: Enforcer ↔ Control Plane (Production)

```
High-Performance Pattern

  Enforcer (Host)                Control Plane (Central)
  ┌──────────────────┐           ┌──────────────────────┐
  │ 1. eBPF Hook     │           │                      │
  │    intercepts    │           │ gRPC Server          │
  │    connection    │           │ ┌────────────────┐   │
  │                  │           │ │ validate_async │   │
  │ 2. Extract info  │───────────│→│ (connection)   │   │
  │                  │ gRPC call │ │                │   │
  │ 3. Query cached  │◄──────────│ │ Returns:       │   │
  │    decision      │ Decision  │ │ {verdict...}   │   │
  │                  │           │ └────────────────┘   │
  │ 4. If cached,    │           │                      │
  │    enforce now   │           │ OPA Engine           │
  │                  │           │ SRP Engine           │
  │ 5. If miss,      │           │ Audit Ledger         │
  │    wait for      │           │                      │
  │    response      │           │ Redis Cache          │
  │                  │           │ (policy results)     │
  │ 6. Cache result  │           │                      │
  │    (5 min TTL)   │           │                      │
  │                  │           │                      │
  │ 7. Enforce       │           │                      │
  │    (allow/deny)  │           │                      │
  └──────────────────┘           └──────────────────────┘

Latency Profile:
- Cache hit: 0.5 ms (eBPF lookup in kernel)
- Cache miss: 2-5 ms (gRPC to control plane + OPA evaluation)
- Typical: 95% cache hit rate → avg 1 ms latency
```

---

## Deployment Topology Maps

### Single-Host Development

```
Developer Machine
│
├─ Docker Container 1
│  ├─ Gavel Control Plane
│  │  ├─ FastAPI server (port 8000)
│  │  ├─ OPA engine (port 8181)
│  │  └─ gRPC server (port 8443)
│  │
│  ├─ PostgreSQL (port 5432)
│  │
│  └─ Redis (port 6379)
│
├─ Docker Container 2
│  ├─ Agent 1 (Claude Code)
│  │  └─ Localhost → Control Plane
│  │
│  └─ Gavel Enforcer (host network mode)
│     └─ Intercepts Agent 1 connections
│
├─ Docker Container 3
│  ├─ Agent 2 (Codex)
│  │  └─ Localhost → Control Plane
│  │
│  └─ Gavel Enforcer (host network mode)
│     └─ Intercepts Agent 2 connections
│
└─ localhost:8000/health → Control Plane status
```

### Kubernetes (Multi-Tenant Production)

```
Kubernetes Cluster (Multi-Zone)
│
├─ gavel-system Namespace
│  │
│  ├─ Deployment: gavel-control-plane
│  │  ├─ Replica 1 (zone-a)
│  │  ├─ Replica 2 (zone-b)
│  │  └─ Replica 3 (zone-c)
│  │  
│  │  Pod Internals:
│  │  ├─ FastAPI container (port 8000)
│  │  ├─ OPA sidecar (port 8181)
│  │  ├─ Policy loader (watches ConfigMap)
│  │  └─ Audit exporter (→ PostgreSQL)
│  │
│  ├─ StatefulSet: PostgreSQL
│  │  ├─ Primary (zone-a)
│  │  ├─ Standby (zone-b)
│  │  └─ Standby (zone-c)
│  │  
│  │  Storage:
│  │  ├─ PVC: /data (primary)
│  │  ├─ WAL log
│  │  └─ Backup snapshots → S3
│  │
│  ├─ Deployment: Redis Cache
│  │  └─ 2 replicas (master-slave)
│  │
│  ├─ DaemonSet: gavel-enforcer
│  │  ├─ One pod per node
│  │  ├─ Host network mode
│  │  ├─ eBPF program loaded
│  │  └─ Connects to control plane (gRPC)
│  │
│  ├─ ConfigMap: Policies
│  │  ├─ rego policies (authz.rego, runtime.rego)
│  │  └─ YAML rules (default.yaml)
│  │
│  └─ Service: gavel-control-plane
│     ├─ Service type: ClusterIP
│     ├─ Port 8000 (REST)
│     └─ Port 8443 (gRPC)
│
├─ Agent Namespaces (per customer)
│  │
│  ├─ customer-a
│  │  ├─ Deployment: claude-code-agent
│  │  │  ├─ Pod 1
│  │  │  └─ Pod 2
│  │  │
│  │  └─ Deployment: codex-agent
│  │     └─ Pod 1
│  │
│  └─ customer-b
│     ├─ Deployment: claude-code-agent
│     └─ Deployment: codex-agent
│
└─ Monitoring Namespace
   ├─ Prometheus (scrapes /metrics)
   ├─ Grafana (dashboards)
   └─ Loki (log aggregation)
```

---

## Request Lifecycle Sequence

### Complete End-to-End Flow

```
TIME    ACTOR              ACTION
────────────────────────────────────────────────────────────

0ms     Agent Process      1. Attempt: socket.connect("api.openai.com", 443)
                              └─ Python code: urllib.request.urlopen(url)

1ms     Linux Kernel       2. eBPF hook triggered: cgroup_inet_egress
        (eBPF)               ├─ Extract tuple: (10.0.1.50:45678 → 93.184.216.34:443)
                             ├─ Extract PID: 1234, UID: 1000
                             └─ Build query

2ms     eBPF Program       3. Query local cache
                             └─ Cache miss → must call userspace

3ms     Enforcer           4. Read from BPF ringbuffer
        (Host Process)       ├─ Dequeue query
                             └─ Prepare to call control plane

4ms     Network            5. gRPC call to control plane
        (TLS+mTLS)           POST grpc://control-plane:8443/Validate
                             ├─ Auth: machine-key signature
                             ├─ Payload: {pid, uid, src, dst}
                             └─ Wait for response (timeout: 2s)

5-7ms   Control Plane      6. Receive request at gRPC handler
        (FastAPI)            ├─ Verify machine-key auth
                             ├─ Rate limit check: passed
                             └─ Begin policy evaluation

7ms     OPA Engine         7. Load policy (rego/runtime.rego)
                             ├─ Query cache: "is 93.184.216.34 approved?"
                             ├─ Cache miss → evaluate OPA
                             └─ OPA decision: allowed (in approved_domains)

10ms    Redis Cache        8. Cache result
                             ├─ Key: hash(dest_ip)
                             ├─ Value: {verdict: ALLOW, ttl: 5m}
                             └─ Store in Redis

11ms    SRP Verdict Engine 9. Evaluate tool proposals
                             └─ (skipped: this is network-level, not tool call)

12ms    Audit Ledger       10. Log decision to PostgreSQL
        (PostgreSQL)          ├─ Event: {timestamp, agent, verdict, reason}
                              ├─ Compute hash: SHA256(prev + event)
                              └─ INSERT audit_ledger

14ms    Control Plane      11. Prepare response
                             └─ Return: {verdict: ALLOW, decision_id, timestamp}

15ms    Network            12. gRPC response arrives at enforcer

16ms    eBPF Program       13. Update decision cache
        (BPF Map)            ├─ Store: {query → ALLOW, ttl: 5m}
                             └─ Now subsequent connections use cache

17ms    eBPF Program       14. Return decision: 1 (allow)

18ms    Linux Kernel       15. Kernel receives return: 1
        (Network Stack)       └─ Packet allowed to proceed

20ms    Network Stack      16. Complete 3-way handshake
                             └─ Connection established

21ms    Agent Process      17. Agent receives connected socket
                             └─ can now send() data

────────────────────────────────────────────────────────────

Total latency: ~20ms (plus network RTT)
Typical: 5-15ms (if control plane is local/fast)

Cache behavior:
- First connection (same destination): 20ms
- Subsequent connections (5-min window): 1ms (cache hit)
```

---

## Code Examples & Patterns

### Example 1: Writing a Custom Policy Rule

```rego
# File: policies/rego/custom_rules.rego
# Purpose: Restrict agent to internal domains only

package sentinel.custom

import future.keywords

# Default: deny all
default allow := false

# Rule 1: Allow internal APIs
allow if {
    # Destination must be internal domain
    endswith(input.destination.domain, ".company.com")
    
    # Must be HTTPS (port 443)
    input.destination.port == 443
    
    # Must be from approved agent
    input.agent_id in data.approved_agents
}

# Rule 2: Allow approved external APIs
allow if {
    input.destination in data.approved_external_apis
}

# Rule 3: Deny suspicious patterns
deny_suspicious if {
    # Catch potential data exfiltration
    contains(input.destination, "pastebin") or
    contains(input.destination, "gist") or
    contains(input.destination, "pastie") or
    contains(input.destination, "hastebin")
}

# Data file (policies/data.json)
{
  "approved_agents": [
    "claude-code-1",
    "claude-code-2",
    "codex-financial-agent"
  ],
  
  "approved_external_apis": [
    "api.openai.com",
    "api.anthropic.com",
    "api.stripe.com"
  ]
}
```

### Example 2: YAML Policy Rule (SRP)

```yaml
# File: policies/financial_governance.yaml

name: financial-governance
version: "1.0.0"

rules:
  # Block any deletion operations
  - id: block-data-deletion
    description: "Prevent accidental or malicious data deletion"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete, drop, truncate]
      targets: [database, table, index]
    
    # Optional: escalate instead of block
    # effect: ESCALATE
    # escalation:
    #   notify: ["security@company.com"]
    #   require_approval: true
    #   approval_timeout: 3600  # 1 hour

  # Escalate large financial transactions
  - id: escalate-large-transfers
    description: "Escalate transfers over $100K for human review"
    effect: ESCALATE
    priority: 200
    condition:
      operations: [transfer, refund, payout]
      api_refs: [payments.api, billing.api]
      max_numeric_parameters:
        amount: 100000.0
    
    escalation:
      notify: ["finance-team@company.com", "audit@company.com"]
      require_approval: true
      approval_timeout: 1800  # 30 min window
      audit_reason: "large_financial_transaction"

  # Audit all access to PII
  - id: audit-pii-access
    description: "Log all accesses to personally identifiable information"
    effect: AUDIT
    priority: 50
    condition:
      resource_tags: [pii, sensitive]
      operations: [read, select, query]
    
    audit:
      log_level: INFO
      include_payload: false  # Don't log actual data
      retention_days: 2555  # 7 years for compliance
```

### Example 3: Golang Enforcer Integration

```go
package main

import (
    "context"
    "github.com/gavel-os/gavel/enforcer/runtime"
    pb "github.com/gavel-os/gavel/api/proto"
)

// Example: Query control plane for policy decision
func (e *Enforcer) ValidateConnection(
    ctx context.Context,
    srcIP string, srcPort uint16,
    dstIP string, dstPort uint16,
    pid uint32, uid uint32,
) (pb.Verdict, error) {
    
    // 1. Create policy request
    request := &pb.ValidateRequest{
        SourceIp:    srcIP,
        SourcePort:  uint32(srcPort),
        DestIp:      dstIP,
        DestPort:    uint32(dstPort),
        ProcessId:   pid,
        UserId:      uid,
        Timestamp:   timestamppb.Now(),
    }
    
    // 2. Call control plane (with timeout)
    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    
    response, err := e.controlPlaneClient.Validate(ctx, request)
    if err != nil {
        // Timeout or connection error → fail closed
        e.Logger.Errorf("policy check failed: %v (denying)", err)
        return pb.Verdict_DENY, nil
    }
    
    // 3. Cache decision locally
    e.decisionCache.Set(
        hashTuple(srcIP, dstIP, dstPort),
        response.Verdict,
        5*time.Minute,
    )
    
    return response.Verdict, nil
}

// Example: Update eBPF map with cached decision
func (e *Enforcer) updateEBPFCache(
    key string,
    verdict pb.Verdict,
) error {
    
    spec, err := ebpf.NewCollectionSpec()
    if err != nil {
        return err
    }
    
    m, exists := spec.Maps["decision_cache"]
    if !exists {
        return fmt.Errorf("decision_cache map not found")
    }
    
    // Insert verdict into eBPF map (kernel space)
    err = m.Put(key, uint32(verdict))
    if err != nil {
        e.Logger.Warnf("failed to update eBPF cache: %v", err)
    }
    
    return nil
}
```

### Example 4: Python Control Plane Handler

```python
# File: control_plane/api/routes/external.py

from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
import logging

from control_plane.auth import verify_machine_key
from control_plane.sentinel import opa_engine
from control_plane.srp import verdict_engine
from control_plane.sdk import audit_ledger
from control_plane.models import ValidateRequest, ValidateResponse

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/external/validate")
async def validate(
    req: ValidateRequest,
    verified_auth: dict = Depends(verify_machine_key),
) -> ValidateResponse:
    """
    Enforce policy decision for a network connection.
    
    Called by:
    - Enforcer (eBPF on Linux, WFP on Windows)
    - CLI tools (testing)
    - Envoy ext_authz filter
    
    Returns:
    {
        "verdict": "ALLOW" | "DENY" | "ESCALATE",
        "reason": "matched rule X",
        "decision_id": "dec_abc123"
    }
    """
    
    try:
        # 1. Extract policy input
        policy_input = {
            "destination": {
                "ip": req.dest_ip,
                "port": req.dest_port,
                "domain": resolve_domain(req.dest_ip),
            },
            "source": {
                "ip": req.source_ip,
                "pid": req.process_id,
                "uid": req.user_id,
            },
            "agent_id": extract_agent_id(req.process_id),
            "identity": verified_auth,
        }
        
        # 2. Evaluate OPA policy
        opa_decision = await opa_engine.evaluate_network_policy(policy_input)
        logger.info(f"OPA decision: {opa_decision.verdict}")
        
        # 3. Evaluate SRP (if structured proposal)
        if req.tool_proposal:
            srp_decision = await verdict_engine.evaluate_proposal(
                req.tool_proposal,
                policy_input,
            )
        else:
            srp_decision = None
        
        # 4. Merge decisions
        final_verdict = merge_verdicts(opa_decision, srp_decision)
        
        # 5. Log to audit ledger
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": policy_input["agent_id"],
            "action": "network.connect",
            "destination": policy_input["destination"],
            "verdict": final_verdict.verdict,
            "reason": final_verdict.reason,
        }
        
        await audit_ledger.insert_event(event)
        
        # 6. Return decision to enforcer
        return ValidateResponse(
            verdict=final_verdict.verdict,
            reason=final_verdict.reason,
            decision_id=generate_id(),
            timestamp=datetime.utcnow(),
        )
        
    except Exception as e:
        logger.exception(f"Policy evaluation failed: {e}")
        # Fail closed: deny on error
        return ValidateResponse(
            verdict="DENY",
            reason="policy engine error (fail-closed)",
            decision_id=generate_id(),
        )
```

---

## Summary

This architecture document provides:

1. **System-level understanding** — how Gavel components interact
2. **OS-specific details** — Linux (eBPF), Windows (ETW+WFP), macOS (audit)
3. **Policy evaluation flow** — request → decision → enforcement
4. **Data model** — PostgreSQL schema, event structure
5. **Integration patterns** — REST, gRPC ext_authz, enforcer ↔ control plane
6. **Deployment topologies** — single-host, Kubernetes, hybrid cloud
7. **Code examples** — Rego, YAML, Go, Python patterns

**For Implementation:**
- Start with Linux (eBPF) deployment
- Use Docker Compose locally, Kubernetes in production
- Follow the policy writing patterns for your use cases
- Monitor enforcement latency (target: <5ms p99)

---

**Document Version:** 1.0  
**Last Updated:** April 2026  
**Maintained By:** Gavel Platform Team
