# Policy Authoring

Gavel supports two policy formats: **OPA/Rego** for network-level and API authorization decisions, and **YAML** for structured tool-call governance via the SRP VerdictEngine.

---

## OPA/Rego Policies

Rego policies live in `policies/rego/`. OPA loads them as a bundle at startup.

### Authorization policy (`authz.rego`)

Controls which identities can call which REST API endpoints.

```rego
package sentinel.api.authz

default allow := false

# Authenticated caller with sufficient clearance
allow if {
    input.identity.is_authenticated == true
    input.identity.clearance_level >= input.resource.required_clearance
    not blocked_action
}

# Runtime machine identity (enforcer → control plane)
allow if {
    input.identity.role == "runtime_machine"
    input.identity.is_authenticated == true
    not blocked_action
}

blocked_action if {
    input.resource.action in data.blocked_actions
}
```

**Input shape:**

```json
{
  "identity": {
    "is_authenticated": true,
    "role": "customer",
    "clearance_level": 2,
    "tenant_id": "acme",
    "department": "engineering"
  },
  "resource": {
    "method": "POST",
    "path": "/external/validate",
    "action": "read.data",
    "required_clearance": 1,
    "target_tenant_id": "acme"
  }
}
```

### Runtime policy (`runtime.rego`)

Controls which network actions enforcers are allowed to take.

```rego
package sentinel.runtime.policy

default allow := false

allow if {
    not blocked_by_global_list
    not blocked_by_pattern
}

blocked_by_global_list if {
    input.action in data.blocked_targets
}

blocked_by_pattern if {
    some pattern in data.blocked_patterns
    startswith(input.action, pattern)
}
```

### Data file (`data.json`)

Provides the datasets referenced by Rego rules:

```json
{
  "blocked_actions": ["data.delete", "data.drop", "admin.impersonate"],
  "blocked_roles": ["banned", "suspended"],
  "blocked_targets": ["suspicious-api.io", "malware-c2.example.com"],
  "blocked_patterns": ["169.254.", "100.64."],
  "windows_blocked_targets": [],
  "linux_blocked_targets": []
}
```

### Testing Rego policies

```bash
# Start OPA with the policy bundle
docker run --rm -p 8181:8181 \
  -v $(pwd)/policies/rego:/policies:ro \
  openpolicyagent/opa:0.70.0 run --server --bundle /policies

# Test an allow decision
curl -s -X POST http://localhost:8181/v1/data/sentinel/api/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "identity": {
        "is_authenticated": true,
        "role": "customer",
        "clearance_level": 2
      },
      "resource": {
        "action": "read.data",
        "required_clearance": 1
      }
    }
  }' | jq .result
# → true

# Test a deny decision (blocked action)
curl -s -X POST http://localhost:8181/v1/data/sentinel/api/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "identity": {"is_authenticated": true, "role": "customer", "clearance_level": 2},
      "resource": {"action": "data.delete", "required_clearance": 1}
    }
  }' | jq .result
# → false
```

---

## YAML Policies (SRP VerdictEngine)

YAML policies govern structured tool-call proposals evaluated by the `VerdictEngine`. The default policy is at `policies/default.yaml`.

### Format

```yaml
name: my-policy
version: "1.0.0"

rules:
  - id: block-data-delete
    description: "Block any agent attempting to delete or drop data"
    effect: BLOCK          # ALLOW | BLOCK | ESCALATE
    priority: 100          # lower number = evaluated first
    condition:
      operations:          # matches if tool_call.operation is in this list
        - delete
        - drop
        - truncate

  - id: escalate-financial-writes
    description: "Escalate financial write operations for human review"
    effect: ESCALATE
    priority: 300
    condition:
      api_refs:            # matches if tool_call.api_ref is in this list
        - payments.api
        - billing.api
      operations:
        - write
        - transfer

  - id: block-external-prod
    description: "Block external agents in production without elevated clearance"
    effect: BLOCK
    priority: 200
    condition:
      roles:               # matches if caller.role is in this list
        - external
        - anonymous
      environments:        # matches if proposal.environment is in this list
        - prod

  - id: block-large-transfers
    description: "Block transfers over $10,000"
    effect: BLOCK
    priority: 150
    condition:
      operations: [transfer]
      max_numeric_parameters:   # matches if parameters[field] > max_value
        amount: 10000.0
```

### Condition fields

All specified fields must match (logical AND). Each field is a set membership check.

| Field | Matches against |
|---|---|
| `tenants` | `proposal.caller.tenant_id` |
| `roles` | `proposal.caller.role` |
| `environments` | `proposal.environment` (`dev`, `staging`, `prod`) |
| `api_refs` | `proposal.tool_call.api_ref` |
| `operations` | `proposal.tool_call.operation` |
| `max_numeric_parameters` | `proposal.tool_call.parameters[field] > max_value` |

### Priority ordering

Rules are evaluated in ascending `priority` order (lower = first). The first matching rule wins. If no rule matches, the VerdictEngine applies its built-in checks (environment validation, nonce strength, parameter size).

### Hot reload

The `YamlPolicyLoader` watches the policy file for changes and reloads automatically without a restart. Changes take effect within 1 second.

### Testing YAML policies

```python
from srp.models import CallerContext, Proposal, ToolCall
from srp.policy import PolicyCondition, PolicyEffect, PolicyRule, PolicySet
from srp.verdict_engine import VerdictEngine, VerdictEngineConfig
from srp.sdk.impl.yaml_policy_loader import YamlPolicyLoader

# Load from file
loader = YamlPolicyLoader()
loader.load("policies/default.yaml")

engine = VerdictEngine(VerdictEngineConfig(policy_set=loader.policy_set))

proposal = Proposal(
    caller=CallerContext(tenant_id="acme", caller_id="agent-1", role="customer"),
    tool_call=ToolCall(api_ref="payments.api", operation="delete", parameters={}),
    environment="prod",
    replay_nonce="a" * 16,
)

verdict = engine.evaluate(proposal)
print(verdict.verdict)   # BLOCK
print(verdict.reasons)   # [VerdictReason(code='POLICY_BLOCK', ...)]
```

---

## Common Patterns

### Block all writes in production for external agents

```yaml
- id: block-external-prod-writes
  description: "External agents cannot write in production"
  effect: BLOCK
  priority: 100
  condition:
    roles: [external, anonymous]
    environments: [prod]
    operations: [write, delete, update, create, insert]
```

### Escalate high-value operations

```yaml
- id: escalate-high-value
  description: "Require human approval for transfers over $1,000"
  effect: ESCALATE
  priority: 200
  condition:
    operations: [transfer, refund, payout]
    max_numeric_parameters:
      amount: 1000.0
```

### Block specific API references entirely

```yaml
- id: block-admin-api
  description: "No agent may call the admin API"
  effect: BLOCK
  priority: 50
  condition:
    api_refs: [admin.api, system.api, internal.api]
```
