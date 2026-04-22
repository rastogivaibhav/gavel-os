package sentinel.api.authz

import rego.v1

# ---------------------------------------------------------------------------
# Gavel OS — Base Authorization Policy
#
# Evaluated by OPAValidationEngine.check_routing_allowance().
# Input shape:
#   input.identity  — CallerContext from JWT / machine-key auth
#   input.resource  — target endpoint descriptor
# ---------------------------------------------------------------------------

default allow := false

# ── Allow: authenticated caller with sufficient clearance ───────────────────
allow if {
    input.identity.is_authenticated == true
    input.identity.clearance_level >= input.resource.required_clearance
    not blocked_action
    not blocked_role
}

# ── Allow: runtime machine identity (enforcer → control plane) ─────────────
allow if {
    input.identity.role == "runtime_machine"
    input.identity.is_authenticated == true
    not blocked_action
}

# ── Allow: admin role bypasses clearance check (not action blocklist) ──────
allow if {
    input.identity.role == "admin"
    input.identity.is_authenticated == true
    not blocked_action
}

# ── Deny: action is on the global blocklist ─────────────────────────────────
blocked_action if {
    input.resource.action in data.blocked_actions
}

# ── Deny: role is explicitly denied ─────────────────────────────────────────
blocked_role if {
    input.identity.role in data.blocked_roles
}

# ── Deny: anonymous callers are never allowed ───────────────────────────────
deny_anonymous if {
    input.identity.is_authenticated == false
}
