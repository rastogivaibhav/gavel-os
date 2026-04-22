package sentinel.runtime.policy

import rego.v1

# ---------------------------------------------------------------------------
# Gavel OS — Runtime Network Action Policy
#
# Evaluated for enforcer-submitted network verdicts.
# Input shape:
#   input.action        — target hostname or IP
#   input.method        — CONNECT | GET | POST | EXECUTE
#   input.host_id       — enforcer host identifier
#   input.runtime_os    — linux | windows | macos
#   input.agent_id      — agent process name or identifier
# ---------------------------------------------------------------------------

default allow := false

# ── Allow: action not on any blocklist ──────────────────────────────────────
allow if {
    not blocked_by_global_list
    not blocked_by_pattern
    not blocked_by_os_rule
}

# ── Deny: exact match on global blocked targets ─────────────────────────────
blocked_by_global_list if {
    input.action in data.blocked_targets
}

# ── Deny: action matches a blocked pattern (prefix match) ───────────────────
blocked_by_pattern if {
    some pattern in data.blocked_patterns
    startswith(input.action, pattern)
}

# ── Deny: OS-specific rules ─────────────────────────────────────────────────
blocked_by_os_rule if {
    input.runtime_os == "windows"
    input.action in data.windows_blocked_targets
}

blocked_by_os_rule if {
    input.runtime_os == "linux"
    input.action in data.linux_blocked_targets
}

# ── Verdict helpers ─────────────────────────────────────────────────────────
verdict := "ALLOW" if { allow }
verdict := "DENY"  if { not allow }
