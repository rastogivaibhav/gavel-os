# P0 resource isolation goal

Goal: under A0/A1 and a trusted host/supervisor, close indirect resource paths for guarded unprivileged arbitrary code, with actual kernel evidence. Existing issues #5/#6/#7 track these operations; no duplicate issue.

| Gate | Acceptance | Status |
| --- | --- | --- |
| P0.1 | Ambient file/socket descriptors absent; stdin inert; output write-only pipe/null; positive controls and descendants | IMPLEMENTED_UNVERIFIED |
| P0.2 | Unapproved Unix IPC and descriptor transfer denied, approved local use tested | OPEN |
| P0.3 | Mapped IPv6 and connected socket paths obey policy | OPEN |
| P0.4 | Trusted helper channels constrained, exclusions explicit | OPEN |
| P0.5 | A0/A1 policy/map/link modification denied and actual enforcement persists | OPEN |

Completion requires passing isolated privileged CI, observed effects, reviewed threat assumptions and independent reproduction; no host-root claim. Prioritize failures before another gate; no auto-merge.

P0.1 deliberately uses close_range(CLOEXEC) in the dedicated trusted supervisor, requires atomic CLOEXEC for any concurrent trusted opens, and only preserves the sealed public filter FD. stdin becomes /dev/null; stdout/stderr must already be write-only pipes or /dev/null. Operators must launch with trusted output sinks (no direct terminal/file/socket redirection). Existing output pipes remain an authorized communication channel, not a general IPC guarantee. This does not prohibit later descriptor transfer, procfs reopening, same-UID helper access, or all inherited resources in non-guarded PID mode. Requires Linux >=5.11; fail closed on unsupported close_range. No tests on live user hosts.
