# P0 resource isolation goal

Goal: under A0/A1 and a trusted host/supervisor, close indirect resource paths for guarded unprivileged arbitrary code, with actual kernel evidence. Existing issues #5/#6/#7 track these operations; no duplicate issue.

| Gate | Acceptance | Status |
| --- | --- | --- |
| P0.1 | Ambient file/socket descriptors absent; stdin inert; output write-only pipe/null; positive controls and descendants | KERNEL_TESTED (run 45774704902) |
| P0.2 | Unapproved Unix IPC and descriptor transfer denied, approved local use tested | IMPLEMENTED_UNVERIFIED (strict socket policy slice) |
| P0.3 | Mapped IPv6 and connected socket paths obey policy | OPEN |
| P0.4 | Trusted helper channels constrained, exclusions explicit | OPEN |
| P0.5 | A0/A1 policy/map/link modification denied and actual enforcement persists | OPEN |

Completion requires passing isolated privileged CI, observed effects, reviewed threat assumptions and independent reproduction; no host-root claim. Prioritize failures before another gate; no auto-merge.

P0.1 deliberately uses close_range(CLOEXEC) in the dedicated trusted supervisor, requires atomic CLOEXEC for any concurrent trusted opens, and only preserves the sealed public filter FD. stdin becomes /dev/null; stdout/stderr must already be write-only pipes or /dev/null. Operators must launch with trusted output sinks (no direct terminal/file/socket redirection). Existing output pipes remain an authorized communication channel, not a general IPC guarantee. This does not prohibit later descriptor transfer, procfs reopening, same-UID helper access, or all inherited resources in non-guarded PID mode. Requires Linux >=5.11; fail closed on unsupported close_range. No tests on live user hosts.

## P0.2 strict Unix socket boundary

Guarded seccomp refuses all newly created externally addressable AF_UNIX sockets (pathname and abstract), while allowing AF_UNIX SOCK_STREAM socketpair for private same-domain communication. Datagram/seqpacket pairs and pidfd_getfd are denied. This intentionally breaks applications requiring D-Bus, Docker sockets, local Unix agents or other Unix services; there is no compatibility bypass. The change does not inspect ancillary data on approved private pairs: transfers of descriptors already held within the protected domain are allowed. Tests must show actual external synthetic descriptor receipt without the guard, kernel denial with the guard, no external server connections, allowed private stream communication and fork/exec inheritance. Same-UID /proc reopening, other IPC mechanisms, allowed TCP helper services, output-pipe consumers and privileged brokers remain separate gates. Requires P0.1's trusted launch descriptor boundary. Independent review pending.
