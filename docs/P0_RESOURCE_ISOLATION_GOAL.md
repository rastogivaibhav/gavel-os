# P0 resource isolation goal

Goal: under A0/A1 and a trusted host/supervisor, close indirect resource paths for guarded unprivileged arbitrary code, with actual kernel evidence. Existing issues #5/#6/#7 track these operations; no duplicate issue.

| Gate | Acceptance | Status |
| --- | --- | --- |
| P0.1 | Ambient file/socket descriptors absent; stdin inert; output write-only pipe/null; positive controls and descendants | KERNEL_TESTED (run 45774704902) |
| P0.2 | Unapproved Unix IPC and descriptor transfer denied, approved local use tested | KERNEL_TESTED (run 45778120888; external Unix socket scope) |
| P0.3 | Mapped IPv6 and connected socket paths obey policy | KERNEL_TESTED (run 45906222748; native/mapped TCP and connected/unconnected UDP slice) |
| P0.4 | Trusted helper channels constrained, exclusions explicit | PARTIAL_KERNEL_TESTED (exclusive UID run 45907820954; system IPC implemented, verification pending) |
| P0.5 | A0/A1 policy/map/link modification denied and actual enforcement persists | OPEN |

Completion requires passing isolated privileged CI, observed effects, reviewed threat assumptions and independent reproduction; no host-root claim. Prioritize failures before another gate; no auto-merge.

P0.1 deliberately uses close_range(CLOEXEC) in the dedicated trusted supervisor, requires atomic CLOEXEC for any concurrent trusted opens, and only preserves the sealed public filter FD. stdin becomes /dev/null; stdout/stderr must already be write-only pipes or /dev/null. Operators must launch with trusted output sinks (no direct terminal/file/socket redirection). Existing output pipes remain an authorized communication channel, not a general IPC guarantee. This does not prohibit later descriptor transfer, procfs reopening, same-UID helper access, or all inherited resources in non-guarded PID mode. Requires Linux >=5.11; fail closed on unsupported close_range. No tests on live user hosts.

## P0.2 strict Unix socket boundary

Guarded seccomp refuses all newly created externally addressable AF_UNIX sockets (pathname and abstract), while allowing AF_UNIX SOCK_STREAM socketpair for private same-domain communication. Datagram/seqpacket pairs and pidfd_getfd are denied. This intentionally breaks applications requiring D-Bus, Docker sockets, local Unix agents or other Unix services; there is no compatibility bypass. The change does not inspect ancillary data on approved private pairs: transfers of descriptors already held within the protected domain are allowed. Tests must show actual external synthetic descriptor receipt without the guard, kernel denial with the guard, no external server connections, allowed private stream communication and fork/exec inheritance. Same-UID /proc reopening, other IPC mechanisms, allowed TCP helper services, output-pipe consumers and privileged brokers remain separate gates. Requires P0.1's trusted launch descriptor boundary. Independent review pending.

## P0.3 native and mapped destination blocklists

Both connect6 and sendmsg6 check the IPv4 map for exact ::ffff:0:0/96 addresses in addition to the IPv6 map. Native IPv6 stays on its own exact-key policy. Guarded tests explicitly create AF_INET6 dual-stack sockets rather than relying on Go's family selection. Test native IPv4, native IPv6, mapped IPv4 TCP, connected UDP write, explicit sendto/sendmsg on both connected and unconnected UDP, positive unguarded receiver controls and guarded descendants. This is destination blocklist enforcement, not default deny, semantic API policy, proxy parity, UDP-Lite or exhaustive protocol coverage. Existing connected descriptors from outside the guard, trusted helpers, and dynamic policy updates/revocation are not covered. CI pending; no independent review.

## P0.4 exclusive workload identity (first slice)

Guarded startup obtains a root-only, nonblocking per-UID flock under /run/gavel-guarded-uids and scans the host-visible procfs task credential records (real/effective/saved/filesystem UID) before allowing the workload to launch. Any observed matching UID, inaccessible credential record other than a vanished task, or invalid procfs/lease directory is a launch error. The lease remains held through cleanup; an orphan visible after supervisor SIGKILL is detected by the next scan. Never unlink lock files (inode replacement would permit simultaneous holders). process_vm_readv now explicitly denied alongside process_vm_writev, ptrace and pidfd_getfd. This is conservative admission control, not a kernel-enforced UID reservation: trusted host must dedicate the UID to this workload, prohibit other services/login or external launch using it, and expose the full host PID namespace/procfs. A scan cannot atomically prove absence under arbitrary concurrent external process creation or PID churn. Existing output consumers, permitted network helpers, shared GID permissions, filesystem aliases and non-socket IPC are not addressed. Dedicated UID must not be a shared account. CI pending; independent validation pending.

## P0.4 System V IPC and POSIX message queues

Strict guarded seccomp denies the native amd64/arm64 System V shared memory, message queue and semaphore syscall families and POSIX message queue syscall family. There is no opt-out or compatibility fallback. Tests exercise real synthetic shared memory, queue and semaphore objects with an unguarded unprivileged positive control, guarded parent and descendant negative controls, and host-side unchanged object state. Anonymous private memory and ordinary pipes remain usable. POSIX shared memory via files (including /dev/shm), file-backed mmap, named FIFOs, shared filesystem/GID permissions, procfs exposure, and authorized TCP services are distinct surfaces; this does not close them. Landlock is optional and does not replace helper authorization. Existing UID admission is conditional on exclusive host assignment and full procfs visibility. No independent review. PRs #18/#19 merged at 79e8f960ed83da5987b02635ffc7eaa34b5e9792; tree identical to tested #19.
