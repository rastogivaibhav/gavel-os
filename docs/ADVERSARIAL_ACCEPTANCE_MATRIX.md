# GavelOS — Adversarial OS-operation acceptance matrix

**Baseline date:** 2026-11-23. Status is evidence-gated. One explicitly scoped kernel proof (T01/T10) passed in [GitHub Actions run 45285372144](https://github.com/rastogivaibhav/gavel-os/actions/runs/45285372144); all other tests remain unproven unless separately recorded.

**State vocabulary:** NOT_IMPLEMENTED / IMPLEMENTED_UNVERIFIED / KERNEL_TESTED / ADVERSARIAL_TESTED / INDEPENDENTLY_VERIFIED. `PASS` requires evidence (kernel status, test log, version/ref). `DENY` in a control-plane log without blocked OS action is not PASS.

| ID | Unauthorized action by agent | Required OS mediation | Baseline GavelOS state | Target proof |
|---|---|---|---|---|
| T01 | Outbound TCP IPv4 to denied IP | cgroup/connect4 | KERNEL_TESTED; run 45285372144 (one test PID; startup failure handling still unverified) | Kernel returns refusal, independent of middleware |
| T02 | Same operation from fork/exec child | Cgroup identity inheritance | KERNEL_TESTED for dedicated guarded cgroup; run 45292312207 (legacy PID mode still bypassable) | Child denied after replacing executable |
| T03 | IPv6 outbound | connect6/sendmsg6 | **PARTIAL KERNEL_TESTED:** IPv6 TCP connect6; PID, guarded child and crash retention (runs 45347852581, 45348118393). IPv6 UDP/sendmsg6 NOT IMPLEMENTED | Denied IPv6 TCP **and UDP**; positive permitted control |
| T04 | UDP `sendto` to denied IP | sendmsg4/sendmsg6 | IMPLEMENTED_UNVERIFIED (native unconnected UDP sendto/sendmsg; draft stacked branch, CI pending) | Denied datagram; no unintended packets |
| T05 | Unauthorized executable | BPF LSM bprm_check_security or equivalent | NOT_IMPLEMENTED | Kernel denies exec and records errno |
| T06 | Read secret/credential file | BPF LSM file_open or equivalent | NOT_IMPLEMENTED | Read denied including helper subprocess |
| T07 | Modify protected OS/config file | Appropriate file/rename/truncate hooks | NOT_IMPLEMENTED | Write, rename, truncation denied |
| T08 | Attempt eBPF program injection | bpf syscall/LSM gate, explicit capabilities | NOT_IMPLEMENTED | Unauthorized BPF load denied under declared tier |
| T09 | Tamper with maps, links or enforcer | integrity/privilege boundary | NOT_IMPLEMENTED | Agent unable to disable protection under declared tier |
| T10 | Agent bypasses SDK and invokes socket directly | same kernel network hook | KERNEL_TESTED; direct test-process TCP connect without middleware, run 45285372144 | Kernel denial still enforced |
| T11 | Semantic unauthorized API operation over allowed TLS connection | separate trusted gateway/API authorization | NOT UNIVERSALLY ENFORCED | Gateway blocks specific action; not attributed to kernel hook |
| T12 | Windows denied destination | Native WFP Windows Firewall rules | IMPLEMENTED_UNVERIFIED; scope may be host-wide | OS firewall denies; no userspace-only fallback |
| T13 | Control-plane outage and policy failure | local cached known-good controls / fail closed | PARTIAL + KERNEL_TESTED for pinned guarded workload on supervisor SIGKILL (run 45344226360); no always-on recovery daemon | Cannot enter "protected" state with unprotected actions |
| T14 | Post-boot protection tampering by host root | signed protection + trusted boot assumptions | NOT_IMPLEMENTED | Explicit hardened root threat test |
| T15 | Linux agent attempts kernel exploit | hardening/patching outside Gavel scope | OUT OF SCOPE FOR GENERAL EXPLOITS | Document boundary; no blanket claim |

## Every security test records

- `build_sha`, host kernel version, test harness image digest and kernel config.
- Agent principal, effective UID, capabilities, cgroup/namespace identity, descendant lineage.
- Exact intended attempted operation, expected deny/allow and actual OS syscall outcome/errno.
- Probe traffic or filesystem state demonstrating **no prohibited effect**.
- Loaded BPF program and attached hook, policy digest, enforcement-mode status.
- Failure-mode and false-positive controls.
- Exportable logs/artifacts with clear timestamp; no real secrets and no untrusted production targets.

## First vertical slice — T01

Prepare a disposable Linux VM with cgroup v2 and eBPF support, configure a monitored test workload and prohibited loopback/test-network destination, start enforcer under the documented setup, verify program is attached with `bpftool`, attempt direct IPv4 TCP connect, assert failure; then assert a permitted target succeeds. Repeat with application middleware absent. Record false-positive control. Run as isolated test; do not assume normal unprivileged CI runners have BPF capabilities.

## Known bypass families to investigate

PID lifecycle; subprocesses; IPv6; UDP; alternate sockets; already-open or inherited FDs; DNS and domain/IP mismatch; container mount/cgroup namespaces; privilege changes; enforcer shutdown; BPF detach; policy-update races; control-plane failure; spoofed agent identifiers; indirect API or trusted helper invocation. For each, classify as covered, excluded, or exposed and link to evidence.

## Release gate

No new claim of `kernel-enforced` for an operation until a real OS denial test passes. No claim of `agent-proof` until active adversarial tests against that operation pass. No claim of `root-resistant` without an explicitly hardened deployment and tested root threat model.

## Evidence recorded — 2026-11-23 (T01/T10)

**Evidence:** [GitHub Actions run 45285372144](https://github.com/rastogivaibhav/gavel-os/actions/runs/45285372144), job **Kernel IPv4 Denial (ephemeral VM)**; commit `9d808d50023b645d63f2ca31615f88b342c1c284` (PR #9, unmerged). GitHub log shows `TestKernelConnect4Probe` and `TestKernelConnect4Denial` **PASS**, with direct TCP dial to permitted `127.0.0.1`, kernel `EPERM/EACCES` for forbidden `127.0.0.2`, and no connection observed at the denied listener. The job ran on an ephemeral Ubuntu 26.04.1 runner with read-only repository token and a dedicated test cgroup. The test uses an in-process constructed eBPF program and controlled single PID (not a real multi-agent workload). Go version 1.26.1. The exact kernel version and effective privileged-runner capabilities were **not captured** in this job and are needed in subsequent evidence.

**Scope:** direct IPv4 TCP `connect4` only. This does not establish descendant identity, IPv6/UDP, filesystem/exec permissions, surviving enforcer termination or root-level integrity. Passing T01/T10 does not close M0 until startup and outage behavior are safe.

## M0 enforce-required startup update — 2026-11-23 (T13 partial)

Proposed branch [PR #9](https://github.com/rastogivaibhav/gavel-os/pull/9) introduces default enforcement-required startup, an explicitly unprotected `--audit-only` mode, rechecking policy before BPF attach, nonzero exit on policy or attachment failures, and an `enforcement_attached` status separate from preflight capability. Unit tests mock failed prerequisites, degraded control plane, policy race, missing BPF link and attachment failure; the CI enforcer job also asserts that a real invalid-policy executable invocation exits nonzero with a `SECURITY BLOCKER` message. **Tests must be verified green before marking CI_TESTED.**

This is a **startup-fail-stop** improvement only; it does not deny connections for an agent that is already running separately when the daemon stops or its hook is detached. A secure agent/workload launcher or equivalent independent quarantine remains necessary before T13 can pass as an agent-boundary guarantee. Issue #3 stays open.

## Guarded workload descendant proof — 2026-11-23 (T02 narrowly KERNEL_TESTED)

[GitHub Actions run 45292312207](https://github.com/rastogivaibhav/gavel-os/actions/runs/45292312207), commit `1f145a63b99e8ea70d5938505a474d87a016e67b` on [draft PR #11](https://github.com/rastogivaibhav/gavel-os/pull/11): all six CI jobs passed. The isolated privileged Linux kernel job ran both `TestKernelConnect4Denial` and `TestKernelGuardedAgentAndDescendants`. The new guarded workflow creates an empty child cgroup, attaches an eBPF cgroup/connect4 program with no PID allow-bypass path, launches an unprivileged agent atomically into it via `UseCgroupFD`, and verifies both agent and fork/exec child are in a `gavel-agent-*` cgroup. The test reports permitted `127.0.0.1` connection success and forbidden `127.0.0.2` connection denied with `EPERM/EACCES` in both processes. The child test requires an observable pass result, not merely launch success. The kernel version and full capability state should be recorded in a future evidence artifact.

**Exclusions:** The original legacy monitored-PID mode has *not* gained descendant inheritance. The guarded launcher does not yet withstand hostile supervisor `SIGKILL`/crash, privileged cgroup escape or eBPF removal. IPv6, UDP and file/exec restrictions remain unimplemented. A standard process-launched agent bypassing the guarded launcher is not automatically protected. Issue #4 remains open for these adversarial and integration gaps.

## M1 crash-retained kernel policy — 2026-11-24 (partial T13, isolated SIGKILL proof)

**Code:** [draft PR #11](https://github.com/rastogivaibhav/gavel-os/pull/11) introduces a root-owned mode-0700 bpffs pin directory `/sys/fs/bpf/gavel-agents`; the protected cgroup `connect4` BPF link **must be pinned before the agent is launched**, with no fallback to unpinnable legacy cgroup attachment. A trusted `gavel-enforcer recover <gavel-agent-N>` command kills the full cgroup and proves `populated 0` before unpinning. The normal supervisor cleanup follows the same empty-before-unpin order.

**Actual kernel proof:** [GitHub Actions run 45344226360](https://github.com/rastogivaibhav/gavel-os/actions/runs/45344226360), privileged `Kernel IPv4 Denial (ephemeral VM)` job, test `TestKernelSupervisorSIGKILLRetainsBPF`. A real unprivileged agent started in a pinned, dedicated cgroup and fork/execed a descendant. The descendant first received a kernel denial for forbidden IPv4 and an allowed IPv4 control succeeded; the host test killed its privileged supervisor via `SIGKILL`, checked the descendant remained alive and the BPF link remained pinned, and required the descendant to perform **another actual forbidden IPv4 connect**. That second syscall still returned `EPERM/EACCES`. Independent root recovery killed the orphan, verified empty cgroup and removed pinned link and cgroup. All three privileged tests passed: prior `TestKernelConnect4Denial`, `TestKernelGuardedAgentAndDescendants`, and this SIGKILL/recovery test.

**Limitations:** This is one explicitly scoped live adversarial test. It is not independent third-party validation. An agent started outside the guarded launcher is not automatically contained. Privileged attackers with host-root/cgroup/BPF access can still detach or bypass controls; IPv6, UDP, local sockets, inherited connected FDs and other OS actions remain unprotected. A permanently running trusted recovery service that automatically discovers abandoned pins/workloads after crash and boot is **not implemented**. Do not close T13 or claim full fail-closed/production safety based on this result.

## IPv6 cgroup/connect6 evidence — 2026-11-24 (T03 partial)

**Code:** [draft PR #12](https://github.com/rastogivaibhav/gavel-os/pull/12) adds a `cgroup/connect6` program with an exact 128-bit destination key; separate local `GAVEL_BLOCKED_IPV6` and control-plane `GAVEL_RUNTIME_BLOCKED_IPV6`/`blocked_ipv6` policy fields. Both IPv4/IPv6 BPF links must attach and (in guarded mode) be pinned before workload execution; failures reject startup and attempt rollback. Unprivileged agents do not inherit the supervisor's network-policy environment.

**Actual kernel proof:** [GitHub Actions run 45348118393](https://github.com/rastogivaibhav/gavel-os/actions/runs/45348118393), privileged Linux CI job, shows `TestKernelConnect6DenialForMonitoredPID` **PASS** (native IPv6 denial in original monitored-PID mode), `TestKernelGuardedIPv6AndDescendants` **PASS** (unprivileged agent and fork/exec child), and `TestKernelSupervisorSIGKILLRetainsBPF` **PASS** (surviving grandchild denied IPv4 **and IPv6** after supervisor SIGKILL, both pinned links cleaned after cgroup kill/emptiness check). The IPv6 test assigns only a local isolated IPv6 loopback alias `fd00:6761:7665:6c::2`, allows `::1`, and requires actual kernel `EPERM/EACCES` from forbidden connects. No external test destination or actual secrets are used.

**Still uncovered:** IPv6 UDP (`sendmsg6` and related operations), IPv4/IPv6 mapped dual-stack bypasses, raw/packet sockets, pre-established or passed file descriptors, route/tunnel/proxy bypasses, host-root cgroup/BPF tampering and automatic crash recovery. T03 does NOT meet its full IPv6 TCP+UDP acceptance gate. These must be separately tested with explicit negative and positive controls. This result is project-owned CI proof, not third-party verification.

## M2 native UDP destination enforcement (T03/T04, verification pending)

The UDP branch adds cgroup/sendmsg4 and cgroup/sendmsg6 to the same blocked-IP maps and both PID and guarded-cgroup identity modes. All four connect/sendmsg attachments are required; guarded execution requires all four pinned before launch. UDP sendmsg4 is deny-only: no proxy destination rewrite. Tests use direct Linux sendto and sendmsg syscalls to loopback-bound native IPv4/IPv6 UDP receivers, positive receipt and negative no-packet controls, legacy PID mode, guarded parent/child and repeated checks after supervisor SIGKILL. Recovery must remove all pins only after cgroup emptiness. No new kernel-tested status until privileged CI passes.

Scope: A0/A1 unprivileged workloads, native-family unconnected UDP only; IPv4-mapped IPv6, inherited/preconnected sockets, raw/packet sockets, other UDP paths, trusted helper/IPC bypass, privileged cgroup migration, host-root and independent verification remain open. Existing blocklist is not a default-deny policy. Connected UDP and IPv4 proxy semantics require separate validation.

## Native UDP and containment evidence update

Native unconnected UDP tests passed in [run 45434260219](https://github.com/rastogivaibhav/gavel-os/actions/runs/45434260219); PRs #12/#13 merged into master at f70a893a32bdc806eade825d7f80447215cb6ffd. T03/T04 KERNEL_TESTED for scoped native TCP and unconnected UDP only. [Run 45504587779](https://github.com/rastogivaibhav/gavel-os/actions/runs/45504587779) on draft PR #14 passed the guarded setuid syscall, positive-control setuid executable and root-owned sibling migration denial tests. Capability bounding and cgroup ownership gate now implemented on PR #14, pending privileged CI. T08/T09 remain open; neither namespace restrictions nor general kernel tamper resistance nor independent verification has been demonstrated.

## Seccomp containment extension (implemented, unverified)

PR #14 adds mandatory seccomp before untrusted exec, scoped namespace/syscall and alternate socket family restrictions. T08/T09 remain open until kernel tests and additional tamper probes are complete. No namespace-isolation, full network mediation or host-root protection claim.

## Filesystem and executable enforcement (T05–T07, implemented unverified)

Stacked Landlock branch introduces opt-in host-supplied JSON read/write/execute allowlists through GAVEL_AGENT_FS_POLICY. A configured policy requires ABI >=3 and supported setpriv, rejects invalid or unresolved rules, does not downgrade, and applies before untrusted exec. Native executable rights cannot overlap configured writable paths. Explicitly handles file read/write/truncate, directory enumeration, remove, create, refer and execute. CI positive control must show ordinary DAC permits access to synthetic fixtures; guarded parent and descendant must deny forbidden operations and permit approved read/write/exec, with post-test filesystem state checks. Filesystem policy is not active on legacy launches without the environment setting. Landlock does not restrict pre-opened descriptors, all metadata operations, interpreter semantics, trusted helper access, or host-root actions. Independent verification pending.

## Verification reconciliation — 2026-11-25
PR #14 run 45511474402 passed all six jobs, including scoped seccomp and delegated-cgroup tests; draft remains unmerged. PR #15 run 45511559775 passed five jobs but failed privileged filesystem positive control at /dev/null open, before forbidden file/exec assertions. Corrected probe streams and executable path; no additional policy rights granted. T05–T07 remain IMPLEMENTED_UNVERIFIED pending rerun.

## Filesystem verification and P0 descriptor gate

PR #15 corrected run [45587216225](https://github.com/rastogivaibhav/gavel-os/actions/runs/45587216225) passed all six jobs including guarded Landlock proof; T05–T07 KERNEL_TESTED for the documented opt-in scope. PR #14 and #15 still draft. P0.1 adds close-on-exec ambient FD handling and strict standard streams in guarded mode; new privileged tests verify synthetic inaccessible file/socket positive controls and absence of those resources in agent/descendants. IMPLEMENTED_UNVERIFIED until CI. See P0_RESOURCE_ISOLATION_GOAL.md for acceptance and remaining gates.

## P0 inherited resources and Unix IPC

PR #16: [run 45774704902](https://github.com/rastogivaibhav/gavel-os/actions/runs/45774704902) passed six jobs including guarded inherited descriptor isolation. T05–T07 scoped Landlock proof passed in [run 45587216225](https://github.com/rastogivaibhav/gavel-os/actions/runs/45587216225). PRs #14–#16 remain unmerged. P0.2 adds strict Unix socket creation restrictions, private stream pairs only, and pidfd_getfd denial. New tests require negative and positive local IPC controls and descendants. No new evidence claim until CI completes; does not close trusted helper or general descriptor transfer via other paths.

## P0.3 mapped address and connected UDP slice

PRs #14–#17 merged to master at 73043be9d052bb679b48b5db8cc2bddb2abefcf8, tree identical to tested #17 (run 45778120888). P0.2 external Unix pathname and abstract service denial and private stream pairs KERNEL_TESTED. P0.3 adds explicit IPv4-mapped checks to connect6/sendmsg6 and native/mapped TCP and UDP kernel controls including connected UDP and destination overrides. T03/T04 remain scoped, new proof pending. No claims of exhaustive network mediation or proxy equivalence.

## P0.4 helper identity slice

PR #18 [run 45906222748](https://github.com/rastogivaibhav/gavel-os/actions/runs/45906222748) passed six jobs including mapped and connected UDP receiver evidence. P0.4 adds exclusive UID lease and process credential admission checks, plus process_vm_readv seccomp denial. Tests require a same-UID external helper to prevent startup, concurrent lease refusal, release after helper exit, and positive guarded launch. Host must exclusively assign the UID; process scanning is not an atomic security boundary against concurrent external launch. No claim that all helper channels are closed. New CI pending.

## P0.4 system IPC slice

PR #19 [run 45907820954](https://github.com/rastogivaibhav/gavel-os/actions/runs/45907820954) passed all six jobs including exclusive UID/helper admission. PRs #18/#19 merged, master tree identical to #19. System V shared memory/message queues/semaphores and POSIX message queue syscalls now denied by guarded seccomp. Real fixture tests require unguarded positive controls, guarded parent and descendants receiving EPERM, unchanged host objects, and allowed private memory/pipes. New evidence pending. POSIX shared memory files and other filesystem/IPC/helper paths remain unresolved; no broad helper protection claim.

## P0.4 isolated filesystem profile

An explicit isolated filesystem profile requires a valid Landlock policy and rejects rules covering known host IPC and kernel pseudo-filesystem roots and their ancestors (including resolved symlinks). The legacy guarded launch remains opt-in for filesystem policy. Added isolated real fixture proof for file-backed shared memory and a named FIFO outside the allowlist, plus private workspace mmap and descendant controls. No kernel evidence yet; PR #20 System V/POSIX queue proof remains pending. Trusted mount layout and private workspace required; aliases, approved shared paths and network brokers are not closed.
