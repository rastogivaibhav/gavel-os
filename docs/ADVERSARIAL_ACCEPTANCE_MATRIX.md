# GavelOS — Adversarial OS-operation acceptance matrix

**Baseline date:** 2026-11-23. Status is evidence-gated. One explicitly scoped kernel proof (T01/T10) passed in [GitHub Actions run 45285372144](https://github.com/rastogivaibhav/gavel-os/actions/runs/45285372144); all other tests remain unproven unless separately recorded.

**State vocabulary:** NOT_IMPLEMENTED / IMPLEMENTED_UNVERIFIED / KERNEL_TESTED / ADVERSARIAL_TESTED / INDEPENDENTLY_VERIFIED. `PASS` requires evidence (kernel status, test log, version/ref). `DENY` in a control-plane log without blocked OS action is not PASS.

| ID | Unauthorized action by agent | Required OS mediation | Baseline GavelOS state | Target proof |
|---|---|---|---|---|
| T01 | Outbound TCP IPv4 to denied IP | cgroup/connect4 | KERNEL_TESTED; run 45285372144 (one test PID; startup failure handling still unverified) | Kernel returns refusal, independent of middleware |
| T02 | Same operation from fork/exec child | Cgroup identity inheritance | KERNEL_TESTED for dedicated guarded cgroup; run 45292312207 (legacy PID mode still bypassable) | Child denied after replacing executable |
| T03 | IPv6 outbound | connect6/sendmsg6 | NOT_IMPLEMENTED | Denied IPv6 TCP and UDP; positive permitted control |
| T04 | UDP `sendto` to denied IP | sendmsg4/sendmsg6 | NOT_IMPLEMENTED | Denied datagram; no unintended packets |
| T05 | Unauthorized executable | BPF LSM bprm_check_security or equivalent | NOT_IMPLEMENTED | Kernel denies exec and records errno |
| T06 | Read secret/credential file | BPF LSM file_open or equivalent | NOT_IMPLEMENTED | Read denied including helper subprocess |
| T07 | Modify protected OS/config file | Appropriate file/rename/truncate hooks | NOT_IMPLEMENTED | Write, rename, truncation denied |
| T08 | Attempt eBPF program injection | bpf syscall/LSM gate, explicit capabilities | NOT_IMPLEMENTED | Unauthorized BPF load denied under declared tier |
| T09 | Tamper with maps, links or enforcer | integrity/privilege boundary | NOT_IMPLEMENTED | Agent unable to disable protection under declared tier |
| T10 | Agent bypasses SDK and invokes socket directly | same kernel network hook | KERNEL_TESTED; direct test-process TCP connect without middleware, run 45285372144 | Kernel denial still enforced |
| T11 | Semantic unauthorized API operation over allowed TLS connection | separate trusted gateway/API authorization | NOT UNIVERSALLY ENFORCED | Gateway blocks specific action; not attributed to kernel hook |
| T12 | Windows denied destination | Native WFP Windows Firewall rules | IMPLEMENTED_UNVERIFIED; scope may be host-wide | OS firewall denies; no userspace-only fallback |
| T13 | Control-plane outage and policy failure | local cached known-good controls / fail closed | PARTIAL in PR #9: enforce-required fail-stop before startup; live agent quarantine NOT IMPLEMENTED | Cannot enter "protected" state with unprotected actions |
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
