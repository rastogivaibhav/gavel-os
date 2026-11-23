# GavelOS — Agent-to-OS Security Boundary Engineering Programme

**Version:** 0.1 (2026-11-23) · **Status:** proposed, security-review required · **Primary platform:** Linux · **Default branch:** `master`

## Mission

Protect operating-system and kernel-mediated resources from unauthorized activity originating in autonomous AI agents, including adversarial or compromised agents. The security mechanism must enforce policy outside the agent's trust boundary. Agent governance is the control mechanism for this boundary, not a substitute for enforcement.

**Security invariant:** For each explicitly protected operation, an untrusted agent and its descendants cannot perform that operation unless independently authorized by the OS enforcement layer. Missing policy, failed attachment, stale identity, loss of control-plane connectivity and failed integrity checks must not silently result in unprotected execution.

This is a target invariant **to prove incrementally**, not a present guarantee. GavelOS does not claim to protect a kernel already compromised by arbitrary kernel code execution.

## Ground truth at programme start (2026-11-23)

- Linux: Go/cilium-ebpf runtime-generated `cgroup/connect4` program; monitored PID and blocked IPv4 maps; optional redirect. Current code's `ebpfProgramStatus() == "runtime-generated"` conflicts with an `"available"`-only readiness check. A fix requires CI and an actual kernel attachment test before claiming enforcement.
- Windows: ETW/WMI process and traffic observation; Windows Firewall/WFP-backed outbound rules generated via PowerShell. Some failure paths fall back to userspace recording. Rules are not proven per-agent and coverage must be measured.
- macOS: audit-only, not enforcement.
- Control plane: machine-key-authenticated runtime policy fetch, OPA/Rego, structured tool verdicts, escalations, chained audit ledger. Semantic tool verdicts are not universally bound to kernel operations.
- Known security limitations: IPv6 on Linux unsupported; descendants not automatically inherited in PID map; kernel-side process/exec/file protections absent; privileged runtime tamper resistance and TPM attestation absent; startup can degrade to audit-only. Repository tests do not prove kernel attachment or adversarial resilience.

## Threat model and boundaries

| Attacker tier | Description | Goal |
|---|---|---|
| A0 | Prompt-injected agent using permitted tool calls | Block unauthorized actions without trusting middleware |
| A1 | Agent with arbitrary user-level code execution | Survive bypass of SDK, direct syscalls, child processes and alternate languages |
| A2 | Agent in container/sandbox with limited extra capabilities | Survive namespace and cgroup boundary manipulation, subject to explicit assumptions |
| A3 | Agent with host-root or substantial Linux capabilities | Protect enforcement state under a hardened, explicitly specified host configuration |
| A4 | Agent with arbitrary kernel-code execution/physical boot control | Explicitly **out of scope** without additional trusted boot/hardware controls |

**Protected resources:** outbound communication, executable launch, selected files and secrets, privilege-sensitive and kernel-management operations, access to runtime policy/enforcer state. **Non-goal:** parsing prompt intent inside the kernel or guaranteeing that an approved HTTPS destination is safe; semantic tool/API authorization must be separately enforced at a trusted gateway.

### Six non-negotiable properties

1. **Identity:** durable agent/workload identity; descendant coverage without PID races.
2. **Complete mediation:** each in-scope OS operation has an identified enforcement hook and negative test.
3. **Least privilege:** default-deny for protected workloads; explicit allow rules and escape-safe exception handling.
4. **Integrity:** agent cannot tamper with policy, enforcer, hooks, maps or audit evidence within declared attacker tier.
5. **Availability semantics:** fail closed *for protected actions*; policy/attach errors become visible terminal errors or preserved known-good enforcement, never quiet audit-only.
6. **Evidence:** produce reproducible denial proof (kernel return/errno and attempted operation), with immutable or remotely anchored receipt and versioned policy identity. A `DENY` log alone is not proof of prevention.

## Milestones (gated; no date promises)

### M0 — Truthful boot and first reproducible denial (P0)

- [ ] Correct Linux readiness mismatch; unit test readiness-state logic.
- [ ] Add a privileged, isolated Linux integration test that loads and attaches `connect4` and verifies forbidden IPv4 connect fails while permitted connect succeeds. Include kernel version, cgroup path, capabilities and skip reason.
- [ ] Make startup errors explicit: no security-ready health status when policy is missing or eBPF cannot attach; separate operator-selected audit-only from unexpected degradation.
- [ ] Compare runtime and docs; correct any blanket "fail-closed" wording unsupported by code.
- [ ] CI: Go tests and static checks green; privileged test job added using an appropriate runner and safe isolated environment.
**Exit gate:** reproducible proof of kernel denial + a negative failure-mode test; reported runtime mode equals actual mode.

### M1 — Agent identity and process inheritance (P0)

- [ ] Model protected agents as workload/cgroup identities, not only numeric PIDs; document lifecycle and reuse semantics.
- [ ] Enforce policy for child processes, `exec`, forks and agent-created subprocesses.
- [ ] Negative cases: new child, detached process, PID reuse, namespace changes, agent framework swapped, SDK removed.
- [ ] Bind policy to kernel-visible identity; reject unverifiable user-supplied agent IDs.
**Exit gate:** all protected descendants denied independent of agent framework.

### M2 — Network mediation completeness (P1)

- [ ] IPv4/IPv6 and TCP/UDP coverage; classify raw/packet sockets and local IPC with explicit policy.
- [ ] Prevent routes using alternate destination families/proxies/DNS, within documented limits; avoid relying solely on domain-name lookups.
- [ ] Add tests for direct connect, sendmsg/sendto, IPv6, UDP, metadata endpoints and allowed destination.
- [ ] Clarify global Windows Firewall rules versus per-process authorization; test native enforcement/no silent userspace fallback.
**Exit gate:** all listed in-scope network operations blocked when prohibited; exceptions documented.

### M3 — File, exec and kernel-management mediation (P1)

- [ ] Evaluate BPF LSM or equivalent kernel mechanisms for exec, file open/write/create/rename, ptrace, mount, kernel modules and BPF loading.
- [ ] Enforce deny of credential-file reads and selected writes by workload/identity, not just filename heuristics.
- [ ] Enumerate hook bypasses: inherited or passed descriptors, mmap, file replacement, mount namespaces, privileged helpers.
- [ ] Keep mechanisms modular; benchmark overhead and verifier constraints.
**Exit gate:** deny/allow and bypass tests with kernel-level evidence for each declared protected operation.

### M4 — Enforcement integrity and audit assurance (P1)

- [ ] Attack testing: stop agent daemon, unload eBPF, alter maps, modify policy, compromise API credentials, force control-plane outage.
- [ ] Harden with Linux security features and appropriately signed artefacts; assess TPM/secure boot/integrity measurement and options such as Shirudo-style signed upatches.
- [ ] Bind signed/hashed policy version to deployed enforcement; remotely anchor receipts, distinguish attempted from completed actions.
- [ ] Establish root-level adversary assumptions, including any special kernel, Secure Boot and hardware requirements.
**Exit gate:** independent adversarial red-team suite against documented A0–A3 tiers; no unsupported "tamper-proof" or "kernel safe" claims.

### M5 — Enterprise and independent reproducibility (P2)

- [ ] Multi-tenant policy, expiry/revocation and agent lifecycle; minimal control-plane privilege; workload enrollment and cleanup.
- [ ] Signed release images, dependency/SBOM scanning, CI provenance, upgrade/rollback and explicit operational failure modes.
- [ ] Independent reviewer reproduces all in-scope denials and attempts bypasses.
- [ ] Publish a concise security paper with code, benchmarks, threat assumptions, bypasses discovered and remediated.
**Exit gate:** independent evidence pack and release candidate; production classification only after security review.

## Operating method

- Treat `docs/ADVERSARIAL_ACCEPTANCE_MATRIX.md` as the source of truth for each operation, hook, status, limitations and evidence.
- Open issues for milestones; implement one vertical slice per branch and pull request. No direct security-code changes to `master`; review and CI required before merge.
- Every PR must state: intended boundary; adversary tier; threat prevented; coverage; tests run; limitations; rollback path.
- A passing unit test does not imply kernel enforcement. Mark `design`, `implemented`, `tested on isolated kernel`, and `independently validated` separately.
- Prioritize correctness of Linux baseline first, then widen platforms. Windows/macOS claims require independent OS-specific tests.
- Continue programme while relevant goals remain unmet. Scheduled reviews may prepare new issues/PRs when permissions allow but must report blockers honestly; they cannot self-certify a finished security product.

## Completion definition

The programme has reached its initial goal only when an independent reviewer can reproduce a specified protection matrix on a supported platform, including bypass of application middleware, untrusted child processes and attempts to tamper with enforcement, with recorded real kernel denials and known limitations. No general claim of kernel compromise prevention or absolute non-bypassability is permitted.
