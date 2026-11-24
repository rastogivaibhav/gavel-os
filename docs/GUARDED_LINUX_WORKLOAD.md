# GavelOS guarded Linux workload (experimental, IPv4-only)

This feature provides a narrow, reproducible security property: **the agent cannot begin running before the Linux cgroup `connect4` hook is attached**, and children inherit the same cgroup-scoped network controls. Unlike the legacy monitored-PID mode, it does not rely on registering every child PID.

## Example: disposable isolated Linux VM only

Build the main enforcer (Go version from `enforcer/go.mod`):

```sh
cd enforcer
go build -o /tmp/gavel-enforcer .
```

Configure a dedicated *unprivileged* local account; UID 0 and GID 0 are refused. Example using the existing `nobody` account in a disposable VM:

```sh
sudo env \
  GAVEL_AGENT_UID=65534 GAVEL_AGENT_GID=65534 \
  GAVEL_BLOCKED_IPS=127.0.0.2 \
  /tmp/gavel-enforcer run /usr/bin/python3 /path/to/agent.py
```

The executable path must be absolute; the command is executed without a shell. `GAVEL_MACHINE_KEY` may be supplied for control-plane policy instead of a local blocklist. The control plane must report an online policy; stale/degraded policy is rejected. The child does **not** inherit the supervisor's machine key or policy configuration.

`GAVEL_CGROUP_PATH` optionally selects an existing cgroup-v2 **parent directory** with permission to create children. The runner creates its own `gavel-agent-*` child cgroup and fails rather than silently switching to the host root when the explicit parent path is invalid.

The parent process:

1. Validates kernel capabilities, cgroup v2 and an enforceable policy.
2. Creates a **new isolated child cgroup** containing no processes; requires a mounted bpffs at `/sys/fs/bpf` and a protected root-owned `/sys/fs/bpf/gavel-agents` directory (mode `0700`).
3. Loads and attaches the `connect4` program with `ProtectAll` enabled, **pins its modern BPF link in bpffs**, and refuses to launch the agent if pinning fails or only legacy non-pinnable attachment is supported.
4. Starts the unprivileged agent via Linux `CLONE_INTO_CGROUP` (Go `UseCgroupFD`), with **no fallback to fork-then-move** if the kernel rejects atomic assignment.
5. On normal termination, uses `cgroup.kill` to terminate descendants, waits until the group is unpopulated, then unpins BPF and removes the group. On supervisor `SIGKILL`, the pinned kernel restriction remains even if an orphaned grandchild is alive.

### Acceptance evidence

Opt-in isolated test:

```sh
cd enforcer
go test -c -o /tmp/gavel-kernel.test .
sudo env GAVEL_RUN_KERNEL_TESTS=1 /tmp/gavel-kernel.test \
  -test.run '^TestKernelGuardedAgentAndDescendants$' -test.v -test.timeout=55s
```

The test checks both the unprivileged parent **and a fork/exec child**: permitted `127.0.0.1` TCP connect succeeds and prohibited `127.0.0.2` connect is rejected by the kernel. It additionally verifies both processes are in a `gavel-agent-*` cgroup. The protected agent test process runs as UID/GID 65534.

The PR's privileged GitHub Actions proof job runs this exact test. It must **PASS in a real Linux runner** before `KERNEL_TESTED` is claimed; Go unit tests alone are insufficient.

## Crash-resistant enforcement and trusted recovery

On supported kernels, the guarded launcher requires a **pinned** cgroup BPF link before agent execution, rather than relying on a process-owned file descriptor. An unexpected supervisor `SIGKILL` does not automatically detach the pinned kernel hook. An orphaned, unprivileged agent descendant remains constrained by the IPv4 `connect4` policy until a trusted recovery process stops the entire cgroup.

**Requirement:** `/sys/fs/bpf` must already be mounted as bpffs before starting the launcher. A disposable Linux test VM can use `sudo mount -t bpf bpf /sys/fs/bpf` if necessary. Do not auto-mount bpffs on production hosts via an AI agent.

When the GavelOS supervisor dies, a privileged host operator or a separately supervised trusted recovery service can run:

```sh
sudo /usr/local/bin/gavel-enforcer recover gavel-agent-123456
```

Replace the identifier with the **actual generated protected cgroup basename**, visible in `/sys/fs/cgroup` or the supervisor's audited startup logs. The command validates the name, signals `cgroup.kill`, confirms `cgroup.events` reports `populated 0`, loads/unpins the BPF link, and removes the empty cgroup. It **does not** unpin the security link if it cannot establish that the protected workload has stopped.

Use the same `GAVEL_CGROUP_PATH` parent for launch and recovery when a nondefault cgroup-v2 parent was configured. Do not grant the agent access to the bpffs pin directory or cgroup controllers.

### Live SIGKILL test

On the isolated, restricted GitHub Actions runner (or your own disposable Linux VM) run:

```sh
sudo env GAVEL_RUN_KERNEL_TESTS=1 /tmp/gavel-kernel.test \
  -test.run TestKernelSupervisorSIGKILLRetainsBPF -test.v -test.timeout=80s
```

The test launches an unprivileged agent with a fork/exec grandchild, proves pre-crash kernel denial, SIGKILLs the trusted supervisor, and requires the surviving grandchild to receive a **second actual kernel EPERM/EACCES**. Then independent root recovery must kill the protected cgroup and remove the pin/cgroup with no remnants. A green unit test without the privileged job is not sufficient evidence.

## Threat model and known exclusions

- **Network scope only:** `cgroup/connect4` IPv4 TCP connect; no protection yet for IPv6, UDP, inherited connected sockets, AF_UNIX, filesystem, exec policies, kernel operations or semantic misuse of an approved endpoint.
- **Protection survives supervisor SIGKILL only with a supported pinned link:** It is still not safe against arbitrary privileged root who can remove pins, change cgroup membership or manipulate BPF. A complete independent always-on recovery/watchdog service, crash-loop handling and anti-escape cgroup ownership policy remain future work.
- **Agent is assumed nonroot:** Launched agents are forced to specified nonzero UID/GID and must not have the privileges required to modify protected cgroups or eBPF links.
- **No complete sandbox:** These controls do not supply filesystem isolation, separate network namespaces, seccomp enforcement or a general agent privilege boundary.
- **Recovery must be verified:** If `cgroup.kill` or empty-group verification fails, leave the pinned policy attached and report a security-critical error. Do not unpin while active tasks remain.

**Engineering status:** KERNEL_TESTED for the narrowly scoped unprivileged IPv4 supervisor-`SIGKILL` scenario in [CI run 45344226360](https://github.com/rastogivaibhav/gavel-os/actions/runs/45344226360). This does not imply production readiness, automatic recovery, or tamper-proof enforcement.

## Next hardening work

1. Independently supervise recovery on host crash/restart; verify the BPF pin and protected cgroup are discoverable after supervisor termination and failures cannot orphan workloads forever.
2. Add cgroup-owned and verifiable workload admission, preventing agents from escaping the cgroup via writable cgroup controllers.
3. Cover IPv6 and UDP and test namespace/cgroup escape attempts.
4. Verify proper credential/capability dropping and protected policy identities.
