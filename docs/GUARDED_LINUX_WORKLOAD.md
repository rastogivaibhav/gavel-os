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
2. Creates a **new isolated child cgroup** containing no processes.
3. Loads and attaches the `connect4` program to that child cgroup with `ProtectAll` enabled.
4. Starts the unprivileged agent via Linux `CLONE_INTO_CGROUP` (Go `UseCgroupFD`), with **no fallback to fork-then-move** if the kernel rejects atomic assignment.
5. On normal termination, uses `cgroup.kill` to terminate descendants, waits until the group is unpopulated, then detaches BPF and removes the group.

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

## Threat model and known exclusions

- **Network scope only:** `cgroup/connect4` IPv4 TCP connect. The current implementation **does not** block IPv6, UDP, preexisting socket descriptors, AF_UNIX, filesystem access, exec, kernel operations or semantic abuse of an allowed TLS endpoint.
- **No survival of hostile supervisor termination:** eBPF link ownership remains in the supervisor process; SIGKILL, crash, or a privileged attacker unloading the link could leave other descendants running without its policy. `Pdeathsig` kills only the direct child, not arbitrary grandchildren. A pinned/protected kernel link, systemd binding or out-of-process watchdog and proof of crash containment is necessary before claiming fail-closed operation if the supervisor is killed.
- **Agent is assumed nonroot:** The launched agent is forced to a designated UID/GID; it must not have privileges to write cgroups or eBPF state. No guarantee against root escalation or a kernel exploit.
- **Operational failure:** If `cgroup.kill` or empty-group verification fails, the runner reports a security-critical error. **Do not assume that error by itself preserves enforcement after supervisor process exit.** Treat it as a blocker to safe production use.
- **No general workload sandbox:** The environment is not a full process namespace, filesystem or seccomp sandbox. Network policy is not a substitute for container isolation.

**Engineering status:** prototype targeting M1 and T02 of `docs/ADVERSARIAL_ACCEPTANCE_MATRIX.md`. This is not production-ready until test evidence and failure-mode hardening are completed.

## Next hardening work

1. Pin or otherwise independently own enforcement links so the policy remains attached after supervisor failure, and make link cleanup possible only after cgroup emptiness is verified.
2. Add cgroup-owned and verifiable workload admission, preventing agents from escaping the cgroup via writable cgroup controllers.
3. Cover IPv6 and UDP and test namespace/cgroup escape attempts.
4. Verify proper credential/capability dropping and protected policy identities.
