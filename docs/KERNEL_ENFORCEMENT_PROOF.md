# Linux T01/T10 kernel-enforcement proof runbook

This procedure tests **an actual kernel-level denial**, not GavelOS's broader agent-security claims. It is opt-in; a passing result is not production readiness.

## Prerequisites

- Use a **disposable Linux VM**. Never use a production machine, sensitive developer workstation or shared CI controller.
- amd64/arm64 Linux with cgroup v2 and eBPF cgroup hooks, and a writable `/sys/fs/cgroup`.
- Sufficient BPF and cgroup privileges (CAP_BPF or CAP_SYS_ADMIN, plus any kernel-required capabilities).
- Go toolchain matching `enforcer/go.mod` and its dependencies.
- Test traffic uses loopback only: no external network required.

## Run

Build the test executable from an approved GavelOS security branch:

```bash
cd enforcer
go test -c -o /tmp/gavel-kernel.test .
```

On an isolated disposable VM, run:

```bash
sudo env GAVEL_RUN_KERNEL_TESTS=1 /tmp/gavel-kernel.test \
  -test.run '^TestKernelConnect4Denial$' -test.v -test.timeout=45s
```

The test creates an isolated `/sys/fs/cgroup/gavel-test-*` child cgroup and a test-only helper process. It enrolls the helper in that cgroup before connecting, attaches the `cgroup/connect4` BPF hook **only to the newly created child cgroup**, and attempts two connections. The permitted destination (`127.0.0.1`) must connect; the denied destination (`127.0.0.2`) must fail with `EPERM` or `EACCES`. The forbidden test listener must not receive a connection.

The test does not attach to the parent or root cgroup and does not change host firewall rules. Cleanup removes its BPF link and child cgroup. A crash could leave an empty child cgroup; manually remove only a proven test-created empty `gavel-test-*` cgroup after checking for attached programs/processes.

## Acceptance rules

- **PASS:** both allowed and denied checks succeed, actual kernel socket operation returns refusal for the denied destination, the test exits successfully, and the test environment demonstrably has eBPF support.
- **FAIL:** BPF load/attach fails, a forbidden connect succeeds, or an allowed connection is denied.
- **BLOCKED:** host lacks writable cgroups or necessary kernel/BPF capabilities.
- **UNVERIFIED:** ordinary Go/CI tests pass without the privileged test being executed.

Collect commit SHA, Go and kernel versions, cgroup mount status, capabilities, test stdout/stderr, verifier errors if any, and the known security limitations. Add outcome and evidence to `docs/ADVERSARIAL_ACCEPTANCE_MATRIX.md`.

## Explicit exclusions

This test does **not** prove child-process inheritance, IPv6, UDP, read/write or exec denial, protection against root, control-plane outage safety, or resistance to BPF removal. These remain separately tracked milestones.
