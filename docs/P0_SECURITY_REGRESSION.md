# P0.6 — continuous kernel security assurance

Status: IMPLEMENTED_UNVERIFIED until the new CI run completes. Independent reproduction is outstanding. Baseline master 56b17b2f751b66c03e6e24cef0ef204215b84a11: CI run [45974859656](https://github.com/rastogivaibhav/gavel-os/actions/runs/45974859656) passed five ordinary jobs but **skipped** privileged kernel proof. Historical PR #25 run 45912312145 reported successful kernel steps; that is not a master regression or an independent reproduction.

## Isolation and trust

Run only on a dedicated, authorized disposable Linux VM with cgroup v2, bpffs, supported eBPF/Landlock/seccomp features, Go matching enforcer/go.mod, Python 3, GNU timeout and passwordless sudo for the trusted test operator. Never run on a shared, production or personal host. Tests may manipulate local cgroups, BPF pins, identities, IPC and local network fixtures. Discard the VM after any run. GitHub CI uses hosted Ubuntu VMs, a read-only contents token, no persisted checkout credentials or privileged-job cache, no repository secrets, and only same-repository PRs or main/master pushes. Same-repository writers and workflow changes are trusted; this is not an authorization mechanism against malicious maintainers. Fork PRs cannot run the privileged job under this condition; their changes require trusted review before an authorized repository-branch run. Branch protection configuration is not asserted by this document.

## Reproduction

From a clean checkout of the exact commit under review, as a non-root trusted operator on the disposable VM:

```sh
git rev-parse HEAD
python3 scripts/kernel_regression.py --self-test
if ! mountpoint -q /sys/fs/bpf; then
  sudo mount -t bpf bpf /sys/fs/bpf
fi
findmnt -n -o FSTYPE --target /sys/fs/bpf
python3 scripts/kernel_regression.py --isolated-vm --evidence /tmp/gavel-evidence
```

Use a previously nonexistent evidence directory. The runner builds the test executable from the checkout and checks the exact inventory of 20 standalone kernel assertions and five subprocess entry points. New or missing TestKernel names require explicit classification. Each assertion gets an exact test selector, bounded duration and separate log. A zero exit without the named top-level run and pass, duplicate results, a skip or failed subtest does not satisfy the gate. Runner self-tests cover these conditions; failures stop the sequence and leave remaining cases marked not_run. Ordinary Go/Python/build/extension CI remains separate. The suite is the existing privileged assertion inventory, not an exhaustive syscall inventory.

## Evidence acceptance

Download kernel-security-evidence-<run>-<attempt> from the Actions run. Inspect results.json (commit/tree, PR head, kernel, cgroup and bpffs types, effective/bounding capabilities, Go version, binary digest, exact test names, durations, exit codes and log digests), inventory.txt, build.log and per-test logs. Require all 20 cases passed, no unclassified kernel tests, no not_run entries, and a successful privileged job. A setup failure or absent artifact is not evidence. Compare the checkout tree to the reviewed change and inspect the actual Go test assertions and logs for permitted/denied syscall and receiver controls, descendant behavior, crash persistence and fail-closed admission where applicable. The result and hashes are produced by trusted CI, not signed remote attestation. Logs need not include every policy digest unless emitted by the underlying test.

For independent reproduction, a separate reviewer must provision their own VM, repeat the above against the same commit, preserve their results and environment, inspect the assertions and record mismatches. Project-owned CI does not qualify as independent. A second successful run by this automation is not independent either.

## Scope and next gate

Existing P0 tests address scoped A0/A1 arbitrary unprivileged code under trusted supervisor/host assumptions. Helper application-layer semantics, trusted output sinks, private mounts and UID allocation remain deployment assumptions. Optional profiles must be explicitly enabled for their guarantees. A2/A3, host root, kernel exploits, comprehensive protocol mediation, and original issues #2–#8 are not closed. No enforcement mechanism is changed by P0.6. After successful CI, record the exact run/commit and review artifacts; obtain independent reproduction before deciding P0 closure. Keep original acceptance matrix open.

## M0 admission regression (issue #3, T13)

The original 18-case P0.6 baseline remains the deferred P0.7 reproduction target. This follow-on adds a nineteenth assertion for incomplete/invalid local and remote proxy configuration, synthetic HTTP 503 and degraded policy response. Each refusal must leave a payload marker absent; valid local launch must create it as the dedicated unprivileged UID. Malformed proxy settings must not be silently discarded even when a blocklist exists; valid proxy ports are 1–65535. This is launch admission only, not continuous control-plane availability, revocation or automatic crash recovery. Status IMPLEMENTED_UNVERIFIED until CI passes.

## T13 orphan recovery sweep (issue #3)

The twentieth assertion tests the opt-in trusted discovery sweep against a real supervisor crash, active and competing leases, a same-name foreign cgroup, post-crash network denial and idempotent cleanup. See [the recovery contract](GUARDED_ORPHAN_RECOVERY.md). Status IMPLEMENTED_UNVERIFIED. The frozen 18-test P0.7 baseline remains deferred.
