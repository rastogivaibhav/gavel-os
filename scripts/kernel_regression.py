#!/usr/bin/env python3
"""Run the guarded kernel proof suite ONLY on a disposable, authorized Linux VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
# Individually bounded to preserve the established CI timeouts.
CASES = {
    "TestKernelConnect4Denial": 40,
    "TestKernelGuardedAgentAndDescendants": 55,
    "TestKernelConnect6DenialForMonitoredPID": 60,
    "TestKernelGuardedIPv6AndDescendants": 70,
    "TestKernelSupervisorSIGKILLRetainsBPF": 80,
    "TestKernelGuardedContainment": 55,
    "TestKernelGuardedRejectsDelegatedCgroup": 55,
    "TestKernelGuardedFilesystem": 55,
    "TestKernelGuardedDescriptors": 55,
    "TestKernelGuardedUnixIPC": 55,
    "TestKernelGuardedNetworkMediation": 70,
    "TestKernelGuardedHelperIdentity": 55,
    "TestKernelGuardedSystemIPC": 55,
    "TestKernelGuardedFileIPCProfile": 55,
    "TestKernelGuardedTCPServiceProfile": 55,
    "TestKernelGuardedPolicyIntegrity": 55,
    "TestKernelGuardedLifecycleLease": 25,
    "TestKernelGuardedPolicyProvenance": 55,
    "TestKernelGuardedStrictPolicyAdmission": 65,
}
# Subprocess entry points, not standalone assertions. Their parent tests invoke them.
HELPERS = {
    "TestKernelConnect4Probe", "TestKernelConnect6Probe",
    "TestKernelGuardedChildProbe", "TestKernelGuardedAgentProbe",
    "TestKernelGuardedContainmentProbe",
}


def command(argv, cwd=ROOT):
    return subprocess.check_output(argv, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_inventory(listing):
    discovered = set(re.findall(r"^TestKernel\w+$", listing, re.M))
    expected = set(CASES) | HELPERS
    if discovered != expected:
        raise RuntimeError(f"kernel inventory drift: missing={sorted(expected-discovered)}, "
                           f"unclassified={sorted(discovered-expected)}")


def verdict(name, code, output):
    # Go's top-level result starts at column zero. Child probe output cannot
    # substitute for the named parent assertion. Require exactly one run/pass.
    escaped = re.escape(name)
    runs = re.findall(r"^=== RUN\s+" + escaped + r"\s*$", output, re.M)
    passes = re.findall(r"^--- PASS: " + escaped + r" \([^\n]*\)$", output, re.M)
    skipped = re.search(r"^\s*--- (?:SKIP|FAIL): " + escaped + r"(?:/[^ \n]+)?(?: |\n|$)", output, re.M)
    return code == 0 and len(runs) == 1 and len(passes) == 1 and not skipped


def self_test():
    name = "TestKernelExample"
    good = f"=== RUN   {name}\n--- PASS: {name} (0.01s)\nPASS\n"
    samples = [(0, good, True), (1, good, False), (0, "PASS\n", False),
               (0, f"=== RUN   {name}\n--- SKIP: {name} (0.00s)\nPASS\n", False),
               (0, good + f"    --- SKIP: {name}/child (0.00s)\n", False),
               (0, good.replace(name, name+"Probe"), False),
               (0, good+good, False)]
    for code, output, expected in samples:
        if bool(verdict(name, code, output)) != expected:
            raise RuntimeError("verdict self-test failed")
    listing = "\n".join(sorted(set(CASES) | HELPERS))
    validate_inventory(listing)
    for invalid in (listing + "\nTestKernelUnclassified", listing.replace(next(iter(CASES)), "")):
        try:
            validate_inventory(invalid)
        except RuntimeError:
            continue
        raise RuntimeError("inventory self-test failed")
    print("Runner self-tests passed: success, failure, skip, missing, duplicate, helper and inventory drift")


def execute(evidence):
    evidence.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "scope": "project-owned A0/A1 scoped kernel regression; trusted host",
              "status": "incomplete", "cases": [
                  {"name": name, "status": "not_run", "timeout_seconds": seconds}
                  for name, seconds in CASES.items()]}
    def save():
        (evidence / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    try:
        report["commit"] = command(["git", "rev-parse", "HEAD"])
        report["tree"] = command(["git", "rev-parse", "HEAD^{tree}"])
        if command(["git", "status", "--porcelain", "--untracked-files=no"]):
            raise RuntimeError("tracked working tree is dirty")
        report["ci"] = {k: os.environ.get(k) for k in
                        ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_EVENT_NAME",
                         "GITHUB_SHA", "GITHUB_REF", "GAVEL_CI_HEAD_SHA", "RUNNER_OS", "ImageOS", "ImageVersion")}
        report["environment"] = {
            "kernel": command(["uname", "-a"]),
            "go": command(["go", "version"]),
            "cgroup_fs": command(["stat", "-fc", "%T", "/sys/fs/cgroup"]),
            "bpffs": command(["findmnt", "-n", "-o", "FSTYPE", "--target", "/sys/fs/bpf"]),
            "privileged_caps": command(["sudo", "-n", "sh", "-c",
                                       "grep -E '^(CapEff|CapBnd):' /proc/self/status"]),
            "os_release": Path("/etc/os-release").read_text(),
        }
        if report["environment"]["cgroup_fs"] != "cgroup2fs" or report["environment"]["bpffs"] != "bpf":
            raise RuntimeError("requires cgroup v2 and mounted bpffs")
        save()
        with tempfile.TemporaryDirectory(prefix="gavel-kernel-") as tmp:
            Path(tmp).chmod(0o755)  # unprivileged descendant probes must execute binary
            binary = Path(tmp) / "gavel-kernel.test"
            build = subprocess.run(["go", "test", "-c", "-o", str(binary), "."],
                                   cwd=ROOT / "enforcer", stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, timeout=300)
            (evidence / "build.log").write_text(build.stdout)
            if build.returncode:
                raise RuntimeError("kernel test compilation failed")
            binary.chmod(0o755)
            report["binary_sha256"] = digest(binary)
            listing = command([str(binary), "-test.list", "^TestKernel"])
            (evidence / "inventory.txt").write_text(listing + "\n")
            validate_inventory(listing)
            save()
            for case in report["cases"]:
                name, seconds = case["name"], case["timeout_seconds"]
                print(f"Running {name}", flush=True)
                start = time.monotonic()
                argv = [
                    "sudo", "-n", "env", "GAVEL_RUN_KERNEL_TESTS=1", "timeout",
                     "--kill-after=5s", f"{seconds+5}s", str(binary),
                     "-test.run", "^"+name+"$", "-test.v", f"-test.timeout={seconds}s"]
                try:
                    proc = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True, errors="replace",
                                          timeout=seconds+20)
                    code, output = proc.returncode, proc.stdout
                except subprocess.TimeoutExpired as exc:
                    code = 124
                    output = exc.stdout or b""
                    if isinstance(output, bytes):
                        output = output.decode("utf-8", errors="replace")
                    output += "\nOuter runner timeout; VM must be discarded.\n"
                log = evidence / (name + ".log")
                log.write_text(output)
                case.update(exit_code=code, duration_seconds=round(time.monotonic()-start, 3),
                            log=log.name, log_sha256=digest(log),
                            status="passed" if verdict(name, code, output) else "failed")
                print(output, flush=True)
                save()
                if case["status"] != "passed":
                    # A failing test may have left privileged state behind.
                    raise RuntimeError(f"{name}: failed, skipped or absent assertion; stop on first failure")
        report["status"] = "passed"
        save()
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
        save()
        print(str(exc), file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--isolated-vm", action="store_true", help="confirm authorized disposable VM")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return 0
    if not args.isolated_vm or not args.evidence or sys.platform != "linux" or os.geteuid() == 0:
        parser.error("requires explicit isolated VM acknowledgement, new evidence directory and non-root Linux caller")
    return execute(args.evidence.resolve())


if __name__ == "__main__":
    sys.exit(main())
