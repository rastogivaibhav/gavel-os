//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGuardedAgentIdentityRequiresExplicitUnprivilegedUser(t *testing.T) {
	t.Setenv("GAVEL_AGENT_UID", "")
	t.Setenv("GAVEL_AGENT_GID", "")
	if _, _, err := guardedUnprivilegedIdentity(); err == nil {
		t.Fatal("missing unprivileged identity must be rejected")
	}
	t.Setenv("GAVEL_AGENT_UID", "0")
	t.Setenv("GAVEL_AGENT_GID", "0")
	if _, _, err := guardedUnprivilegedIdentity(); err == nil {
		t.Fatal("root workload must be rejected")
	}
	t.Setenv("GAVEL_AGENT_UID", "65534")
	t.Setenv("GAVEL_AGENT_GID", "65534")
	uid, gid, err := guardedUnprivilegedIdentity()
	if err != nil || uid != 65534 || gid != 65534 {
		t.Fatalf("invalid unprivileged identity: %d %d %v", uid, gid, err)
	}
}

func TestGuardedAgentRemovesSupervisorSecrets(t *testing.T) {
	out := guardedWorkloadEnvironment([]string{
		"GAVEL_MACHINE_KEY=never-expose", "GAVEL_AGENT_UID=65534",
		"GAVEL_AGENT_GID=65534", "GAVEL_BLOCKED_IPS=127.0.0.2",
		"GAVEL_ENGINE_URL=http://localhost:8000",
		"GAVEL_CGROUP_PATH=/sys/fs/cgroup", "GAVEL_PROXY_IPV4=127.0.0.1",
		"PATH=/usr/bin", "GAVEL_GUARD_TEST_SENTINEL=ok",
	})
	for _, v := range out {
		if strings.HasPrefix(v, "GAVEL_MACHINE_KEY=") ||
			strings.HasPrefix(v, "GAVEL_AGENT_") ||
			strings.HasPrefix(v, "GAVEL_BLOCKED_IPS=") ||
			strings.HasPrefix(v, "GAVEL_ENGINE_URL=") ||
			strings.HasPrefix(v, "GAVEL_CGROUP_PATH=") ||
			strings.HasPrefix(v, "GAVEL_PROXY_") {
			t.Fatalf("supervisor configuration leaked into child: %s", v)
		}
	}
	if len(out) != 2 {
		t.Fatalf("wrong sanitized environment: %v", out)
	}
}

func TestGuardedCgroupPolicyDoesNotNeedHostPIDList(t *testing.T) {
	blocked, err := parseIPv4("127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	config := LinuxEnforcerConfig{ProtectAll: true, BlockedIPv4: []uint32{blocked}}
	if !linuxPolicyConfigured(config) {
		t.Fatal("dedicated cgroup must be enforceable without monitored PID entries")
	}
	if linuxPolicyConfigured(LinuxEnforcerConfig{ProtectAll: true}) {
		t.Fatal("no-op protected cgroup policy must be rejected")
	}
	if _, err := attachEnforcer("/sys/fs/cgroup", config); err == nil {
		t.Fatal("all-process enforcement on host root cgroup must be forbidden")
	}
}

func guardedDial(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("test workload unexpectedly runs with root privileges")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		t.Fatalf("SECURITY FAILURE: inherited supplementary groups: %v (%v)", groups, err)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil { t.Fatal(err) }
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok { fields[key] = strings.TrimSpace(value) }
	}
	if fields["NoNewPrivs"] != "1" {
		t.Fatal("SECURITY FAILURE: no_new_privs not active")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if fields[key] != "0000000000000000" {
			t.Fatalf("SECURITY FAILURE: %s=%q", key, fields[key])
		}
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err != nil || !strings.Contains(string(data), "gavel-agent-") {
		t.Fatalf("workload not inside isolated protected cgroup: %q %v", string(data), err)
	}
	allowed, err := net.DialTimeout("tcp4", os.Getenv("GAVEL_GUARD_ALLOWED_ADDR"), time.Second)
	if err != nil {
		t.Fatalf("allowed network connection failed: %v", err)
	}
	_ = allowed.Close()

	forbidden, err := net.DialTimeout("tcp4", os.Getenv("GAVEL_GUARD_DENIED_ADDR"), time.Second)
	if forbidden != nil {
		_ = forbidden.Close()
		t.Fatal("security violation: prohibited connection succeeded")
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("denial did not return kernel EPERM/EACCES: %v", err)
	}
	checkGuardedIPv6(t)
	checkUDPProof(t)
}

func TestKernelGuardedChildProbe(t *testing.T) {
	if os.Getenv("GAVEL_GUARD_CHILD_HELPER") != "1" {
		t.Skip("guarded child process probe")
	}
	guardedDial(t)
}

func TestKernelGuardedAgentProbe(t *testing.T) {
	if os.Getenv("GAVEL_GUARD_AGENT_HELPER") != "1" {
		t.Skip("guarded main process probe")
	}
	guardedDial(t)
	// Fork+exec an entirely new executable process; it must inherit protection.
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelGuardedChildProbe$", "-test.v")
	cmd.Env = append(os.Environ(), "GAVEL_GUARD_CHILD_HELPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fork/exec descendant escaped or failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "PASS: TestKernelGuardedChildProbe") {
		t.Fatalf("descendant proof did not run: %s", output)
	}
}

// An isolated kernel test executed only by the restricted, privileged
// same-repository GitHub Actions job, or a disposable Linux VM.
func TestKernelGuardedAgentAndDescendants(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" {
		t.Skip("requires opt-in isolated privileged Linux VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root to manage dedicated cgroup and attach BPF")
	}
	allowed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	denied, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()

	t.Setenv("GAVEL_MACHINE_KEY", "")
	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID", "65534")
	t.Setenv("GAVEL_AGENT_GID", "65534")
	t.Setenv("GAVEL_GUARD_AGENT_HELPER", "1")
	t.Setenv("GAVEL_GUARD_ALLOWED_ADDR", allowed.Addr().String())
	t.Setenv("GAVEL_GUARD_DENIED_ADDR", denied.Addr().String())
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := runGuardedAgent([]string{exe, "-test.run=^TestKernelGuardedAgentProbe$", "-test.v"}); err != nil {
		t.Fatalf("guarded agent and descendant were not properly kernel-contained: %v", err)
	}
	t.Log("KERNEL PROOF: both restricted-UID parent and fork/exec descendant denied the forbidden IPv4 connection")
}

func TestGuardedRunRefusesMissingIdentityWithoutExecuting(t *testing.T) {
	t.Setenv("GAVEL_AGENT_UID", "")
	t.Setenv("GAVEL_AGENT_GID", "")
	if err := runGuardedAgent([]string{"/bin/true"}); err == nil {
		t.Fatal("must reject before creating cgroup or executing agent")
	}
}

func TestKernelGuardedContainmentProbe(t *testing.T) {
	if os.Getenv("GAVEL_CONTAINMENT_PROBE") != "1" { t.Skip("isolated containment probe") }
	if os.Geteuid() != 65534 { t.Fatalf("unexpected uid: %d", os.Geteuid()) }
	if err := syscall.Setuid(0); !errors.Is(err, syscall.EPERM) { t.Fatalf("setuid denial: %v", err) }
	target := os.Getenv("GAVEL_CONTAINMENT_TARGET")
	before, err := os.ReadFile("/proc/self/cgroup")
	if err != nil { t.Fatal(err) }
	err = os.WriteFile(filepath.Join(target, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600)
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) { t.Fatalf("migration must be denied: %v", err) }
	after, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(before) != string(after) { t.Fatalf("cgroup changed: %q -> %q (%v)", before, after, err) }
	out, err := exec.Command(os.Getenv("GAVEL_CONTAINMENT_SETUID"), "-u").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "65534" { t.Fatalf("setuid executable elevated or failed: %q %v", out, err) }
	t.Log("KERNEL PROOF: setuid syscall, setuid executable and sibling cgroup migration denied")
}

func TestKernelGuardedContainment(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	target, err := os.MkdirTemp("/sys/fs/cgroup", "gavel-test-sibling-")
	if err != nil { t.Fatal(err) }
	defer os.Remove(target)
	dir, err := os.MkdirTemp("/tmp", "gavel-setuid-proof-")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil { t.Fatal(err) }
	data, err := os.ReadFile("/usr/bin/id")
	if err != nil { t.Fatal(err) }
	fixture := filepath.Join(dir, "id")
	if err := os.WriteFile(fixture, data, 0755); err != nil { t.Fatal(err) }
	if err := os.Chmod(fixture, 0755|os.ModeSetuid); err != nil { t.Fatal(err) }
	// Positive control: prove the fixture actually elevates without the guard.
	control := exec.Command(fixture, "-u")
	control.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid:65534,Gid:65534}}
	out, err := control.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "0" { t.Fatalf("invalid setuid fixture (nosuid mount or other restriction): %q %v",out,err) }
	t.Setenv("GAVEL_MACHINE_KEY", "")
	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID", "65534")
	t.Setenv("GAVEL_AGENT_GID", "65534")
	t.Setenv("GAVEL_CONTAINMENT_PROBE", "1")
	t.Setenv("GAVEL_CONTAINMENT_TARGET", target)
	t.Setenv("GAVEL_CONTAINMENT_SETUID", fixture)
	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	if err := runGuardedAgent([]string{exe, "-test.run=^TestKernelGuardedContainmentProbe$", "-test.v"}); err != nil { t.Fatal(err) }
}
