//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

// Helpers execute as separate processes. They are not mocks: both socket
// attempts are performed by actual unprivileged Linux tasks in the cgroup.
func TestCrashDescendantHelper(t *testing.T) {
	if os.Getenv("GAVEL_CRASH_DESCENDANT_HELPER") != "1" {
		t.Skip("only invoked as a real protected grandchild")
	}
	guardedDial(t)
	dir := os.Getenv("GAVEL_CRASH_TEST_DIR")
	if err := os.WriteFile(filepath.Join(dir, "ready"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "after-sigkill-gate")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("did not receive post-crash test gate")
		}
		time.Sleep(30 * time.Millisecond)
	}
	// The supervisor is now dead. This MUST still fail inside the kernel:
	// if the link was not pinned, this test detects the escaped connection.
	guardedDial(t)
	if err := os.WriteFile(filepath.Join(dir, "after"), []byte("KERNEL_DENIED_AFTER_SIGKILL"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(200 * time.Millisecond) // independent recovery kills cgroup
	}
}

func TestCrashAgentHelper(t *testing.T) {
	if os.Getenv("GAVEL_CRASH_AGENT_HELPER") != "1" {
		t.Skip("only invoked as a real protected child")
	}
	if os.Geteuid() == 0 {
		t.Fatal("protected agent must not run as root")
	}
	// Fork/exec grandchild survives direct parent's Pdeathsig(SIGKILL).
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashDescendantHelper$", "-test.v", "-test.timeout=55s")
	cmd.Env = append(os.Environ(), "GAVEL_CRASH_DESCENDANT_HELPER=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

func TestCrashSupervisorHelper(t *testing.T) {
	if os.Getenv("GAVEL_CRASH_SUPERVISOR_HELPER") != "1" {
		t.Skip("only invoked as privileged supervisor subprocess")
	}
	if os.Geteuid() != 0 {
		t.Fatal("supervisor must have host privileges to install BPF")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := runGuardedAgent([]string{exe, "-test.run=^TestCrashAgentHelper$", "-test.v", "-test.timeout=60s"}); err != nil {
		t.Fatal(err)
	}
}

func waitForProofFile(filename string, timeout time.Duration) ([]byte, error) {
	until := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(filename)
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		if !time.Now().Before(until) {
			return nil, fmt.Errorf("timed out waiting for %s", filename)
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func guardedCgroupNameForPID(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		name := filepath.Base(strings.TrimSpace(strings.TrimPrefix(line, "0::")))
		if guardedCgroupName.MatchString(name) {
			return name, nil
		}
	}
	return "", fmt.Errorf("pid %d is not in an isolated GavelOS cgroup: %q", pid, data)
}

// This test deliberately SIGKILLs a privileged supervisor. The grandchild
// must remain alive AND be denied by a pinned kernel hook. Recovery then
// verifies the whole cgroup is empty before unpinning.
func TestKernelSupervisorSIGKILLRetainsBPF(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" {
		t.Skip("requires isolated privileged Linux runner and bpffs")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires privileged disposable Linux VM")
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
	dir, err := os.MkdirTemp("/tmp", "gavel-sigkill-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GAVEL_MACHINE_KEY", "")
	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_AGENT_UID", "65534")
	t.Setenv("GAVEL_AGENT_GID", "65534")
	t.Setenv("GAVEL_GUARD_ALLOWED_ADDR", allowed.Addr().String())
	t.Setenv("GAVEL_GUARD_DENIED_ADDR", denied.Addr().String())
	t.Setenv("GAVEL_CRASH_TEST_DIR", dir)
	t.Setenv("GAVEL_CRASH_SUPERVISOR_HELPER", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	supervisor := exec.Command(exe, "-test.run=^TestCrashSupervisorHelper$", "-test.v", "-test.timeout=65s")
	supervisor.Env = os.Environ()
	supervisor.Stdout, supervisor.Stderr = os.Stdout, os.Stderr
	if err := supervisor.Start(); err != nil {
		t.Fatal(err)
	}

	cgroupName := ""
	defer func() {
		if supervisor.ProcessState == nil {
			_ = supervisor.Process.Kill()
			_ = supervisor.Wait()
		}
		if cgroupName != "" {
			pin, _ := guardedPinPath(cgroupName)
			if _, err := os.Stat(pin); err == nil {
				if err := recoverGuardedAgent(cgroupName); err != nil {
					t.Errorf("SECURITY CRITICAL: cleanup recovery failed: %v", err)
				}
			}
		}
	}()

	rawPID, err := waitForProofFile(filepath.Join(dir, "ready"), 20*time.Second)
	if err != nil {
		t.Fatal("grandchild did not prove protected pre-crash connection: ", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if err != nil {
		t.Fatal(err)
	}
	cgroupName, err = guardedCgroupNameForPID(pid)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := guardedPinPath(cgroupName)
	if err != nil {
		t.Fatal(err)
	}
	// Test a real persistent BPF link is accessible before crashing owner.
	l, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		t.Fatalf("kernel link was not pinned before starting child: %v", err)
	}
	_ = l.Close()
	t.Logf("pre-crash: protected descendant pid=%d pinned kernel link=%s", pid, pin)

	if err := supervisor.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Wait(); err == nil {
		t.Fatal("supervisor should be killed by SIGKILL, not exit cleanly")
	}
	if err := syscallKillZero(pid); err != nil {
		t.Fatalf("protected grandchild did not survive supervisor SIGKILL: %v", err)
	}
	if _, err := os.Stat(pin); err != nil {
		t.Fatalf("SECURITY FAILURE: pinned BPF link disappeared after SIGKILL: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "after-sigkill-gate"), []byte("go"), 0644); err != nil {
		t.Fatal(err)
	}
	after, err := waitForProofFile(filepath.Join(dir, "after"), 10*time.Second)
	if err != nil {
		t.Fatal("no protected denial was observed AFTER supervisor SIGKILL: ", err)
	}
	if strings.TrimSpace(string(after)) != "KERNEL_DENIED_AFTER_SIGKILL" {
		t.Fatalf("unexpected post-crash evidence: %q", after)
	}
	t.Log("KERNEL PROOF: survivor received IPv4 EPERM/EACCES after supervisor SIGKILL")

	if err := recoverGuardedAgent(cgroupName); err != nil {
		t.Fatalf("independent trusted recovery failed: %v", err)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatalf("pin still present after recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join("/sys/fs/cgroup", cgroupName)); !os.IsNotExist(err) {
		t.Fatalf("cgroup still present after recovery: %v", err)
	}
	t.Log("KERNEL PROOF: independent recovery killed descendants, verified emptiness and removed pinned link")
}

// syscallKillZero is a process-existence probe, not a signal delivery.
func syscallKillZero(pid int) error {
	return syscall.Kill(pid, 0)
}
