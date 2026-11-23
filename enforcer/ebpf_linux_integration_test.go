//go:build linux

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

// TestKernelConnect4Probe runs in a separate process inside the test-only cgroup.
// It proves an actual kernel-mediated socket operation, not a policy mock.
func TestKernelConnect4Probe(t *testing.T) {
	if os.Getenv("GAVEL_KERNEL_PROBE_HELPER") != "1" {
		t.Skip("helper for opt-in privileged cgroup/eBPF test")
	}
	var gate [1]byte
	if _, err := io.ReadFull(os.Stdin, gate[:]); err != nil {
		t.Fatalf("waiting for cgroup enrollment: %v", err)
	}
	allowed, err := net.DialTimeout("tcp4", os.Getenv("GAVEL_KERNEL_ALLOWED_ADDR"), 3*time.Second)
	if err != nil {
		t.Fatalf("allowed connection unexpectedly denied: %v", err)
	}
	_ = allowed.Close()

	denied, err := net.DialTimeout("tcp4", os.Getenv("GAVEL_KERNEL_DENIED_ADDR"), 3*time.Second)
	if denied != nil {
		_ = denied.Close()
		t.Fatal("security violation: connection to denied destination succeeded")
	}
	if err == nil || (!errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES)) {
		t.Fatalf("expected kernel EPERM/EACCES for denied connect, got %v", err)
	}
}

// TestKernelConnect4Denial is intentionally excluded from ordinary CI.
// Run ONLY in a disposable privileged Linux VM with cgroup v2 and eBPF:
//
// GAVEL_RUN_KERNEL_TESTS=1 go test -run '^TestKernelConnect4Denial$' -v .
//
// The test never attaches BPF to the existing parent/root cgroup.
func TestKernelConnect4Denial(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" {
		t.Skip("requires opt-in isolated privileged Linux VM: GAVEL_RUN_KERNEL_TESTS=1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires privileged isolated test VM; do not run on production")
	}

	cg, err := os.MkdirTemp("/sys/fs/cgroup", "gavel-test-")
	if err != nil {
		t.Fatalf("cannot create isolated child cgroup v2: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cg); err != nil {
			t.Errorf("cleanup cgroup %s: %v", cg, err)
		}
	})
	if _, err := os.Stat(filepath.Join(cg, "cgroup.procs")); err != nil {
		t.Fatalf("cgroup setup failed: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("cannot increase BPF memlock: %v", err)
	}

	allowedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer allowedListener.Close()
	deniedListener, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Fatalf("cannot bind denied loopback address: %v", err)
	}
	defer deniedListener.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelConnect4Probe$", "-test.v")
	cmd.Env = append(os.Environ(),
		"GAVEL_KERNEL_PROBE_HELPER=1",
		"GAVEL_KERNEL_ALLOWED_ADDR="+allowedListener.Addr().String(),
		"GAVEL_KERNEL_DENIED_ADDR="+deniedListener.Addr().String(),
		"GAVEL_RUN_KERNEL_TESTS=0",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	// Helper pauses before any connection. Enroll it in an isolated cgroup,
	// then install BPF with its exact PID before allowing it to run.
	pid := cmd.Process.Pid
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0600); err != nil {
		t.Fatalf("cannot enroll helper PID %d: %v", pid, err)
	}
	blocked, err := parseIPv4("127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	detach, err := attachEnforcer(cg, LinuxEnforcerConfig{
		MonitoredPIDs: []uint32{uint32(pid)},
		BlockedIPv4:   []uint32{blocked},
	})
	if err != nil {
		t.Fatalf("actual kernel BPF load/attach failed: %v", err)
	}
	defer detach()

	if _, err := stdin.Write([]byte{1}); err != nil {
		t.Fatalf("releasing test probe: %v", err)
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("kernel connection-denial probe failed: %v", err)
	}

	// Evidence check: the forbidden address must not have received a TCP
	// connection. This is in addition to observing an EPERM/EACCES syscall.
	tcpListener, ok := deniedListener.(*net.TCPListener)
	if !ok {
		t.Fatal("expected TCPListener")
	}
	_ = tcpListener.SetDeadline(time.Now().Add(200 * time.Millisecond))
	blockedConn, err := tcpListener.Accept()
	if blockedConn != nil {
		_ = blockedConn.Close()
		t.Fatal("security violation: denied listener accepted a connection")
	}
	if err == nil {
		t.Fatal("expected denied listener accept to time out")
	}
	t.Logf("kernel-proven IPv4 deny 127.0.0.2 and allow 127.0.0.1 for test-only PID %d", pid)
}
