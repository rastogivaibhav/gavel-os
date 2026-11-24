//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Run only as a child of the mandatory seccomp launcher. All attempted
// operations use harmless invalid arguments or local sockets; no external
// targets, real kernel modification or privileged operations are performed.
func checkGuardedSyscallPolicy(t *testing.T) {
	t.Helper()
	for _, nr := range []uintptr{
		unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_BPF,
		unix.SYS_PERF_EVENT_OPEN, unix.SYS_MOUNT, unix.SYS_IO_URING_SETUP,
	} {
		_, _, errno := unix.RawSyscall6(nr, 0, 0, 0, 0, 0, 0)
		if errno != unix.EPERM {
			t.Fatalf("blocked syscall %d returned %v, expected EPERM", nr, errno)
		}
	}
	// Ordinary clone is required by the Go runtime and exec descendants.
	// Verify clone3 is explicitly unavailable without creating a new task.
	_, _, errno := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0)
	if errno != unix.ENOSYS { t.Fatalf("clone3 policy: %v", errno) }

	for _, c := range []struct{ family, kind, protocol int }{
		{unix.AF_PACKET, unix.SOCK_DGRAM, 0},
		{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP},
		{unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6},
		{unix.AF_NETLINK, unix.SOCK_RAW, 0},
	} {
		fd, err := unix.Socket(c.family, c.kind, c.protocol)
		if fd >= 0 { unix.Close(fd) }
		if !errors.Is(err, unix.EPERM) { t.Fatalf("socket policy %+v: %v", c, err) }
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6, unix.AF_UNIX} {
		fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil { t.Fatalf("allowed socket %d: %v", family, err) }
		unix.Close(fd)
	}
	t.Log("KERNEL PROOF: restricted syscalls and socket families denied; ordinary sockets permitted")
}

func TestGuardedSeccompProbe(t *testing.T) {
	if os.Getenv("GAVEL_SECCOMP_PROBE") != "1" { t.Skip("child probe") }
	checkGuardedSyscallPolicy(t)
}

func TestGuardedSeccompSealsAndKernelExecution(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" { t.Skip("unsupported ABI") }
	f, err := guardedSeccompFile()
	if err != nil { t.Fatal(err) }
	defer f.Close()
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals & (unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) != (unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) {
		t.Fatalf("filter not sealed: %d %v", seals, err)
	}
	if _, err := f.WriteAt([]byte{0}, 0); !errors.Is(err, unix.EPERM) { t.Fatalf("filter mutation: %v", err) }
	// The required privileged integration job also exercises this filter
	// via the full guarded launcher. Here test the actual kernel independently
	// of eBPF permissions, with an unprivileged test process.
	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	cmd := exec.Command("/usr/bin/setpriv", "--no-new-privs", "--seccomp-filter", "/proc/self/fd/3", "--", exe, "-test.run=^TestGuardedSeccompProbe$", "-test.v")
	cmd.Env = append(os.Environ(), "GAVEL_SECCOMP_PROBE=1")
	cmd.ExtraFiles = []*os.File{f}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS: TestGuardedSeccompProbe") {
		t.Fatalf("seccomp child failed: %v\n%s", err, out)
	}
}
