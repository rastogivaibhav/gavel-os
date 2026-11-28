//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

func TestRecoveryInterruptHelper(t *testing.T) {
	point := os.Getenv("GAVEL_TEST_RECOVERY_INTERRUPT")
	if point == "" || os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("isolated recovery subprocess only") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	name := os.Getenv("GAVEL_TEST_RECOVERY_NAME")
	lease, err := acquireGuardedLifecycleLease(name)
	if err != nil { t.Fatal(err) }
	defer lease.Close()
	_, err = recoverGuardedCandidateWithCheckpoint("/sys/fs/cgroup", name, func(stage string) {
		if stage == point {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil { t.Fatal(err) }
			t.Fatal("SIGKILL unexpectedly returned")
		}
	})
	t.Fatalf("interruption checkpoint not reached: %v", err)
}

func TestKernelGuardedRecoveryInterruption(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	parent := "/sys/fs/cgroup"
	t.Setenv("GAVEL_CGROUP_PATH", parent)
	for _, tc := range []struct{ point string; remaining int; removed bool }{
		{"receipt", 4, false},
		{"unpin:_udp6", 3, false},
		{"all-unpinned", 0, false},
		{"cgroup-removed", 0, true},
	} {
		t.Run(tc.point, func(t *testing.T) {
			cg, err := os.MkdirTemp(parent, "gavel-agent-")
			if err != nil { t.Fatal(err) }
			name := filepath.Base(cg)
			base, err := guardedPinPath(name)
			if err != nil { t.Fatal(err) }
			defer func() {
				if _, err := os.Stat(cg); err == nil {
					if err := killProtectedCgroup(cg); err != nil { t.Error(err); return }
					if err := waitProtectedCgroupEmpty(cg, 5*time.Second); err != nil { t.Error(err); return }
					if err := unpinGuardedEnforcer(name); err != nil { t.Error(err); return }
					if err := os.Remove(cg); err != nil { t.Error(err) }
				}
				if err := clearGuardedRecoveryReceipt(name); err != nil { t.Error(err) }
			}()
			ip, err := parseIPv4("127.0.0.2")
			if err != nil { t.Fatal(err) }
			if _, err := attachPinnedGuardedEnforcer(cg, LinuxEnforcerConfig{ProtectAll:true, BlockedIPv4:[]uint32{ip}}); err != nil { t.Fatal(err) }
			fd, err := os.Open(cg)
			if err != nil { t.Fatal(err) }
			defer fd.Close()
			payload := exec.Command("/bin/sleep", "60")
			payload.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD:true,CgroupFD:int(fd.Fd()),Credential:&syscall.Credential{Uid:421344,Gid:421344}}
			if err := payload.Start(); err != nil { t.Fatal(err) }
			defer func(){ if payload.ProcessState == nil { _ = payload.Process.Kill(); _ = payload.Wait() } }()
			if err := waitProtectedCgroupEmpty(cg, 0); err == nil { t.Fatal("expected live workload") }
			exe, err := os.Executable()
			if err != nil { t.Fatal(err) }
			recovery := exec.Command(exe, "-test.run=^TestRecoveryInterruptHelper$", "-test.v", "-test.timeout=15s")
			recovery.Env = append(os.Environ(), "GAVEL_TEST_RECOVERY_INTERRUPT="+tc.point, "GAVEL_TEST_RECOVERY_NAME="+name)
			out, err := recovery.CombinedOutput()
			if err == nil || recovery.ProcessState == nil { t.Fatalf("expected real interrupted recovery: %v %s", err, out) }
			status, ok := recovery.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL { t.Fatalf("recovery not SIGKILLed: %v %s", err, out) }
			if err := payload.Wait(); err == nil { t.Fatal("payload not terminated") }
			ps, ok := payload.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !ps.Signaled() || ps.Signal() != syscall.SIGKILL { t.Fatalf("payload status %v", payload.ProcessState) }
			if tc.removed {
				if _, err := os.Stat(cg); !os.IsNotExist(err) { t.Fatalf("expected removed cgroup: %v", err) }
			} else if err := waitProtectedCgroupEmpty(cg, 0); err != nil { t.Fatal(err) }
			receipt, err := readGuardedRecoveryReceipt(name)
			if err != nil || receipt == nil { t.Fatalf("missing receipt: %v", err) }
			count := 0
			for _, suffix := range guardedNetworkPinSuffixes {
				if _, err := os.Lstat(base+suffix); os.IsNotExist(err) { continue } else if err != nil { t.Fatal(err) }
				l, err := link.LoadPinnedLink(base+suffix,nil)
				if err != nil { t.Fatal(err) }
				l.Close()
				count++
			}
			if count != tc.remaining { t.Fatalf("expected %d pins, got %d", tc.remaining, count) }
			state, err := sweepGuardedCandidate(parent, name)
			if err != nil || (state != "recovered" && !(tc.removed && state == "gone")) { t.Fatalf("retry: %s %v",state,err) }
			if _, err := os.Stat(cg); !os.IsNotExist(err) { t.Fatalf("residual cgroup: %v",err) }
			for _, suffix := range guardedNetworkPinSuffixes {
				if _, err := os.Lstat(base+suffix); !os.IsNotExist(err) { t.Fatalf("residual pin: %v",err) }
			}
			if _, err := os.Stat(recoveryReceiptPath(name)); !os.IsNotExist(err) { t.Fatalf("residual receipt: %v",err) }
			t.Logf("KERNEL PROOF: real recovery SIGKILL at %s; payload terminated before unpin; retry cleared all state",tc.point)
		})
	}
}
