//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
)

func TestKernelGuardedRecoveryFaultTolerance(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" { t.Skip("requires isolated privileged VM") }
	if os.Geteuid() != 0 { t.Fatal("requires root") }
	parent := "/sys/fs/cgroup"
	t.Setenv("GAVEL_CGROUP_PATH", parent)
	for _, mode := range []string{"partial-live", "interrupted-partial", "interrupted-zero", "repopulated", "unattributed"} {
		t.Run(mode, func(t *testing.T) {
			cg, err := os.MkdirTemp(parent, "gavel-agent-")
			if err != nil { t.Fatal(err) }
			name := filepath.Base(cg)
			base, err := guardedPinPath(name)
			if err != nil { t.Fatal(err) }
			lease, err := acquireGuardedLifecycleLease(name)
			if err != nil { t.Fatal(err) }
			defer lease.Close()
			defer func() {
				// Trusted isolated fixture cleanup, never a product recovery path.
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
			if mode != "unattributed" {
				if _, err := attachPinnedGuardedEnforcer(cg, LinuxEnforcerConfig{ProtectAll:true, BlockedIPv4:[]uint32{ip}}); err != nil { t.Fatal(err) }
			}
			id, err := guardedRecoveryIdentity(parent, name)
			if err != nil { t.Fatal(err) }
			if mode == "interrupted-partial" || mode == "interrupted-zero" || mode == "repopulated" {
				if err := waitProtectedCgroupEmpty(cg, 0); err != nil { t.Fatal(err) }
				if err := writeGuardedRecoveryReceipt(id); err != nil { t.Fatal(err) }
			}
			var cmd *exec.Cmd
			if mode == "partial-live" || mode == "repopulated" || mode == "unattributed" {
				fd, err := os.Open(cg)
				if err != nil { t.Fatal(err) }
				defer fd.Close()
				cmd = exec.Command("/bin/sleep", "60")
				cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD:true, CgroupFD:int(fd.Fd()), Credential:&syscall.Credential{Uid:421344,Gid:421344}}
				if err := cmd.Start(); err != nil { t.Fatal(err) }
				defer func(){ if cmd.ProcessState == nil { _ = cmd.Process.Kill(); _ = cmd.Wait() } }()
				if err := waitProtectedCgroupEmpty(cg, 0); err == nil { t.Fatal("fixture should be populated") }
			}
			// Inject trusted-host partial loss or interruption at the real
			// pin-removal boundary; this is not a simulated Go link object.
			if mode != "unattributed" {
				if mode == "interrupted-zero" {
					if err := unpinGuardedEnforcer(name); err != nil { t.Fatal(err) }
				} else {
					l, err := link.LoadPinnedLink(base+"_udp6", nil)
					if err != nil { t.Fatal(err) }
					err = l.Unpin()
					_ = l.Close()
					if err != nil { t.Fatal(err) }
				}
			}
			if err := lease.Close(); err != nil { t.Fatal(err) }
			if mode == "repopulated" || mode == "unattributed" {
				_, err := sweepGuardedCandidate(parent, name)
				if err == nil { t.Fatal("ambiguous populated target must be refused") }
				if mode == "repopulated" && !strings.Contains(err.Error(), "not empty") { t.Fatal(err) }
				if mode == "unattributed" && !strings.Contains(err.Error(), "cannot attribute") { t.Fatal(err) }
				if err := syscall.Kill(cmd.Process.Pid, 0); err != nil { t.Fatal(err) }
				if mode == "repopulated" {
					for _, suffix := range []string{"", "_v6", "_udp4"} {
						l, err := link.LoadPinnedLink(base+suffix, nil)
						if err != nil { t.Fatal(err) }; l.Close()
					}
				}
				t.Logf("KERNEL PROOF: %s refused; populated target and remaining pins retained", mode)
				return
			}
			result, err := sweepGuardedOrphans()
			if err != nil || len(result.Recovered) != 1 || result.Recovered[0] != name { t.Fatalf("recovery: %+v %v", result, err) }
			if _, err := os.Stat(cg); !os.IsNotExist(err) { t.Fatalf("cgroup remains: %v", err) }
			for _, suffix := range guardedNetworkPinSuffixes {
				if _, err := os.Stat(base+suffix); !os.IsNotExist(err) { t.Fatalf("pin remains: %v", err) }
			}
			if _, err := os.Stat(recoveryReceiptPath(name)); !os.IsNotExist(err) { t.Fatalf("receipt remains: %v", err) }
			if cmd != nil {
				if err := cmd.Wait(); err == nil { t.Fatal("orphan exited successfully instead of being killed") }
				status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL { t.Fatalf("unexpected exit: %v", cmd.ProcessState) }
			}
			again, err := sweepGuardedOrphans()
			if err != nil || len(again.Recovered) != 0 { t.Fatalf("repeat recovery: %+v %v", again, err) }
			t.Logf("KERNEL PROOF: %s recovered, no residual pins/cgroup/receipt; repeated safely", mode)
		})
	}
}
