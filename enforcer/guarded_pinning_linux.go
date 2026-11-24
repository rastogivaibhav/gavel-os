//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const guardedBPFFSRoot = "/sys/fs/bpf/gavel-agents"

var guardedCgroupName = regexp.MustCompile(`^gavel-agent-[0-9]+$`)

// prepareGuardedPinRoot requires bpffs, never an ordinary writable directory.
// The pinned link is deliberately owned by privileged host-side recovery,
// rather than by the agent or the lifetime of the launching process.
func prepareGuardedPinRoot() error {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &fs); err != nil {
		return fmt.Errorf("bpffs inaccessible: %w", err)
	}
	if uint64(fs.Type) != uint64(unix.BPF_FS_MAGIC) {
		return fmt.Errorf("SECURITY BLOCKER: /sys/fs/bpf must be a mounted bpffs (got magic %#x)", fs.Type)
	}
	if err := os.MkdirAll(guardedBPFFSRoot, 0700); err != nil {
		return fmt.Errorf("create protected pin directory: %w", err)
	}
	info, err := os.Lstat(guardedBPFFSRoot)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("SECURITY BLOCKER: pin directory must be root-owned directory mode 0700")
	}
	return nil
}

func guardedPinPath(name string) (string, error) {
	if !guardedCgroupName.MatchString(name) {
		return "", fmt.Errorf("not a generated GavelOS guarded cgroup name: %q", name)
	}
	return filepath.Join(guardedBPFFSRoot, name), nil
}

// attachPinnedGuardedEnforcer constructs a kernel-enforced policy scoped to
// a dedicated child cgroup. The link must successfully pin BEFORE an agent
// can start; on kernels using the legacy cgroup attach fallback Pin fails
// with ErrNotSupported and the launch is refused.
func attachPinnedGuardedEnforcer(cgroup string, config LinuxEnforcerConfig) (string, error) {
	if !config.ProtectAll || !linuxPolicyConfigured(config) {
		return "", fmt.Errorf("SECURITY BLOCKER: pinned attachment requires a nonempty protect-all policy")
	}
	name := filepath.Base(filepath.Clean(cgroup))
	pin, err := guardedPinPath(name)
	if err != nil {
		return "", err
	}
	if err := prepareGuardedPinRoot(); err != nil {
		return "", err
	}
	if _, err := os.Lstat(pin); err == nil {
		return "", fmt.Errorf("SECURITY BLOCKER: pin already exists for %s; refusing overwrite", name)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	objects, err := loadLinuxEnforcerObjects(true)
	if err != nil {
		return "", fmt.Errorf("load protected kernel program: %w", err)
	}
	defer objects.Close()
	if err := configureLinuxEnforcer(objects, config); err != nil {
		return "", err
	}
	attached, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroup, Attach: ebpf.AttachCGroupInet4Connect,
		Program: objects.GavelRedirectHandler,
	})
	if err != nil {
		return "", fmt.Errorf("attach protected kernel program: %w", err)
	}
	defer attached.Close()
	if err := attached.Pin(pin); err != nil {
		return "", fmt.Errorf("SECURITY BLOCKER: modern pinnable cgroup BPF link required: %w", err)
	}
	// Closing the local link fd after Pin does not detach the kernel hook.
	// The pin and kernel references retain the BPF maps and program even
	// when this process dies without running Go defers (e.g. SIGKILL).
	return pin, nil
}

func unpinGuardedEnforcer(name string) error {
	pin, err := guardedPinPath(name)
	if err != nil {
		return err
	}
	attached, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		return fmt.Errorf("load persisted BPF link %s: %w", pin, err)
	}
	defer attached.Close()
	if err := attached.Unpin(); err != nil {
		return fmt.Errorf("unpin protected BPF link %s: %w", pin, err)
	}
	return nil
}

// recoverGuardedAgent is only called from an independent privileged host
// process, never from an untrusted agent. Always stop the entire cgroup
// and prove emptiness BEFORE removing the persistent kernel policy.
func recoverGuardedAgent(name string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("SECURITY BLOCKER: recovery requires privileged host operator")
	}
	if _, err := guardedPinPath(name); err != nil {
		return err
	}
	if err := prepareGuardedPinRoot(); err != nil {
		return err
	}
	parent, ok := resolveLinuxCgroupPath()
	if !ok {
		return fmt.Errorf("cannot resolve protected cgroup parent")
	}
	cgroup := filepath.Join(parent, name)
	info, err := os.Lstat(cgroup)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("protected cgroup missing or invalid %s: %w", cgroup, err)
	}
	// Do not remove the only remaining enforcement attachment when we
	// cannot stop the processes it protects.
	if err := killProtectedCgroup(cgroup); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot kill protected cgroup: %w", err)
	}
	if err := waitProtectedCgroupEmpty(cgroup, 5e9); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: protected cgroup not empty; link remains pinned: %w", err)
	}
	if err := unpinGuardedEnforcer(name); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: protected workload stopped but pinned link cleanup failed: %w", err)
	}
	if err := os.Remove(cgroup); err != nil {
		return fmt.Errorf("remove recovered protected cgroup: %w", err)
	}
	return nil
}
