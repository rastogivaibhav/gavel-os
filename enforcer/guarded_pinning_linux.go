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

// guardedIPv6PinPath is intentionally a sibling, not a different cgroup.
// Both links must remain pinned for the lifetime of the protected workload.
func guardedIPv6PinPath(name string) (string, error) {
	base, err := guardedPinPath(name)
	if err != nil {
		return "", err
	}
	return base + ".v6", nil
}

// attachPinnedGuardedEnforcer installs both connect4 and connect6 under a
// dedicated child cgroup and pins BOTH links before any unprivileged task may
// enter it. Modern pinnable BPF links are mandatory; no legacy fallback.
func attachPinnedGuardedEnforcer(cgroup string, config LinuxEnforcerConfig) (string, error) {
	if !config.ProtectAll || !linuxPolicyConfigured(config) {
		return "", fmt.Errorf("SECURITY BLOCKER: pinned attachment requires a nonempty protect-all policy")
	}
	name := filepath.Base(filepath.Clean(cgroup))
	pin4, err := guardedPinPath(name)
	if err != nil {
		return "", err
	}
	pin6, err := guardedIPv6PinPath(name)
	if err != nil {
		return "", err
	}
	if err := prepareGuardedPinRoot(); err != nil {
		return "", err
	}
	for _, pin := range []string{pin4, pin6} {
		if _, err := os.Lstat(pin); err == nil {
			return "", fmt.Errorf("SECURITY BLOCKER: pin already exists %s; refusing overwrite", pin)
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	objects, err := loadLinuxEnforcerObjects(true)
	if err != nil {
		return "", fmt.Errorf("load protected dual-family kernel program: %w", err)
	}
	defer objects.Close()
	if err := configureLinuxEnforcer(objects, config); err != nil {
		return "", err
	}

	link4, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroup, Attach: ebpf.AttachCGroupInet4Connect,
		Program: objects.GavelRedirectHandler,
	})
	if err != nil {
		return "", fmt.Errorf("attach guarded connect4: %w", err)
	}
	defer link4.Close()
	if err := link4.Pin(pin4); err != nil {
		return "", fmt.Errorf("SECURITY BLOCKER: pinnable connect4 BPF link required: %w", err)
	}

	link6, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroup, Attach: ebpf.AttachCGroupInet6Connect,
		Program: objects.GavelIPv6Handler,
	})
	if err != nil {
		if unpinErr := link4.Unpin(); unpinErr != nil {
			return "", fmt.Errorf("SECURITY BLOCKER: IPv6 attach failed (%v), rollback IPv4 pin failed (%w)", err, unpinErr)
		}
		return "", fmt.Errorf("SECURITY BLOCKER: IPv6 attach failed, IPv4 pin rolled back: %w", err)
	}
	defer link6.Close()
	if err := link6.Pin(pin6); err != nil {
		if unpinErr := link4.Unpin(); unpinErr != nil {
			return "", fmt.Errorf("SECURITY BLOCKER: IPv6 pin failed (%v), rollback IPv4 pin failed (%w)", err, unpinErr)
		}
		return "", fmt.Errorf("SECURITY BLOCKER: pinnable connect6 BPF link required: %w", err)
	}
	// Both pinned hooks outlive this process, including SIGKILL. Their map
	// dependencies are retained by the kernel. Never launch an agent if
	// either link could not be made persistent.
	return pin4, nil
}

// Called only after the entire protected cgroup has been stopped and proven
// unpopulated. Older IPv4-only workloads may lack the .v6 link.
func unpinGuardedEnforcer(name string) error {
	pin4, err := guardedPinPath(name)
	if err != nil {
		return err
	}
	pin6, err := guardedIPv6PinPath(name)
	if err != nil {
		return err
	}
	// Remove the IPv6 link first; leave IPv4 attached if this fails.
	for _, pin := range []string{pin6, pin4} {
		attached, err := link.LoadPinnedLink(pin, nil)
		if os.IsNotExist(err) && pin == pin6 {
			continue // legacy IPv4-only guarded cgroup
		}
		if err != nil {
			return fmt.Errorf("load persisted kernel link %s: %w", pin, err)
		}
		unpinErr := attached.Unpin()
		_ = attached.Close()
		if unpinErr != nil {
			return fmt.Errorf("unpin protected kernel link %s: %w", pin, unpinErr)
		}
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
