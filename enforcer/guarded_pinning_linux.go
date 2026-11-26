//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const guardedBPFFSRoot = "/sys/fs/bpf/gavel-agents"

var guardedCgroupName = regexp.MustCompile(`^gavel-agent-[0-9]+$`)

// prepareGuardedPinRoot requires bpffs, never an ordinary writable directory.
// The pinned link is deliberately owned by privileged host-side recovery,
// rather than by the agent or the lifetime of the launching process.
func prepareGuardedPinRoot() error {
	if err := validateTrustedDirectoryChain("/sys/fs/bpf"); err != nil {
		return fmt.Errorf("untrusted bpffs ancestor: %w",err)
	}
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
	// bpffs rejects filenames containing a dot on several kernels.
	return base + "_v6", nil
}

// The suffixes are fixed and match networkHooks. Older workloads may
// have only the primary link or the primary and IPv6 links.
var guardedNetworkPinSuffixes = []string{"", "_v6", "_udp4", "_udp6"}

// Attach and pin every required hook before an untrusted task is launched.
// Never fall back to audit-only or a partial set of hooks.
func attachPinnedGuardedEnforcer(cgroup string, config LinuxEnforcerConfig) (string, error) {
	if !config.ProtectAll || !linuxPolicyConfigured(config) {
		return "", fmt.Errorf("SECURITY BLOCKER: pinned attachment requires a nonempty protect-all policy")
	}
	base, err := guardedPinPath(filepath.Base(filepath.Clean(cgroup)))
	if err != nil {
		return "", err
	}
	if err := prepareGuardedPinRoot(); err != nil {
		return "", err
	}
	for _, suffix := range guardedNetworkPinSuffixes {
		pin := base + suffix
		if _, err := os.Lstat(pin); err == nil {
			return "", fmt.Errorf("SECURITY BLOCKER: pin already exists %s; refusing overwrite", pin)
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	objects, err := loadLinuxEnforcerObjects(true, config.TCPOnly)
	if err != nil {
		return "", fmt.Errorf("load protected network kernel programs: %w", err)
	}
	defer objects.Close()
	if err := configureLinuxEnforcer(objects, config); err != nil {
		return "", err
	}
	if err := objects.freezeGuardedPolicy(); err != nil {
		return "", fmt.Errorf("SECURITY BLOCKER: immutable guarded policy required: %w",err)
	}
	var pinned []link.Link
	rollback := func(cause error) error {
		for i := len(pinned)-1; i >= 0; i-- {
			if err := pinned[i].Unpin(); err != nil {
				cause = errors.Join(cause, fmt.Errorf("rollback pin: %w", err))
			}
		}
		return cause
	}
	for _, hook := range objects.networkHooks() {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path: cgroup, Attach: hook.attach, Program: hook.program,
		})
		if err != nil {
			return "", rollback(fmt.Errorf("attach guarded %s: %w", hook.name, err))
		}
		defer l.Close()
		if err := l.Pin(base + hook.pinSuffix); err != nil {
			return "", rollback(fmt.Errorf("SECURITY BLOCKER: pinnable %s BPF link required: %w", hook.name, err))
		}
		pinned = append(pinned, l)
	}
	return base, nil
}

// Called only after the entire protected cgroup has been stopped and proven
// unpopulated. Missing pins are supported for older workloads and
// for retries after partially successful cleanup.
func unpinGuardedEnforcer(name string) error {
	base, err := guardedPinPath(name)
	if err != nil {
		return err
	}
	for i := len(guardedNetworkPinSuffixes)-1; i >= 0; i-- {
		pin := base + guardedNetworkPinSuffixes[i]
		attached, err := link.LoadPinnedLink(pin, nil)
		if os.IsNotExist(err) {
			continue
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
	if err := validateGuardedCgroup(cgroup); err != nil {
		return fmt.Errorf("protected cgroup missing or untrusted %s: %w", cgroup, err)
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
