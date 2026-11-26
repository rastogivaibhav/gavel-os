//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// runGuardedAgent launches ONLY new, unprivileged workloads in a dedicated
// cgroup after all required network BPF hooks are attached and pinned. Existing PID-based monitoring
// and its policy model are unchanged by this opt-in path.
//
// Security scope: IP connect and unconnected UDP destination blocklists. Requires a modern pinnable BPF link;
// the kernel hook survives a supervisor SIGKILL, but independent recovery is
// required to kill any surviving descendants and remove the pin.
func runGuardedAgent(argv []string) (resultErr error) {
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("usage: gavel-enforcer run <absolute-executable> [args...]")
	}
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("guarded executable path must be absolute: %q", argv[0])
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("guarded runner requires a privileged supervisor in an isolated cgroup-v2 host")
	}
	uid, gid, err := guardedUnprivilegedIdentity()
	if err != nil {
		return err
	}
	// Refuse a concurrently used identity before any workload starts.
	// Hold the lease for the complete supervisor lifetime, including cleanup.
	lease, err := acquireGuardedUIDLease(uid)
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: dedicated agent identity: %w", err)
	}
	defer lease.Close()
	fsArgs, err := guardedFilesystemArguments()
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: filesystem policy: %w", err)
	}
	preflight := runLinuxPreflight()
	if !preflight.EnforcementCapable || !linuxEBPFProgramReady(preflight.EBPFProgramStatus) || !preflight.CgroupV2 {
		return fmt.Errorf("SECURITY BLOCKER: kernel or cgroup preflight failed: %s", preflight.ReasonCode)
	}
	config, status, err := resolveLinuxRuntimePolicy(preflight)
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: agent policy unavailable: %w", err)
	}
	if preflight.PolicySource == "control_plane" && status != "online" {
		return fmt.Errorf("SECURITY BLOCKER: control-plane runtime policy is not online: %s", status)
	}
	// Never accept host supplied PIDs as a substitute for workload attribution.
	// Every task in this dedicated cgroup, including descendants, is in-scope.
	config.MonitoredPIDs = nil
	config.ProtectAll = true
	if !linuxPolicyConfigured(config) {
		return fmt.Errorf("SECURITY BLOCKER: guarded workload requires a block or redirect policy")
	}

	if err := validateGuardedCgroup(preflight.CgroupPath); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: untrusted cgroup parent: %w", err)
	}
	cg, err := os.MkdirTemp(preflight.CgroupPath, "gavel-agent-")
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot create dedicated child cgroup: %w", err)
	}
	// The BPF link is pinned *before* the unprivileged child is launched.
	// A Go defer cannot execute under SIGKILL; the persisted bpffs link
	// continues to mediate this cgroup when this supervisor dies.
	started := false
	terminated := true
	pinned := false
	pinName := filepath.Base(cg)
	defer func() {
		if started && !terminated {
			log.Printf("SECURITY CRITICAL: workload may survive supervisor termination in %s; kernel BPF link remains pinned for independent recovery", cg)
			return
		}
		if !terminated {
			return
		}
		if pinned {
			if err := unpinGuardedEnforcer(pinName); err != nil {
				resultErr = fmt.Errorf("SECURITY BLOCKER: safe link cleanup failed (cgroup %s): %w", cg, err)
				return // Never remove cgroup while we still own a pinned link.
			}
		}
		if err := os.Remove(cg); err != nil {
			resultErr = fmt.Errorf("SECURITY BLOCKER: remove protected cgroup %s: %w", cg, err)
		}
	}()

	if err := validateGuardedCgroup(cg); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: untrusted protected cgroup: %w", err)
	}
	pin, err := attachPinnedGuardedEnforcer(cg, config)
	if err != nil {
		// If rollback failed, retain the empty cgroup for operator recovery.
		// No workload has been launched.
		if base, pathErr := guardedPinPath(pinName); pathErr == nil {
			for _, suffix := range guardedNetworkPinSuffixes {
				if _, statErr := os.Lstat(base + suffix); !os.IsNotExist(statErr) {
					terminated = false
					break
				}
			}
		}
		return fmt.Errorf("SECURITY BLOCKER: cannot pin kernel policy before agent execution: %w", err)
	}
	pinned = true
	log.Printf("persistent protected kernel link pinned at %s", pin)

	cgfd, err := os.Open(cg)
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot open protected cgroup: %w", err)
	}
	defer cgfd.Close()

	// The trusted util-linux launcher must drop the capability bounding set
	// while it still has CAP_SETPCAP, then drop all identities/groups before
	// untrusted exec. No fallback to an incomplete credential transition.
	// The privileged supervisor environment is host-controlled, not agent input.
	launcher := "/usr/bin/setpriv"
	info, err := os.Lstat(launcher)
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: trusted setpriv unavailable: %w", err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("SECURITY BLOCKER: setpriv must be a trusted root-owned executable")
	}
	if err := validateTrustedDirectoryChain(filepath.Dir(launcher)); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: untrusted setpriv parent: %w", err)
	}
	filter, err := guardedSeccompFile()
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot prepare syscall policy: %w", err)
	}
	defer filter.Close()
	args := append([]string{
		"--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
		"--reuid="+strconv.FormatUint(uint64(uid), 10), "--regid="+strconv.FormatUint(uint64(gid), 10),
		"--clear-groups", "--pdeathsig", "keep", "--seccomp-filter", "/proc/self/fd/3",
	}, fsArgs...)
	args = append(args, "--")
	args = append(args, argv...)
	if len(fsArgs) != 0 {
		log.Print("guarded launch requires Landlock filesystem allowlist")
	} else {
		log.Print("guarded launch: filesystem policy not configured; filesystem access is not governed by GavelOS")
	}
	cmd := exec.Command(launcher, args...)
	// FD 3 contains only the immutable public filter, never a privileged socket.
	cmd.ExtraFiles = []*os.File{filter}
	if err := configureGuardedDescriptors(cmd); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: descriptor isolation: %w", err)
	}
	cmd.Env = guardedWorkloadEnvironment(os.Environ())
	// Atomic cgroup assignment at process creation eliminates the interval
	// between fork and userspace moving the process into a cgroup.
	// No insecure fallback if clone3/CLONE_INTO_CGROUP is unsupported.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD: int(cgfd.Fd()),
		Pdeathsig: syscall.SIGKILL,
	}
	// Mark all ambient non-stdio descriptors close-on-exec. os/exec
	// deliberately remaps only the sealed filter from ExtraFiles to FD 3.
	if err := sealAmbientDescriptors(); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: descriptor isolation unavailable: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: protected process could not be spawned inside cgroup: %w", err)
	}
	started = true
	terminated = false
	log.Printf("protected child pid=%d cgroup=%s (connect4/connect6/sendmsg4/sendmsg6 policy; descendants inherit scope)", cmd.Process.Pid, cg)

	stops := make(chan os.Signal, 1)
	signal.Notify(stops, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stops)
	done := make(chan struct{})
	go func() {
		select {
		case <-stops:
			if err := killProtectedCgroup(cg); err != nil {
				log.Printf("SECURITY CRITICAL: failed to terminate protected cgroup on shutdown: %v", err)
			}
		case <-done:
		}
	}()

	waitErr := cmd.Wait()
	close(done)
	// A successful direct child exit does NOT imply descendants have exited.
	// Kill the full cgroup before releasing the hook; fail the command if this
	// cannot be verified. Abnormal supervisor death remains out of scope.
	if err := killProtectedCgroup(cg); err != nil {
		return fmt.Errorf("SECURITY CRITICAL: cannot terminate protected descendants before detaching: %w", err)
	}
	if err := waitProtectedCgroupEmpty(cg, 3*time.Second); err != nil {
		return fmt.Errorf("SECURITY CRITICAL: cannot confirm protected workload exited: %w", err)
	}
	terminated = true
	if waitErr != nil {
		return fmt.Errorf("protected workload exited with error: %w", waitErr)
	}
	return nil
}

func guardedUnprivilegedIdentity() (uint32, uint32, error) {
	parse := func(name string) (uint32, error) {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			return 0, fmt.Errorf("%s is required (use a dedicated unprivileged account)", name)
		}
		value, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || value == 0 || value >= 4294967295 {
			return 0, fmt.Errorf("%s must be a valid nonzero unprivileged ID", name)
		}
		return uint32(value), nil
	}
	uid, err := parse("GAVEL_AGENT_UID")
	if err != nil {
		return 0, 0, err
	}
	gid, err := parse("GAVEL_AGENT_GID")
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func guardedWorkloadEnvironment(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		// The agent must not inherit the supervisor's policy or machine secrets.
		if strings.HasPrefix(entry, "LD_") ||
			strings.HasPrefix(entry, "MALLOC_") ||
			strings.HasPrefix(entry, "GLIBC_TUNABLES=") ||
			strings.HasPrefix(entry, "GCONV_PATH=") ||
			strings.HasPrefix(entry, "LOCPATH=") ||
			strings.HasPrefix(entry, "NLSPATH=") ||
			strings.HasPrefix(entry, "TZDIR=") ||
			strings.HasPrefix(entry, "GAVEL_AGENT_FS_POLICY=") ||
			strings.HasPrefix(entry, "GAVEL_MACHINE_KEY=") ||
			strings.HasPrefix(entry, "GAVEL_AGENT_UID=") ||
			strings.HasPrefix(entry, "GAVEL_AGENT_GID=") ||
			strings.HasPrefix(entry, "GAVEL_BLOCKED_IPS=") ||
			strings.HasPrefix(entry, "GAVEL_BLOCKED_IPV6=") ||
			strings.HasPrefix(entry, "GAVEL_MONITORED_PIDS=") ||
			strings.HasPrefix(entry, "GAVEL_ENGINE_URL=") ||
			strings.HasPrefix(entry, "GAVEL_PROXY_") ||
			strings.HasPrefix(entry, "GAVEL_CGROUP_PATH=") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func killProtectedCgroup(cg string) error {
	return os.WriteFile(filepath.Join(cg, "cgroup.kill"), []byte("1"), 0600)
}

func waitProtectedCgroupEmpty(cg string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(filepath.Join(cg, "cgroup.events"))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "populated 0" {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cgroup remains populated after %s", timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// This is intentionally conservative: refuse delegated, symlinked or writable
// paths rather than assuming that the workload cannot manipulate its ancestry.
// Host root, mount namespace and privileged supervisor are trusted assumptions.
func validateTrustedDirectoryChain(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("expected clean absolute directory path: %q", path)
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("directory must be root-owned and not group/world writable: %s", current)
		}
		if current == "/" {
			return nil
		}
	}
}

func validateGuardedCgroup(path string) error {
	if err := validateTrustedDirectoryChain(path); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("expected real cgroup v2 filesystem: %s", path)
	}
	// Migration needs write access to the destination and common ancestor.
	// Check control files for the entire cgroup ancestry on this mount.
	for current := path; ; current = filepath.Dir(current) {
		if err := unix.Statfs(current, &fs); err != nil {
			return err
		}
		if fs.Type != unix.CGROUP2_SUPER_MAGIC {
			break
		}
		for _, name := range []string{"cgroup.procs", "cgroup.threads"} {
			file := filepath.Join(current, name)
			info, err := os.Lstat(file)
			if err != nil {
				return err
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("migration control must be root-owned and not group/world writable: %s", file)
			}
		}
		if current == "/" {
			break
		}
	}
	return nil
}
