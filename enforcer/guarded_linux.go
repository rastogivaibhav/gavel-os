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
)

// runGuardedAgent launches ONLY new, unprivileged workloads in a dedicated
// cgroup after the BPF connect4 hook attaches. Existing PID-based monitoring
// and its policy model are unchanged by this opt-in path.
//
// Security scope: IPv4 connect4 only. The supervisor must remain trusted;
// external SIGKILL or host-root tampering can still detach its BPF link.
func runGuardedAgent(argv []string) error {
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

	cg, err := os.MkdirTemp(preflight.CgroupPath, "gavel-agent-")
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot create dedicated child cgroup: %w", err)
	}
	// An empty cgroup can be removed after the link is detached. Until a
	// workload has started, no process can escape its policy on this cgroup.
	started := false
	terminated := true
	var detach func()
	defer func() {
		if started && !terminated {
			log.Printf("SECURITY CRITICAL: guarded workload may still exist in %s; BPF link will be lost when supervisor exits", cg)
		}
		if detach != nil && terminated {
			detach()
		}
		if terminated {
			if err := os.Remove(cg); err != nil {
				log.Printf("guarded cgroup cleanup: %v", err)
			}
		}
	}()

	detach, err = attachEnforcer(cg, config)
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot attach kernel policy before agent execution: %w", err)
	}
	if detach == nil {
		return fmt.Errorf("SECURITY BLOCKER: kernel attachment provided no owned link")
	}

	cgfd, err := os.Open(cg)
	if err != nil {
		return fmt.Errorf("SECURITY BLOCKER: cannot open protected cgroup: %w", err)
	}
	defer cgfd.Close()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = guardedWorkloadEnvironment(os.Environ())
	// Atomic cgroup assignment at process creation eliminates the interval
	// between fork and userspace moving the process into a cgroup.
	// No insecure fallback if clone3/CLONE_INTO_CGROUP is unsupported.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD: int(cgfd.Fd()),
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("SECURITY BLOCKER: protected process could not be spawned inside cgroup: %w", err)
	}
	started = true
	terminated = false
	log.Printf("protected child pid=%d cgroup=%s (connect4 policy; descendants inherit scope)", cmd.Process.Pid, cg)

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
		if strings.HasPrefix(entry, "GAVEL_MACHINE_KEY=") ||
			strings.HasPrefix(entry, "GAVEL_AGENT_UID=") ||
			strings.HasPrefix(entry, "GAVEL_AGENT_GID=") ||
			strings.HasPrefix(entry, "GAVEL_BLOCKED_IPS=") ||
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
