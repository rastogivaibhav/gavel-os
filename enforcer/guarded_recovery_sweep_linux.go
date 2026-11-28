//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// A sweep never identifies a workload by a directory name alone.
// Pin names select candidates; kernel link metadata must bind every
// required hook to the exact cgroup before the trusted recovery operation.
func guardedSweepCandidates(entries []os.DirEntry) []string {
	names := map[string]bool{}
	for _, entry := range entries {
		for _, suffix := range guardedNetworkPinSuffixes {
			name := strings.TrimSuffix(entry.Name(), suffix)
			if guardedCgroupName.MatchString(name) {
				names[name] = true
			}
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

type guardedSweepResult struct {
	Recovered []string
	Busy []string
	Gone []string
}

func verifyGuardedRecoveryTarget(parent, name string) error {
	cgroup := filepath.Join(parent, name)
	if err := validateGuardedCgroup(cgroup); err != nil {
		return err
	}
	stat, err := os.Stat(cgroup)
	if err != nil {
		return err
	}
	st, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return fmt.Errorf("cannot establish cgroup kernel identity")
	}
	base, err := guardedPinPath(name)
	if err != nil {
		return err
	}
	hooks := []struct{
		suffix string
		attach ebpf.AttachType
	}{
		{"", ebpf.AttachCGroupInet4Connect},
		{"_v6", ebpf.AttachCGroupInet6Connect},
		{"_udp4", ebpf.AttachCGroupUDP4Sendmsg},
		{"_udp6", ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, hook := range hooks {
		pin := base + hook.suffix
		l, err := link.LoadPinnedLink(pin, nil)
		if err != nil {
			return fmt.Errorf("cannot verify required pin %s: %w", pin, err)
		}
		info, err := l.Info()
		_ = l.Close()
		if err != nil {
			return fmt.Errorf("read kernel link metadata %s: %w", pin, err)
		}
		cg := info.Cgroup()
		if cg == nil || cg.CgroupId != st.Ino || ebpf.AttachType(cg.AttachType) != hook.attach {
			return fmt.Errorf("pin %s does not bind expected cgroup and hook", pin)
		}
	}
	return nil
}

// Sweep exactly once. Caller is a trusted host operator or service.
// Never kill a live supervisor's workload or guess at partial/mismatched
// state. Report ambiguous candidates for explicit operator recovery.
func sweepGuardedOrphans() (guardedSweepResult, error) {
	var result guardedSweepResult
	if os.Geteuid() != 0 {
		return result, fmt.Errorf("orphan recovery requires privileged host operator")
	}
	parent, ok := resolveLinuxCgroupPath()
	if !ok {
		return result, fmt.Errorf("cannot resolve protected cgroup parent")
	}
	if err := validateGuardedCgroup(parent); err != nil {
		return result, err
	}
	if err := prepareGuardedPinRoot(); err != nil {
		return result, err
	}
	entries, err := os.ReadDir(guardedBPFFSRoot)
	if err != nil {
		return result, err
	}
	var failures error
	for _, name := range guardedSweepCandidates(entries) {
		state, err := sweepGuardedCandidate(parent, name)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("%s: %w", name, err))
			log.Printf("SECURITY BLOCKER: orphan candidate %s requires operator review: %v", name, err)
			continue
		}
		switch state {
		case "recovered":
			result.Recovered = append(result.Recovered, name)
		case "busy":
			result.Busy = append(result.Busy, name)
		case "gone":
			result.Gone = append(result.Gone, name)
		}
	}
	return result, failures
}

func sweepGuardedCandidate(parent, name string) (string, error) {
	lease, err := acquireGuardedLifecycleLease(name)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return "busy", nil
	}
	if err != nil {
		return "", err
	}
	defer lease.Close()
	// A live supervisor may have completed normal cleanup between the
	// directory snapshot and lease acquisition. Recheck under the lease.
	base, err := guardedPinPath(name)
	if err != nil {
		return "", err
	}
	present := false
	for _, suffix := range guardedNetworkPinSuffixes {
		if _, err := os.Lstat(base + suffix); err == nil {
			present = true
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	if !present {
		return "gone", nil
	}
	if err := verifyGuardedRecoveryTarget(parent, name); err != nil {
		return "", err
	}
	if err := recoverGuardedAgentLocked(parent, name); err != nil {
		return "", err
	}
	return "recovered", nil
}
