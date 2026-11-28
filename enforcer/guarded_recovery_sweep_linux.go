//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
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
	_, count, err := inspectGuardedRecoveryTarget(parent, name)
	if err == nil && count != len(guardedNetworkPinSuffixes) {
		return fmt.Errorf("required pins missing: %d present", count)
	}
	return err
}

func inspectGuardedRecoveryTarget(parent, name string) (guardedRecoveryReceipt, int, error) {
	id, err := guardedRecoveryIdentity(parent, name)
	if err != nil { return id, 0, err }
	base, err := guardedPinPath(name)
	if err != nil { return id, 0, err }
	count := 0
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
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return id, count, fmt.Errorf("cannot verify pin %s: %w", pin, err)
		}
		info, err := l.Info()
		_ = l.Close()
		if err != nil {
			return id, count, fmt.Errorf("read kernel link metadata %s: %w", pin, err)
		}
		cg := info.Cgroup()
		if cg == nil || cg.CgroupId != id.Inode || ebpf.AttachType(cg.AttachType) != hook.attach {
			return id, count, fmt.Errorf("pin %s does not bind expected cgroup and hook", pin)
		}
		count++
	}
	return id, count, nil
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
	candidates := guardedSweepCandidates(entries)
	receipts, err := os.ReadDir(guardedLifecycleRoot)
	if err != nil && !os.IsNotExist(err) { return result, err }
	seen := map[string]bool{}
	for _, name := range candidates { seen[name] = true }
	for _, entry := range receipts {
		name := strings.TrimSuffix(entry.Name(), guardedRecoveryReceiptSuffix)
		if name != entry.Name() && guardedCgroupName.MatchString(name) && !seen[name] {
			candidates = append(candidates, name)
			seen[name] = true
		}
	}
	sort.Strings(candidates)
	for _, name := range candidates {
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
	return recoverGuardedCandidateLocked(parent, name)
}
