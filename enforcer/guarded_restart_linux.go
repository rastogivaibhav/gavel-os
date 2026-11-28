//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// The trusted operator supplies the previous cgroup name and an independently
// approved effective digest. This is a one-shot fresh launch, not a resume,
// hot policy update, or automatic recovery of an ambiguous predecessor.
func restartGuardedAgent(previous, approval string, argv []string) error {
	if os.Geteuid() != 0 { return fmt.Errorf("restart requires privileged host operator") }
	if approval == "" { return fmt.Errorf("restart requires an explicit approved policy digest") }
	if err := verifyGuardedApprovedDigest(approval, approval); err != nil { return err }
	if os.Getenv("GAVEL_MACHINE_KEY") == "" { return fmt.Errorf("restart requires remote policy authority") }
	base, err := guardedPinPath(previous)
	if err != nil { return err }
	parent, ok := resolveLinuxCgroupPath()
	if !ok { return fmt.Errorf("cannot resolve protected cgroup parent") }
	if err := validateGuardedCgroup(parent); err != nil { return err }
	if err := prepareGuardedPinRoot(); err != nil { return err }
	lease, err := acquireGuardedLifecycleLease(previous)
	if err != nil { return fmt.Errorf("predecessor lifecycle lease: %w",err) }
	defer lease.Close()
	// No destructive action is authorized by restart. A previous workload
	// must already have completed trusted cleanup; refuse ambiguous states.
	paths := []string{filepath.Join(parent, previous), recoveryReceiptPath(previous)}
	for _, suffix := range guardedNetworkPinSuffixes { paths = append(paths,base+suffix) }
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("predecessor cleanup incomplete: %s",path)
		} else if !os.IsNotExist(err) { return err }
	}
	return runGuardedAgentWithApproval(argv,approval)
}
