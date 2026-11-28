//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const guardedRecoveryReceiptSuffix = ".recovery.json"

// A boot-local trusted receipt is written only AFTER a verified target has
// been killed and observed empty, BEFORE the first pin is removed. It is
// not a security attestation, nor authorization to kill a repopulated group.
type guardedRecoveryReceipt struct {
	Version int
	Parent string
	Name string
	Device uint64
	Inode uint64
}

func guardedRecoveryIdentity(parent, name string) (guardedRecoveryReceipt, error) {
	var id guardedRecoveryReceipt
	if _, err := guardedPinPath(name); err != nil { return id, err }
	if err := validateGuardedCgroup(filepath.Join(parent, name)); err != nil { return id, err }
	info, err := os.Stat(filepath.Join(parent, name))
	if err != nil { return id, err }
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 { return id, fmt.Errorf("cannot establish cgroup kernel identity") }
	return guardedRecoveryReceipt{1, parent, name, uint64(st.Dev), st.Ino}, nil
}

func recoveryReceiptPath(name string) string {
	return filepath.Join(guardedLifecycleRoot, name+guardedRecoveryReceiptSuffix)
}

func readGuardedRecoveryReceipt(name string) (*guardedRecoveryReceipt, error) {
	if _, err := guardedPinPath(name); err != nil { return nil, err }
	path := recoveryReceiptPath(name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) { return nil, nil }
	if err != nil { return nil, err }
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return nil, fmt.Errorf("invalid recovery receipt inode")
	}
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var id guardedRecoveryReceipt
	if err := json.Unmarshal(data, &id); err != nil { return nil, err }
	if id.Version != 1 || id.Name != name || id.Inode == 0 || !filepath.IsAbs(id.Parent) || filepath.Clean(id.Parent) != id.Parent {
		return nil, fmt.Errorf("invalid recovery receipt identity")
	}
	return &id, nil
}

func syncRecoveryDirectory() error {
	d, err := os.Open(guardedLifecycleRoot)
	if err != nil { return err }
	defer d.Close()
	return d.Sync()
}

// Caller holds the lifecycle lease; the trusted root-only directory is
// validated by lease acquisition. Rename makes publication atomic.
func writeGuardedRecoveryReceipt(id guardedRecoveryReceipt) error {
	data, err := json.Marshal(id)
	if err != nil { return err }
	f, err := os.CreateTemp(guardedLifecycleRoot, ".recovery-tmp-")
	if err != nil { return err }
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil { return err }
	if err := f.Sync(); err != nil { return err }
	if err := f.Close(); err != nil { return err }
	if err := os.Rename(f.Name(), recoveryReceiptPath(id.Name)); err != nil { return err }
	return syncRecoveryDirectory()
}

func clearGuardedRecoveryReceipt(name string) error {
	if err := os.Remove(recoveryReceiptPath(name)); err != nil && !os.IsNotExist(err) { return err }
	return syncRecoveryDirectory()
}

// Both manual and automatic recovery share this path, holding the same
// lease. At least one matching pin is required for initial attribution;
// no-pin recovery is allowed only with the trusted empty-state receipt.
func recoverGuardedCandidateLocked(parent, name string) (string, error) {
	return recoverGuardedCandidateWithCheckpoint(parent, name, nil)
}

// The internal observer is used only by the isolated test binary; there is
// no command-line or environment option enabling interruption in production.
func recoverGuardedCandidateWithCheckpoint(parent, name string, checkpoint func(string)) (string, error) {
	base, err := guardedPinPath(name)
	if err != nil { return "", err }
	receipt, err := readGuardedRecoveryReceipt(name)
	if err != nil { return "", err }
	if receipt != nil && receipt.Parent != parent { return "", fmt.Errorf("recovery receipt parent mismatch") }
	present := false
	for _, suffix := range guardedNetworkPinSuffixes {
		if _, err := os.Lstat(base+suffix); err == nil { present = true } else if !os.IsNotExist(err) { return "", err }
	}
	cg := filepath.Join(parent, name)
	if !present && receipt == nil {
		if _, err := os.Lstat(cg); os.IsNotExist(err) { return "gone", nil }
		return "", fmt.Errorf("no pins or recovery receipt; cannot attribute cgroup")
	}
	if _, err := os.Lstat(cg); os.IsNotExist(err) && !present && receipt != nil {
		if err := clearGuardedRecoveryReceipt(name); err != nil { return "", err }
		return "gone", nil
	}
	id, count, err := inspectGuardedRecoveryTarget(parent, name)
	if err != nil { return "", err }
	if receipt != nil {
		if *receipt != id { return "", fmt.Errorf("recovery receipt cgroup identity mismatch") }
		// A previously empty cgroup must still be empty. Unexpected
		// repopulation is a trusted-host incident; retain remaining links.
		if err := waitProtectedCgroupEmpty(cg, 0); err != nil {
			return "", fmt.Errorf("interrupted recovery target not empty; retain pins: %w", err)
		}
	} else {
		if count == 0 { return "", fmt.Errorf("no matching kernel pin; cannot attribute target") }
		if count != len(guardedNetworkPinSuffixes) {
			log.Printf("SECURITY CRITICAL: %s has only %d/%d matching pins; prior protection incomplete; terminating verified orphan", name, count, len(guardedNetworkPinSuffixes))
		}
		if err := killProtectedCgroup(cg); err != nil { return "", fmt.Errorf("cannot kill protected cgroup: %w", err) }
		if err := waitProtectedCgroupEmpty(cg, 5*time.Second); err != nil { return "", fmt.Errorf("protected cgroup not empty; retain pins: %w", err) }
		if err := writeGuardedRecoveryReceipt(id); err != nil { return "", fmt.Errorf("cannot journal empty target; retain pins: %w", err) }
	}
	if checkpoint != nil { checkpoint("receipt") }
	// Recheck emptiness and identity before removing the first/next pin.
	current, _, err := inspectGuardedRecoveryTarget(parent, name)
	if err != nil { return "", err }
	if current != id { return "", fmt.Errorf("recovery target changed") }
	if err := waitProtectedCgroupEmpty(cg, 0); err != nil { return "", err }
	if err := unpinGuardedEnforcerWithCheckpoint(name, checkpoint); err != nil { return "", err }
	if checkpoint != nil { checkpoint("all-unpinned") }
	if err := os.Remove(cg); err != nil { return "", err }
	if checkpoint != nil { checkpoint("cgroup-removed") }
	if err := clearGuardedRecoveryReceipt(name); err != nil { return "", err }
	return "recovered", nil
}
