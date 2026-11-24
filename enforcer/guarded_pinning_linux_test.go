//go:build linux

package main

import (
	"path/filepath"
	"testing"
)

func TestPinnedLinkNamingRejectsPathTraversalAndForeignNames(t *testing.T) {
	for _, name := range []string{
		"", ".", "..", "/sys/fs/bpf", "../gavel-agent-123",
		"gavel-agent-abc", "gavel-agent-", "foreign-123",
		"gavel-agent-123/../../etc", "gavel-agent-123\x00",
	} {
		if path, err := guardedPinPath(name); err == nil {
			t.Errorf("unsafe/non-generated name %q produced pin %s", name, path)
		}
	}
	pin, err := guardedPinPath("gavel-agent-123456")
	if err != nil || pin != filepath.Join(guardedBPFFSRoot, "gavel-agent-123456") {
		t.Fatalf("legitimate generated name was rejected: %s %v", pin, err)
	}
}

func TestRecoverRejectsUnsafeNameBeforeAccessingCgroups(t *testing.T) {
	for _, name := range []string{"../../proc", "/sys/fs/cgroup", "gavel-agent-1/../../"} {
		if err := recoverGuardedAgent(name); err == nil {
			t.Fatalf("recovery accepted invalid cgroup identifier: %q", name)
		}
	}
}
