//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readyLinuxPreflight() LinuxPreflightResult {
	return LinuxPreflightResult{
		RuntimeOS: "linux", RuntimeArch: "amd64",
		RuntimeMode: "enforce", ReasonCode: "ENFORCEMENT_READY",
		CgroupPath: "/sys/fs/cgroup/gavel-test",
		EnforcementCapable: true,
	}
}

func TestEnforcementRequiredRefusesUnreadyPreflight(t *testing.T) {
	for _, reason := range []string{
		"INSUFFICIENT_PRIVILEGES", "CGROUP_V2_REQUIRED",
		"CONTROL_PLANE_POLICY_UNAVAILABLE", "NO_RUNTIME_POLICY",
		"EBPF_PROGRAM_UNAVAILABLE", "INVALID_RUNTIME_POLICY",
	} {
		called := false
		preflight := readyLinuxPreflight()
		preflight.RuntimeMode = "audit_only"
		preflight.ReasonCode = reason
		status, cleanup, err := prepareLinuxEnforcement(preflight,
			func(LinuxPreflightResult) (LinuxEnforcerConfig, string, error) {
				called = true
				return LinuxEnforcerConfig{}, "", nil
			},
			func(string, LinuxEnforcerConfig) (func(), error) {
				called = true
				return func() {}, nil
			})
		if err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: expected reason-preserving refusal, got %v", reason, err)
		}
		if status.EnforcementAttached || cleanup != nil || called {
			t.Errorf("%s: must never load policy, attach or claim protection after failed preflight", reason)
		}
	}
}

func TestEnforcementRequiredRefusesControlPlaneOutage(t *testing.T) {
	preflight := readyLinuxPreflight()
	didAttach := false
	status, cleanup, err := prepareLinuxEnforcement(preflight,
		func(LinuxPreflightResult) (LinuxEnforcerConfig, string, error) {
			return LinuxEnforcerConfig{}, "degraded", errors.New("policy server unavailable")
		},
		func(string, LinuxEnforcerConfig) (func(), error) {
			didAttach = true
			return func() {}, nil
		})
	if err == nil || cleanup != nil || didAttach || status.EnforcementAttached {
		t.Fatalf("policy outage may never produce a started enforcer: %+v, %v", status, err)
	}
	if status.RuntimeMode == "enforce" || status.ReasonCode != "CONTROL_PLANE_POLICY_UNAVAILABLE" {
		t.Fatalf("must report policy failure, not enforcement: %+v", status)
	}
}

func TestEnforcementRequiredRefusesPolicyRace(t *testing.T) {
	status, cleanup, err := prepareLinuxEnforcement(readyLinuxPreflight(),
		func(LinuxPreflightResult) (LinuxEnforcerConfig, string, error) {
			// Preflight said ready, but the second policy retrieval is empty.
			return LinuxEnforcerConfig{}, "online", nil
		},
		func(string, LinuxEnforcerConfig) (func(), error) {
			t.Fatal("empty or revoked policy must not attach")
			return func() {}, nil
		})
	if err == nil || cleanup != nil || status.EnforcementAttached || status.ReasonCode != "NO_RUNTIME_POLICY" {
		t.Fatalf("empty policy must block startup: %+v, %v", status, err)
	}
}

func TestEnforcementRequiredRefusesKernelAttachFailure(t *testing.T) {
	denied := LinuxEnforcerConfig{MonitoredPIDs: []uint32{200}, BlockedIPv4: []uint32{1}}
	status, cleanup, err := prepareLinuxEnforcement(readyLinuxPreflight(),
		func(LinuxPreflightResult) (LinuxEnforcerConfig, string, error) {
			return denied, "online", nil
		},
		func(string, LinuxEnforcerConfig) (func(), error) {
			return nil, errors.New("BPF verifier denied program")
		})
	if err == nil || cleanup != nil || status.EnforcementAttached || status.ReasonCode != "EBPF_ATTACH_FAILED" {
		t.Fatalf("attachment error must block startup: %+v, %v", status, err)
	}
}

func TestEnforcementActiveOnlyAfterAttachedHook(t *testing.T) {
	denied := LinuxEnforcerConfig{MonitoredPIDs: []uint32{200}, BlockedIPv4: []uint32{1}}
	cleanupCalled := false
	status, cleanup, err := prepareLinuxEnforcement(readyLinuxPreflight(),
		func(LinuxPreflightResult) (LinuxEnforcerConfig, string, error) {
			return denied, "online", nil
		},
		func(path string, cfg LinuxEnforcerConfig) (func(), error) {
			if path != "/sys/fs/cgroup/gavel-test" || len(cfg.MonitoredPIDs) != 1 {
				t.Fatalf("unexpected attachment args: %q %#v", path, cfg)
			}
			return func() { cleanupCalled = true }, nil
		})
	if err != nil || status.RuntimeMode != "enforce" || !status.EnforcementAttached || cleanup == nil {
		t.Fatalf("expected attached-only active status; got %+v %v", status, err)
	}
	if status.MonitoredPIDCount != 1 || status.BlockedIPv4Count != 1 {
		t.Fatalf("policy counts must be from attached policy: %+v", status)
	}
	cleanup()
	if !cleanupCalled {
		t.Fatal("cleanup must be owned by the active runtime")
	}
}

func TestAuditOnlyRequiresExplicitOperatorFlagPath(t *testing.T) {
	status := linuxStartupFailure(readyLinuxPreflight(), "OPERATOR_AUDIT_ONLY")
	if status.EnforcementAttached || status.RuntimeMode != "audit_only" || status.ReasonCode != "OPERATOR_AUDIT_ONLY" {
		t.Fatalf("explicit audit-only must never be reported as protection: %+v", status)
	}
	if status.ReasonDescription == "" || status.RecommendedAction == "" {
		t.Fatal("intentional audit-only requires visible warning and action")
	}
}

func TestExplicitCgroupPathNeverFallsBackToRoot(t *testing.T) {
	t.Setenv("GAVEL_CGROUP_PATH", t.TempDir())
	path, ok := resolveLinuxCgroupPath()
	if ok || path != "" {
		t.Fatalf("invalid explicit cgroup scope must fail closed, got %q %t", path, ok)
	}
}

func TestExplicitCgroupPathIsPreservedWhenValid(t *testing.T) {
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "cgroup.controllers"), []byte("cpu io"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GAVEL_CGROUP_PATH", fake)
	path, ok := resolveLinuxCgroupPath()
	if !ok || path != fake {
		t.Fatalf("explicit cgroup selection was lost: %q %t", path, ok)
	}
}

func TestExplicitEmptyCgroupDoesNotDefaultToRoot(t *testing.T) {
	t.Setenv("GAVEL_CGROUP_PATH", "")
	path, ok := resolveLinuxCgroupPath()
	if ok || path != "" {
		t.Fatalf("explicit empty cgroup scope must fail, got %q %t", path, ok)
	}
}
