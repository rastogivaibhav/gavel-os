package main

import "testing"

func TestArchSupportsEnforcement(t *testing.T) {
	if !archSupportsEnforcement("amd64") {
		t.Fatalf("expected amd64 to support enforcement")
	}
	if !archSupportsEnforcement("arm64") {
		t.Fatalf("expected arm64 to support enforcement")
	}
	if archSupportsEnforcement("386") {
		t.Fatalf("expected 386 to be unsupported")
	}
}

func TestParseCapabilityMask(t *testing.T) {
	mask, err := parseCapabilityMask("0000000000200000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasCapability(mask, 21) {
		t.Fatalf("expected parsed capability mask to preserve set bits")
	}
}

func TestDecideLinuxRuntimeMode(t *testing.T) {
	mode, reason := decideLinuxRuntimeMode(true, true, true, true, true)
	if mode != "enforce" || reason != "ENFORCEMENT_READY" {
		t.Fatalf("unexpected enforce result: %s %s", mode, reason)
	}

	mode, reason = decideLinuxRuntimeMode(true, false, true, true, true)
	if mode != "audit_only" || reason != "CGROUP_V2_REQUIRED" {
		t.Fatalf("unexpected fallback result: %s %s", mode, reason)
	}

	mode, reason = decideLinuxRuntimeMode(true, true, true, true, false)
	if mode != "audit_only" || reason != "NO_RUNTIME_POLICY" {
		t.Fatalf("unexpected no-policy result: %s %s", mode, reason)
	}
}

func TestLoadLinuxEnforcerConfigFromEnv(t *testing.T) {
	t.Setenv("GAVEL_MONITORED_PIDS", "101,202")
	t.Setenv("GAVEL_BLOCKED_IPS", "10.0.0.1, 10.0.0.2")
	t.Setenv("GAVEL_PROXY_IPV4", "127.0.0.1")
	t.Setenv("GAVEL_PROXY_PORT", "18788")

	config, err := loadLinuxEnforcerConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(config.MonitoredPIDs) != 2 {
		t.Fatalf("expected 2 monitored pids, got %d", len(config.MonitoredPIDs))
	}
	if len(config.BlockedIPv4) != 2 {
		t.Fatalf("expected 2 blocked ips, got %d", len(config.BlockedIPv4))
	}
	if config.Proxy.Enabled != 1 {
		t.Fatalf("expected proxy to be enabled")
	}
	if !linuxPolicyConfigured(config) {
		t.Fatalf("expected runtime policy to be configured")
	}
}

func TestLinuxEnforcerConfigFromRuntimePolicy(t *testing.T) {
	policy := RuntimePolicyResponse{
		MonitoredPIDs: []uint32{101, 202},
		BlockedIPv4:   []string{"10.0.0.1"},
		ProxyIPv4:     "127.0.0.1",
		ProxyPort:     18788,
	}

	config, err := linuxEnforcerConfigFromRuntimePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(config.MonitoredPIDs) != 2 {
		t.Fatalf("expected 2 monitored pids, got %d", len(config.MonitoredPIDs))
	}
	if len(config.BlockedIPv4) != 1 {
		t.Fatalf("expected 1 blocked ip, got %d", len(config.BlockedIPv4))
	}
	if config.Proxy.Enabled != 1 || config.Proxy.Port != 18788 {
		t.Fatalf("expected enabled proxy config, got %#v", config.Proxy)
	}
}

func TestLinuxPolicySource(t *testing.T) {
	if got := linuxPolicySource("machine-key"); got != "control_plane" {
		t.Fatalf("expected control_plane policy source, got %q", got)
	}
	if got := linuxPolicySource(""); got != "local_env" {
		t.Fatalf("expected local_env policy source, got %q", got)
	}
}

func TestLinuxReasonMetadata(t *testing.T) {
	description := linuxReasonDescription("CGROUP_V2_REQUIRED")
	if description == "" || description == "Linux runtime status is unavailable." {
		t.Fatalf("expected concrete description for CGROUP_V2_REQUIRED")
	}

	action := linuxRecommendedAction("CONTROL_PLANE_POLICY_UNAVAILABLE")
	if action == "" || action == "Inspect logs and rerun preflight for a more specific Linux runtime diagnosis." {
		t.Fatalf("expected concrete action for control plane policy failures")
	}
}

func TestParseCapabilityMaskRejectsEmptyValue(t *testing.T) {
	if _, err := parseCapabilityMask("   "); err == nil {
		t.Fatalf("expected empty mask parse to fail")
	}
}

func TestLinuxReasonMetadataDefaultsForUnknownCode(t *testing.T) {
	if got := linuxReasonDescription("UNKNOWN_REASON"); got != "Linux runtime status is unavailable." {
		t.Fatalf("unexpected default description: %q", got)
	}
	if got := linuxRecommendedAction("UNKNOWN_REASON"); got != "Inspect logs and rerun preflight for a more specific Linux runtime diagnosis." {
		t.Fatalf("unexpected default action: %q", got)
	}
}

func TestLinuxReasonMetadataCoversKnownCodes(t *testing.T) {
	reasons := []string{
		"ENFORCEMENT_READY",
		"UNSUPPORTED_ARCH",
		"CGROUP_V2_REQUIRED",
		"INSUFFICIENT_PRIVILEGES",
		"EBPF_PROGRAM_UNAVAILABLE",
		"NO_RUNTIME_POLICY",
		"CONTROL_PLANE_POLICY_UNAVAILABLE",
		"INVALID_RUNTIME_POLICY",
	}

	for _, reason := range reasons {
		if got := linuxReasonDescription(reason); got == "" || got == "Linux runtime status is unavailable." {
			t.Fatalf("expected specific description for %s, got %q", reason, got)
		}
		if got := linuxRecommendedAction(reason); got == "" || got == "Inspect logs and rerun preflight for a more specific Linux runtime diagnosis." {
			t.Fatalf("expected specific action for %s, got %q", reason, got)
		}
	}
}

func TestLoadLinuxEnforcerConfigFromEnvRejectsInvalidValues(t *testing.T) {
	t.Setenv("GAVEL_MONITORED_PIDS", "abc")
	if _, err := loadLinuxEnforcerConfigFromEnv(); err == nil {
		t.Fatalf("expected invalid pid list to fail")
	}

	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "not-an-ip")
	if _, err := loadLinuxEnforcerConfigFromEnv(); err == nil {
		t.Fatalf("expected invalid blocked ip list to fail")
	}

	t.Setenv("GAVEL_BLOCKED_IPS", "")
	t.Setenv("GAVEL_PROXY_IPV4", "not-an-ip")
	t.Setenv("GAVEL_PROXY_PORT", "1234")
	if _, err := loadLinuxEnforcerConfigFromEnv(); err == nil {
		t.Fatalf("expected invalid proxy ip to fail")
	}
}

func TestLinuxEnforcerConfigFromRuntimePolicyRejectsInvalidValues(t *testing.T) {
	if _, err := linuxEnforcerConfigFromRuntimePolicy(RuntimePolicyResponse{BlockedIPv4: []string{"bad-ip"}}); err == nil {
		t.Fatalf("expected invalid blocked ip from policy to fail")
	}

	if _, err := linuxEnforcerConfigFromRuntimePolicy(RuntimePolicyResponse{ProxyIPv4: "bad-ip", ProxyPort: 8080}); err == nil {
		t.Fatalf("expected invalid proxy ip from policy to fail")
	}
}

func TestParseUint32CSVAndParseIPv4CSV(t *testing.T) {
	values, err := parseUint32CSV("101, 202")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(values) != 2 || values[0] != 101 || values[1] != 202 {
		t.Fatalf("unexpected uint32 values: %#v", values)
	}

	if _, err := parseUint32CSV("bad"); err == nil {
		t.Fatalf("expected parseUint32CSV to reject invalid values")
	}

	ips, err := parseIPv4CSV("10.0.0.1, 10.0.0.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected two parsed ips, got %#v", ips)
	}

	if _, err := parseIPv4CSV("bad-ip"); err == nil {
		t.Fatalf("expected parseIPv4CSV to reject invalid values")
	}
}

func TestParseIPv4RejectsInvalidInput(t *testing.T) {
	if _, err := parseIPv4("not-an-ip"); err == nil {
		t.Fatalf("expected invalid IPv4 to fail")
	}
}

func TestParseIPv4ParsesValidInput(t *testing.T) {
	ip, err := parseIPv4("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip == 0 {
		t.Fatalf("expected non-zero parsed IP value")
	}
}

func TestHasCapabilityReturnsFalseWhenBitMissing(t *testing.T) {
	if hasCapability(0, 21) {
		t.Fatalf("expected missing capability bit to be false")
	}
}

func TestDecideLinuxRuntimeModeCoversRemainingFallbacks(t *testing.T) {
	mode, reason := decideLinuxRuntimeMode(false, true, true, true, true)
	if mode != "audit_only" || reason != "UNSUPPORTED_ARCH" {
		t.Fatalf("unexpected unsupported arch result: %s %s", mode, reason)
	}

	mode, reason = decideLinuxRuntimeMode(true, true, false, true, true)
	if mode != "audit_only" || reason != "INSUFFICIENT_PRIVILEGES" {
		t.Fatalf("unexpected privilege result: %s %s", mode, reason)
	}

	mode, reason = decideLinuxRuntimeMode(true, true, true, false, true)
	if mode != "audit_only" || reason != "EBPF_PROGRAM_UNAVAILABLE" {
		t.Fatalf("unexpected ebpf result: %s %s", mode, reason)
	}
}

func TestLinuxPolicyConfiguredRequiresPidPlusBlockOrProxy(t *testing.T) {
	if linuxPolicyConfigured(LinuxEnforcerConfig{}) {
		t.Fatalf("expected empty config to be unconfigured")
	}
	if linuxPolicyConfigured(LinuxEnforcerConfig{MonitoredPIDs: []uint32{101}}) {
		t.Fatalf("expected pid-only config to be unconfigured")
	}
	if !linuxPolicyConfigured(LinuxEnforcerConfig{
		MonitoredPIDs: []uint32{101},
		Proxy:         LinuxProxyConfig{Enabled: 1},
	}) {
		t.Fatalf("expected pid-plus-proxy config to be configured")
	}
}

func TestLoadLinuxEnforcerConfigFromEnvAllowsEmptyConfiguration(t *testing.T) {
	config, err := loadLinuxEnforcerConfigFromEnv()
	if err != nil {
		t.Fatalf("expected empty environment to be valid, got %v", err)
	}
	if len(config.MonitoredPIDs) != 0 || len(config.BlockedIPv4) != 0 || config.Proxy.Enabled != 0 {
		t.Fatalf("expected empty config, got %#v", config)
	}
}

func TestLoadLinuxEnforcerConfigFromEnvRejectsInvalidProxyPort(t *testing.T) {
	t.Setenv("GAVEL_PROXY_IPV4", "127.0.0.1")
	t.Setenv("GAVEL_PROXY_PORT", "bad-port")
	if _, err := loadLinuxEnforcerConfigFromEnv(); err == nil {
		t.Fatalf("expected invalid proxy port to fail")
	}
}

func TestLinuxEnforcerConfigFromRuntimePolicyWithoutProxy(t *testing.T) {
	config, err := linuxEnforcerConfigFromRuntimePolicy(RuntimePolicyResponse{MonitoredPIDs: []uint32{77}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(config.MonitoredPIDs) != 1 || config.MonitoredPIDs[0] != 77 {
		t.Fatalf("unexpected monitored pid config: %#v", config)
	}
	if config.Proxy.Enabled != 0 {
		t.Fatalf("expected proxy to remain disabled")
	}
}

// A runtime-generated loader must be eligible for the real attach attempt.
// Actual kernel attach/deny behaviour requires privileged integration testing.
func TestLinuxEBPFProgramReady(t *testing.T) {
	for _, tc := range []struct {
		status string
		want   bool
	}{
		{"runtime-generated", true},
		{"available", true},
		{"unavailable", false},
		{"", false},
	} {
		if got := linuxEBPFProgramReady(tc.status); got != tc.want {
			t.Fatalf("linuxEBPFProgramReady(%q) = %t, want %t", tc.status, got, tc.want)
		}
	}
}
