//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDetectSuspiciousCommandsReturnsKeywordOnly(t *testing.T) {
	proc := WindowsProcessEvent{Name: "cmd.exe", CommandLine: "powershell -c whoami /all"}
	got := detectSuspiciousCommands(proc)
	if got != "whoami" {
		t.Fatalf("expected whoami, got %q", got)
	}
}

func TestRuntimeModeFallsBackToAuditOnlyWithoutMachineKey(t *testing.T) {
	t.Setenv("GAVEL_MACHINE_KEY", "")
	t.Setenv("GAVEL_WINDOWS_MODE", "")

	if mode := runtimeMode(); mode != "audit_only" {
		t.Fatalf("expected audit_only, got %q", mode)
	}
}

func TestMergeWindowsProcessWatchListDeduplicatesAndNormalizes(t *testing.T) {
	merged := mergeWindowsProcessWatchList(
		[]string{"cursor", "Codex"},
		[]string{" cursor ", "Aider", "codex"},
	)

	if len(merged) != 3 {
		t.Fatalf("expected 3 merged entries, got %#v", merged)
	}
	if merged[0] != "cursor" || merged[1] != "codex" || merged[2] != "aider" {
		t.Fatalf("unexpected merged watch list: %#v", merged)
	}
}

func TestSyncPolicyToWindowsRuntimeFallsBackToUserspaceEnforcer(t *testing.T) {
	originalRunner := runWindowsPowerShell
	runWindowsPowerShell = func(string) error { return errors.New("wfp unavailable") }
	defer func() { runWindowsPowerShell = originalRunner }()

	enforcer, warning := syncPolicyToWindowsRuntime(
		RuntimePolicyResponse{
			BlockedTargets:     []string{"analytics.google.com"},
			MonitoredProcesses: []string{"Cursor"},
		},
		&windowsWFPEnforcer{},
	)

	if enforcer == nil {
		t.Fatalf("expected fallback enforcer")
	}
	if enforcer.Name() != "userspace-blocklist" {
		t.Fatalf("expected userspace fallback, got %q", enforcer.Name())
	}
	if !enforcer.IsBlocked("analytics.google.com") {
		t.Fatalf("expected synced blocked target to be enforced")
	}
	if !strings.Contains(warning, "fell back to userspace enforcement") {
		t.Fatalf("expected fallback warning, got %q", warning)
	}
}

func TestBuildWindowsWFPSyncScriptIncludesOnlyIPTargets(t *testing.T) {
	script := buildWindowsWFPSyncScript([]string{"10.0.0.1", "analytics.google.com", "192.168.0.0/24"})

	if !strings.Contains(script, "10.0.0.1") {
		t.Fatalf("expected IPv4 target in script: %s", script)
	}
	if !strings.Contains(script, "192.168.0.0/24") {
		t.Fatalf("expected CIDR target in script: %s", script)
	}
	if strings.Contains(script, "-RemoteAddress 'analytics.google.com'") {
		t.Fatalf("did not expect hostname target to be used as a raw firewall address: %s", script)
	}
	if !strings.Contains(script, "Resolve-DnsName") || !strings.Contains(script, "analytics.google.com") {
		t.Fatalf("expected hostname resolution path in script: %s", script)
	}
}

func TestBuildWindowsWFPCleanupScriptRemovesRuleGroup(t *testing.T) {
	script := buildWindowsWFPCleanupScript()
	if !strings.Contains(script, "Remove-NetFirewallRule") {
		t.Fatalf("expected cleanup script to remove firewall rules")
	}
	if !strings.Contains(script, "Gavel Shield") {
		t.Fatalf("expected cleanup script to target the Gavel Shield rule group")
	}
}

func TestWindowsWFPEnforcerApplyPolicyUsesPowerShellRunner(t *testing.T) {
	originalRunner := runWindowsPowerShell
	originalInterval := windowsHostnameRefreshInterval
	captured := ""
	runWindowsPowerShell = func(script string) error {
		captured = script
		return nil
	}
	windowsHostnameRefreshInterval = func() time.Duration { return 0 }
	defer func() {
		runWindowsPowerShell = originalRunner
		windowsHostnameRefreshInterval = originalInterval
	}()

	enforcer := newWindowsWFPEnforcer(map[string]bool{})
	if err := enforcer.ApplyPolicy(RuntimePolicyResponse{BlockedTargets: []string{"10.0.0.1", "cursor.com"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured == "" || !strings.Contains(captured, "New-NetFirewallRule") {
		t.Fatalf("expected firewall rule script, got %q", captured)
	}
	if !enforcer.IsBlocked("10.0.0.1") || !enforcer.IsBlocked("cursor.com") {
		t.Fatalf("expected enforcer to track blocked targets")
	}
}

func TestWindowsWFPEnforcerRefreshResolvedRulesReplaysLastPolicy(t *testing.T) {
	originalRunner := runWindowsPowerShell
	originalInterval := windowsHostnameRefreshInterval
	calls := 0
	lastScript := ""
	runWindowsPowerShell = func(script string) error {
		calls++
		lastScript = script
		return nil
	}
	windowsHostnameRefreshInterval = func() time.Duration { return 0 }
	defer func() {
		runWindowsPowerShell = originalRunner
		windowsHostnameRefreshInterval = originalInterval
	}()

	enforcer := newWindowsWFPEnforcer(map[string]bool{})
	if err := enforcer.ApplyPolicy(RuntimePolicyResponse{BlockedTargets: []string{"api.example.com"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	enforcer.refreshResolvedRules()

	if calls != 2 {
		t.Fatalf("expected initial sync plus refresh, got %d calls", calls)
	}
	if !strings.Contains(lastScript, "Resolve-DnsName") || !strings.Contains(lastScript, "api.example.com") {
		t.Fatalf("expected refresh to replay hostname resolution policy, got %q", lastScript)
	}
}

func TestWindowsHostnameRefreshIntervalParsesEnv(t *testing.T) {
	original := windowsHostnameRefreshInterval
	defer func() { windowsHostnameRefreshInterval = original }()

	t.Setenv("GAVEL_WINDOWS_DNS_REFRESH_INTERVAL", "90s")
	if got := windowsHostnameRefreshInterval(); got != 90*time.Second {
		t.Fatalf("expected 90s, got %v", got)
	}
}

func TestWindowsWFPEnforcerCleanupUsesPowerShellRunner(t *testing.T) {
	originalRunner := runWindowsPowerShell
	captured := ""
	runWindowsPowerShell = func(script string) error {
		captured = script
		return nil
	}
	defer func() { runWindowsPowerShell = originalRunner }()

	enforcer := newWindowsWFPEnforcer(map[string]bool{"10.0.0.1": true})
	if err := enforcer.Cleanup(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(captured, "Remove-NetFirewallRule") {
		t.Fatalf("expected cleanup script, got %q", captured)
	}
}

func TestBuildWindowsETWMonitorScriptTargetsKernelProcessChannel(t *testing.T) {
	script := buildWindowsETWMonitorScript()
	if !strings.Contains(script, "Microsoft-Windows-Kernel-Process/Operational") {
		t.Fatalf("expected ETW monitor script to target kernel process log")
	}
	if !strings.Contains(script, "EventLogWatcher") {
		t.Fatalf("expected ETW watcher implementation in script")
	}
	if !strings.Contains(script, "ProcessID") {
		t.Fatalf("expected process id extraction in ETW script")
	}
}

func TestBuildWindowsNetworkMonitorScriptTargetsTCPIPChannel(t *testing.T) {
	script := buildWindowsNetworkMonitorScript()
	if !strings.Contains(script, "Microsoft-Windows-TCPIP/Operational") {
		t.Fatalf("expected network monitor script to target TCPIP operational log")
	}
	if !strings.Contains(script, "RemoteAddress") {
		t.Fatalf("expected network monitor script to emit remote addresses")
	}
	if !strings.Contains(script, "ProcessID") || !strings.Contains(script, "RemotePort") {
		t.Fatalf("expected process id and remote port extraction in network monitor script")
	}
}

func TestDecodeWindowsNetworkEventsParsesJSONLines(t *testing.T) {
	reader := strings.NewReader("{\"RemoteAddress\":\"10.0.0.1\",\"RemotePort\":443,\"ProcessID\":1234,\"Source\":\"etw-tcpip\"}\n{\"RemoteAddress\":\"\"}\n")
	events := make(chan WindowsNetworkEvent, 2)
	decodeWindowsNetworkEvents(reader, events)
	close(events)

	count := 0
	for event := range events {
		count++
		if event.RemoteAddress != "10.0.0.1" {
			t.Fatalf("unexpected remote address: %#v", event)
		}
		if event.ProcessID != 1234 || event.RemotePort != 443 || event.Source != "etw-tcpip" {
			t.Fatalf("unexpected event detail: %#v", event)
		}
	}
	if count != 1 {
		t.Fatalf("expected one parsed network event, got %d", count)
	}
}

func TestDecodeWindowsProcessEventsParsesProcessID(t *testing.T) {
	reader := strings.NewReader("{\"Name\":\"cursor.exe\",\"CommandLine\":\"cursor --agent\",\"ProcessID\":4512}\n")
	events := make(chan WindowsProcessEvent, 1)
	decodeWindowsProcessEvents(reader, events)
	close(events)

	event, ok := <-events
	if !ok {
		t.Fatalf("expected one process event")
	}
	if event.Name != "cursor.exe" || event.ProcessID != 4512 {
		t.Fatalf("unexpected process event: %#v", event)
	}
}

func TestBuildWindowsWFPAppendRuleScriptResolvesHostnameTargets(t *testing.T) {
	script := buildWindowsWFPAppendRuleScript("api.example.com")
	if !strings.Contains(script, "Resolve-DnsName") {
		t.Fatalf("expected hostname resolution in append script: %s", script)
	}
	if !strings.Contains(script, "api.example.com") {
		t.Fatalf("expected hostname in append script: %s", script)
	}
}

func TestNormalizeWindowsRemoteAddressStripsIPv6Decorations(t *testing.T) {
	got := normalizeWindowsRemoteAddress("[fe80::1%12]")
	if got != "fe80::1" {
		t.Fatalf("expected normalized IPv6 address, got %q", got)
	}
}

func TestSelectWindowsTrafficEnforcerCanReportUserspaceFallback(t *testing.T) {
	t.Setenv("GAVEL_WINDOWS_FORCE_USERSPACE_ENFORCER", "true")

	enforcer, warning := selectWindowsTrafficEnforcer()
	if enforcer == nil {
		t.Fatalf("expected enforcer")
	}
	if enforcer.Name() != "userspace-blocklist" {
		t.Fatalf("expected userspace enforcer, got %q", enforcer.Name())
	}
	if !strings.Contains(warning, "userspace fallback mode") {
		t.Fatalf("expected userspace warning, got %q", warning)
	}
}
