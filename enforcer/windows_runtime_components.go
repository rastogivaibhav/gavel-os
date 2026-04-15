//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var runWindowsPowerShell = func(script string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run()
}

var startWindowsPowerShellStream = func(script string) (*exec.Cmd, io.ReadCloser, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, stdout, nil
}

type WindowsProcessEvent struct {
	Name        string `json:"Name"`
	CommandLine string `json:"CommandLine"`
	ProcessID   uint32 `json:"ProcessID"`
}

type WindowsNetworkEvent struct {
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    uint16 `json:"RemotePort"`
	ProcessID     uint32 `json:"ProcessID"`
	Source        string `json:"Source,omitempty"`
}

type WindowsProcessMonitor interface {
	Name() string
	Native() bool
	Start(chan<- WindowsProcessEvent) error
	Stop() error
}

type WindowsNetworkMonitor interface {
	Name() string
	Native() bool
	Start(chan<- WindowsNetworkEvent) error
	Stop() error
}

type WindowsTrafficEnforcer interface {
	Name() string
	Native() bool
	ApplyPolicy(RuntimePolicyResponse) error
	IsBlocked(string) bool
	MarkDenied(string)
	Cleanup() error
}

type windowsETWMonitor struct {
	cmd *exec.Cmd
}

func (m *windowsETWMonitor) Name() string { return "etw-process" }
func (m *windowsETWMonitor) Native() bool { return true }
func (m *windowsETWMonitor) Start(events chan<- WindowsProcessEvent) error {
	cmd, stdout, err := startWindowsPowerShellStream(buildWindowsETWMonitorScript())
	if err != nil {
		return err
	}
	m.cmd = cmd
	go decodeWindowsProcessEvents(stdout, events)
	return nil
}
func (m *windowsETWMonitor) Stop() error {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	_ = runWindowsPowerShell("Unregister-Event -SourceIdentifier 'GavelNativeETWMonitor' -ErrorAction SilentlyContinue")
	return nil
}

type windowsTCPIPETWMonitor struct {
	cmd *exec.Cmd
}

func (m *windowsTCPIPETWMonitor) Name() string { return "etw-network" }
func (m *windowsTCPIPETWMonitor) Native() bool { return true }
func (m *windowsTCPIPETWMonitor) Start(events chan<- WindowsNetworkEvent) error {
	cmd, stdout, err := startWindowsPowerShellStream(buildWindowsNetworkMonitorScript())
	if err != nil {
		return err
	}
	m.cmd = cmd
	go decodeWindowsNetworkEvents(stdout, events)
	return nil
}
func (m *windowsTCPIPETWMonitor) Stop() error {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	_ = runWindowsPowerShell("Unregister-Event -SourceIdentifier 'GavelNativeTCPIPMonitor' -ErrorAction SilentlyContinue")
	return nil
}

type windowsWMIFallbackMonitor struct {
	cmd *exec.Cmd
}

func (m *windowsWMIFallbackMonitor) Name() string { return "wmi-fallback" }
func (m *windowsWMIFallbackMonitor) Native() bool { return false }
func (m *windowsWMIFallbackMonitor) Start(events chan<- WindowsProcessEvent) error {
	cmd, err := startWMIProcessStream(events)
	if err != nil {
		return err
	}
	m.cmd = cmd
	return nil
}
func (m *windowsWMIFallbackMonitor) Stop() error {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	_ = runWindowsPowerShell("Unregister-Event -SourceIdentifier 'GavelETWStream' -ErrorAction SilentlyContinue")
	return nil
}

type windowsTCPConnFallbackMonitor struct {
	cmd *exec.Cmd
}

func (m *windowsTCPConnFallbackMonitor) Name() string { return "tcp-fallback" }
func (m *windowsTCPConnFallbackMonitor) Native() bool { return false }
func (m *windowsTCPConnFallbackMonitor) Start(events chan<- WindowsNetworkEvent) error {
	cmd, stdout, err := startWindowsPowerShellStream(buildWindowsTCPConnFallbackScript())
	if err != nil {
		return err
	}
	m.cmd = cmd
	go decodeWindowsNetworkEvents(stdout, events)
	return nil
}
func (m *windowsTCPConnFallbackMonitor) Stop() error {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	return nil
}

type windowsWFPEnforcer struct {
	mu               sync.RWMutex
	blockedTargets   map[string]bool
	hostnameTargets  []string
	lastPolicy       RuntimePolicyResponse
	refreshStop      chan struct{}
	refreshStartOnce sync.Once
	refreshStopOnce  sync.Once
}

var windowsHostnameRefreshInterval = func() time.Duration {
	raw := strings.TrimSpace(os.Getenv("GAVEL_WINDOWS_DNS_REFRESH_INTERVAL"))
	if raw == "" {
		return 5 * time.Minute
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 {
		return 5 * time.Minute
	}
	return duration
}

func newWindowsWFPEnforcer(initial map[string]bool) *windowsWFPEnforcer {
	copied := map[string]bool{}
	for key, value := range initial {
		copied[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return &windowsWFPEnforcer{
		blockedTargets: copied,
		refreshStop:    make(chan struct{}),
	}
}

func (e *windowsWFPEnforcer) Name() string { return "wfp" }
func (e *windowsWFPEnforcer) Native() bool { return true }
func (e *windowsWFPEnforcer) ApplyPolicy(policy RuntimePolicyResponse) error {
	e.mu.Lock()
	if e.blockedTargets == nil {
		e.blockedTargets = map[string]bool{}
	}
	for _, target := range policy.BlockedTargets {
		trimmed := strings.ToLower(strings.TrimSpace(target))
		if trimmed == "" {
			continue
		}
		e.blockedTargets[trimmed] = true
	}
	e.hostnameTargets = windowsFirewallHostnameTargets(policy.BlockedTargets)
	e.lastPolicy = policy
	e.mu.Unlock()
	if err := runWindowsPowerShell(buildWindowsWFPSyncScript(policy.BlockedTargets)); err != nil {
		return err
	}
	e.startHostnameRefreshLoop()
	return nil
}
func (e *windowsWFPEnforcer) IsBlocked(target string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockedTargets[strings.ToLower(strings.TrimSpace(target))]
}
func (e *windowsWFPEnforcer) MarkDenied(target string) {
	trimmed := strings.ToLower(strings.TrimSpace(target))
	if trimmed == "" {
		return
	}
	e.mu.Lock()
	if e.blockedTargets == nil {
		e.blockedTargets = map[string]bool{}
	}
	e.blockedTargets[trimmed] = true
	e.mu.Unlock()
	_ = runWindowsPowerShell(buildWindowsWFPAppendRuleScript(trimmed))
}
func (e *windowsWFPEnforcer) Cleanup() error {
	e.refreshStopOnce.Do(func() {
		if e.refreshStop != nil {
			close(e.refreshStop)
		}
	})
	return runWindowsPowerShell(buildWindowsWFPCleanupScript())
}

func (e *windowsWFPEnforcer) startHostnameRefreshLoop() {
	e.mu.RLock()
	shouldRefresh := len(e.hostnameTargets) > 0
	e.mu.RUnlock()
	if !shouldRefresh {
		return
	}
	interval := windowsHostnameRefreshInterval()
	if interval <= 0 {
		return
	}
	e.refreshStartOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					e.refreshResolvedRules()
				case <-e.refreshStop:
					return
				}
			}
		}()
	})
}

func (e *windowsWFPEnforcer) refreshResolvedRules() {
	e.mu.RLock()
	policy := e.lastPolicy
	e.mu.RUnlock()
	if len(policy.BlockedTargets) == 0 {
		return
	}
	_ = runWindowsPowerShell(buildWindowsWFPSyncScript(policy.BlockedTargets))
}

type windowsUserspaceBlockEnforcer struct {
	mu             sync.RWMutex
	blockedTargets map[string]bool
}

func newWindowsUserspaceBlockEnforcer(initial map[string]bool) *windowsUserspaceBlockEnforcer {
	copied := map[string]bool{}
	for key, value := range initial {
		copied[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return &windowsUserspaceBlockEnforcer{blockedTargets: copied}
}

func (e *windowsUserspaceBlockEnforcer) Name() string { return "userspace-blocklist" }
func (e *windowsUserspaceBlockEnforcer) Native() bool { return false }
func (e *windowsUserspaceBlockEnforcer) ApplyPolicy(policy RuntimePolicyResponse) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, target := range policy.BlockedTargets {
		trimmed := strings.ToLower(strings.TrimSpace(target))
		if trimmed == "" {
			continue
		}
		e.blockedTargets[trimmed] = true
	}
	return nil
}
func (e *windowsUserspaceBlockEnforcer) IsBlocked(target string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockedTargets[strings.ToLower(strings.TrimSpace(target))]
}
func (e *windowsUserspaceBlockEnforcer) MarkDenied(target string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedTargets[strings.ToLower(strings.TrimSpace(target))] = true
}
func (e *windowsUserspaceBlockEnforcer) Cleanup() error { return nil }

func newPreferredWindowsProcessMonitor() WindowsProcessMonitor {
	if strings.EqualFold(os.Getenv("GAVEL_WINDOWS_FORCE_WMI"), "true") {
		return &windowsWMIFallbackMonitor{}
	}
	return &windowsETWMonitor{}
}

func newPreferredWindowsNetworkMonitor() WindowsNetworkMonitor {
	if strings.EqualFold(os.Getenv("GAVEL_WINDOWS_FORCE_TCP_POLL"), "true") {
		return &windowsTCPConnFallbackMonitor{}
	}
	return &windowsTCPIPETWMonitor{}
}

func newPreferredWindowsTrafficEnforcer() WindowsTrafficEnforcer {
	if strings.EqualFold(os.Getenv("GAVEL_WINDOWS_FORCE_USERSPACE_ENFORCER"), "true") {
		return newWindowsUserspaceBlockEnforcer(blockedHosts)
	}
	return newWindowsWFPEnforcer(blockedHosts)
}

func startWindowsProcessMonitor(events chan<- WindowsProcessEvent) (WindowsProcessMonitor, string) {
	monitor := newPreferredWindowsProcessMonitor()
	if err := monitor.Start(events); err == nil {
		if !monitor.Native() {
			return monitor, "process monitor is running in userspace fallback mode"
		}
		return monitor, ""
	} else {
		fallback := &windowsWMIFallbackMonitor{}
		if fallbackErr := fallback.Start(events); fallbackErr != nil {
			return nil, fmt.Sprintf("process monitor unavailable: preferred=%s error=%v fallback=%s error=%v", monitor.Name(), err, fallback.Name(), fallbackErr)
		}
		return fallback, fmt.Sprintf("process monitor fallback active: preferred=%s error=%v fallback=%s", monitor.Name(), err, fallback.Name())
	}
}

func startWindowsNetworkMonitor(events chan<- WindowsNetworkEvent) (WindowsNetworkMonitor, string) {
	monitor := newPreferredWindowsNetworkMonitor()
	if err := monitor.Start(events); err == nil {
		if !monitor.Native() {
			return monitor, "network monitor is running in userspace fallback mode"
		}
		return monitor, ""
	} else {
		fallback := &windowsTCPConnFallbackMonitor{}
		if fallbackErr := fallback.Start(events); fallbackErr != nil {
			return nil, fmt.Sprintf("network monitor unavailable: preferred=%s error=%v fallback=%s error=%v", monitor.Name(), err, fallback.Name(), fallbackErr)
		}
		return fallback, fmt.Sprintf("network monitor fallback active: preferred=%s error=%v fallback=%s", monitor.Name(), err, fallback.Name())
	}
}

func selectWindowsTrafficEnforcer() (WindowsTrafficEnforcer, string) {
	enforcer := newPreferredWindowsTrafficEnforcer()
	if !enforcer.Native() {
		return enforcer, "traffic enforcement is running in userspace fallback mode"
	}
	return enforcer, ""
}

func syncPolicyToWindowsRuntime(policy RuntimePolicyResponse, enforcer WindowsTrafficEnforcer) (WindowsTrafficEnforcer, string) {
	if enforcer != nil {
		if err := enforcer.ApplyPolicy(policy); err == nil {
			applyWindowsRuntimePolicy(policy)
			return enforcer, ""
		}
		fallback := newWindowsUserspaceBlockEnforcer(blockedHosts)
		_ = fallback.ApplyPolicy(policy)
		applyWindowsRuntimePolicy(policy)
		return fallback, fmt.Sprintf("policy sync fell back to userspace enforcement after %s apply failure", enforcer.Name())
	}
	fallback := newWindowsUserspaceBlockEnforcer(blockedHosts)
	_ = fallback.ApplyPolicy(policy)
	applyWindowsRuntimePolicy(policy)
	return fallback, "policy sync started in userspace enforcement because no native enforcer was available"
}

func decodeWindowsProcessEvents(reader io.Reader, events chan<- WindowsProcessEvent) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event WindowsProcessEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		event.Name = strings.ToLower(strings.TrimSpace(event.Name))
		event.CommandLine = strings.ToLower(strings.TrimSpace(event.CommandLine))
		if event.Name == "" {
			continue
		}
		events <- event
	}
}

func decodeWindowsNetworkEvents(reader io.Reader, events chan<- WindowsNetworkEvent) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event WindowsNetworkEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		event.RemoteAddress = normalizeWindowsRemoteAddress(event.RemoteAddress)
		if event.RemoteAddress == "" {
			continue
		}
		event.Source = strings.TrimSpace(event.Source)
		events <- event
	}
}

func buildWindowsETWMonitorScript() string {
	return `
$logName = 'Microsoft-Windows-Kernel-Process/Operational'
try {
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[(EventID=1)]]")
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)
    Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier 'GavelNativeETWMonitor' -Action {
        $record = $Event.SourceEventArgs.EventRecord
        if ($null -eq $record) { return }
        $xml = [xml]$record.ToXml()
        $map = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            $map[[string]$node.Name] = [string]$node.'#text'
        }
        $name = if ($map.ContainsKey('ProcessName')) { $map['ProcessName'] } elseif ($map.ContainsKey('ImageName')) { $map['ImageName'] } else { '' }
        $cmd = if ($map.ContainsKey('CommandLine')) { $map['CommandLine'] } else { '' }
        $pid = 0
        foreach ($candidate in @('ProcessID','ProcessId','PID')) {
            if ($map.ContainsKey($candidate) -and -not [string]::IsNullOrWhiteSpace($map[$candidate])) {
                [void][int]::TryParse($map[$candidate], [ref]$pid)
                break
            }
        }
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        @{ Name = $name.ToLower(); CommandLine = $cmd.ToLower(); ProcessID = $pid } | ConvertTo-Json -Compress
    } | Out-Null
    $watcher.Enabled = $true
    while ($true) { Start-Sleep -Seconds 1 }
}
catch {
    Write-Error $_
    exit 1
}
`
}

func buildWindowsNetworkMonitorScript() string {
	return `
$logName = 'Microsoft-Windows-TCPIP/Operational'
try {
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logName, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
    $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)
    Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier 'GavelNativeTCPIPMonitor' -Action {
        $record = $Event.SourceEventArgs.EventRecord
        if ($null -eq $record) { return }
        $xml = [xml]$record.ToXml()
        $map = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            $map[[string]$node.Name] = [string]$node.'#text'
        }
        $remote = ''
        $remotePort = 0
        $pid = 0
        foreach ($candidate in @('RemoteAddress','daddr','DestAddress','DestinationAddress')) {
            if ($map.ContainsKey($candidate) -and -not [string]::IsNullOrWhiteSpace($map[$candidate])) {
                $remote = $map[$candidate]
                break
            }
        }
        foreach ($candidate in @('RemotePort','DestPort','DestinationPort','dport')) {
            if ($map.ContainsKey($candidate) -and -not [string]::IsNullOrWhiteSpace($map[$candidate])) {
                [void][int]::TryParse($map[$candidate], [ref]$remotePort)
                break
            }
        }
        foreach ($candidate in @('ProcessId','ProcessID','PID')) {
            if ($map.ContainsKey($candidate) -and -not [string]::IsNullOrWhiteSpace($map[$candidate])) {
                [void][int]::TryParse($map[$candidate], [ref]$pid)
                break
            }
        }
        if ([string]::IsNullOrWhiteSpace($remote)) { return }
        @{ RemoteAddress = $remote; RemotePort = $remotePort; ProcessID = $pid; Source = 'etw-tcpip' } | ConvertTo-Json -Compress
    } | Out-Null
    $watcher.Enabled = $true
    while ($true) { Start-Sleep -Seconds 1 }
}
catch {
    Write-Error $_
    exit 1
}
`
}

func buildWindowsTCPConnFallbackScript() string {
	return `
$seen = @{}
while ($true) {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notlike '127.*' -and $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '0.0.0.0' } |
        ForEach-Object {
            $addr = $_.RemoteAddress
            if (-not $seen.ContainsKey($addr)) {
                $seen[$addr] = $true
                @{ RemoteAddress = $addr; RemotePort = $_.RemotePort; ProcessID = $_.OwningProcess; Source = 'tcp-poll' } | ConvertTo-Json -Compress
            }
        }
    Start-Sleep -Seconds 2
}
`
}

func buildWindowsWFPSyncScript(targets []string) string {
	ipTargets := windowsFirewallIPTargets(targets)
	hostnameTargets := windowsFirewallHostnameTargets(targets)
	lines := []string{
		"$group = 'Gavel Shield'",
		"Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null",
	}
	for _, target := range ipTargets {
		lines = append(lines, windowsFirewallRuleCommand(target))
	}
	if len(hostnameTargets) > 0 {
		quotedTargets := []string{}
		for _, target := range hostnameTargets {
			quotedTargets = append(quotedTargets, "'"+psSingleQuoted(target)+"'")
		}
		lines = append(lines,
			"$hostnameTargets = @("+strings.Join(quotedTargets, ", ")+")",
			"foreach ($hostname in $hostnameTargets) {",
			"  try {",
			"    Resolve-DnsName -Name $hostname -ErrorAction Stop |",
			"      Where-Object { $_.IPAddress } |",
			"      ForEach-Object {",
			"        $resolved = $_.IPAddress",
			"        if (-not [string]::IsNullOrWhiteSpace($resolved)) {",
			"          New-NetFirewallRule -DisplayName ('Gavel Shield Block ' + ($hostname + ' ' + $resolved).Replace('.', '_').Replace(':', '_').Replace('/', '_')) -DisplayGroup 'Gavel Shield' -Direction Outbound -Action Block -RemoteAddress $resolved -Profile Any -ErrorAction SilentlyContinue | Out-Null",
			"        }",
			"      }",
			"  } catch {",
			"    Write-Verbose ('Failed to resolve ' + $hostname)",
			"  }",
			"}",
		)
	}
	return strings.Join(lines, "\n")
}

func buildWindowsWFPCleanupScript() string {
	return "$group = 'Gavel Shield'; Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null"
}

func buildWindowsWFPAppendRuleScript(target string) string {
	if isWindowsFirewallAddressTarget(target) {
		return windowsFirewallRuleCommand(target)
	}
	if !isWindowsFirewallHostnameTarget(target) {
		return "$null = $null"
	}
	safeTarget := psSingleQuoted(strings.TrimSpace(target))
	return strings.Join([]string{
		"$hostname = '" + safeTarget + "'",
		"try {",
		"  Resolve-DnsName -Name $hostname -ErrorAction Stop |",
		"    Where-Object { $_.IPAddress } |",
		"    ForEach-Object {",
		"      $resolved = $_.IPAddress",
		"      if (-not [string]::IsNullOrWhiteSpace($resolved)) {",
		"        New-NetFirewallRule -DisplayName ('Gavel Shield Block ' + ($hostname + ' ' + $resolved).Replace('.', '_').Replace(':', '_').Replace('/', '_')) -DisplayGroup 'Gavel Shield' -Direction Outbound -Action Block -RemoteAddress $resolved -Profile Any -ErrorAction SilentlyContinue | Out-Null",
		"      }",
		"    }",
		"} catch {",
		"  Write-Verbose ('Failed to resolve ' + $hostname)",
		"}",
	}, "\n")
}

func windowsFirewallRuleCommand(target string) string {
	safeTarget := psSingleQuoted(target)
	ruleName := psSingleQuoted("Gavel Shield Block " + sanitizeWindowsRuleName(target))
	return fmt.Sprintf(
		"New-NetFirewallRule -DisplayName '%s' -DisplayGroup 'Gavel Shield' -Direction Outbound -Action Block -RemoteAddress '%s' -Profile Any -ErrorAction SilentlyContinue | Out-Null",
		ruleName,
		safeTarget,
	)
}

func windowsFirewallIPTargets(targets []string) []string {
	seen := map[string]bool{}
	filtered := []string{}
	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if !isWindowsFirewallAddressTarget(trimmed) {
			continue
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		filtered = append(filtered, trimmed)
	}
	return filtered
}

func windowsFirewallHostnameTargets(targets []string) []string {
	seen := map[string]bool{}
	filtered := []string{}
	for _, target := range targets {
		trimmed := strings.ToLower(strings.TrimSpace(target))
		if !isWindowsFirewallHostnameTarget(trimmed) {
			continue
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		filtered = append(filtered, trimmed)
	}
	return filtered
}

func isWindowsFirewallAddressTarget(target string) bool {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "/") {
		_, _, err := net.ParseCIDR(trimmed)
		return err == nil
	}
	return net.ParseIP(trimmed) != nil
}

func isWindowsFirewallHostnameTarget(target string) bool {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" || strings.Contains(trimmed, " ") {
		return false
	}
	if isWindowsFirewallAddressTarget(trimmed) {
		return false
	}
	return strings.Contains(trimmed, ".")
}

func sanitizeWindowsRuleName(target string) string {
	replacer := strings.NewReplacer(".", "_", ":", "_", "/", "_")
	return replacer.Replace(strings.TrimSpace(target))
}

func psSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func normalizeWindowsRemoteAddress(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "[")
	trimmed = strings.TrimSuffix(trimmed, "]")
	if index := strings.Index(trimmed, "%"); index >= 0 {
		trimmed = trimmed[:index]
	}
	return strings.TrimSpace(trimmed)
}
