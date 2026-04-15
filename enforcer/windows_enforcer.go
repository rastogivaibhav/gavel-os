//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	heartbeatInterval = 30 * time.Second
)

var knownAgentProcesses = []string{
	"copilot",
	"cursor",
	"aider",
	"cline",
	"continue",
	"supermaven",
	"tabnine",
	"windsurf",
	"codex",
	"gpt-pilot",
}

var blockedHosts = map[string]bool{
	"suspicious-api.io":    true,
	"doubleclick.net":      true,
	"analytics.google.com": true,
}

type RuntimeValidateRequest struct {
	HostID             string `json:"host_id"`
	RuntimeOS          string `json:"runtime_os"`
	RuntimeArch        string `json:"runtime_arch"`
	RuntimeMode        string `json:"runtime_mode"`
	EnforcementCapable bool   `json:"enforcement_capable"`
	Action             string `json:"action"`
	Method             string `json:"method"`
	TargetTenantID     string `json:"target_tenant_id"`
	RequiredClearance  int    `json:"required_clearance"`
	AgentID            string `json:"agent_id"`
}

type RuntimeHeartbeatRequest struct {
	HostID             string `json:"host_id"`
	RuntimeOS          string `json:"runtime_os"`
	RuntimeArch        string `json:"runtime_arch"`
	RuntimeMode        string `json:"runtime_mode"`
	EnforcementCapable bool   `json:"enforcement_capable"`
	AuthStatus         string `json:"auth_status,omitempty"`
	ControlPlaneStatus string `json:"control_plane_status,omitempty"`
	Component          string `json:"component"`
}

type RuntimeEvent struct {
	EventType   string                 `json:"event_type"`
	EventTime   string                 `json:"event_time"`
	HostID      string                 `json:"host_id"`
	RuntimeOS   string                 `json:"runtime_os"`
	RuntimeArch string                 `json:"runtime_arch"`
	AgentID     string                 `json:"agent_id,omitempty"`
	Target      string                 `json:"target"`
	Verdict     string                 `json:"verdict"`
	ReasonCode  string                 `json:"reason_code"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type AgentDetectionRequest struct {
	HostID             string                 `json:"host_id"`
	RuntimeOS          string                 `json:"runtime_os"`
	RuntimeArch        string                 `json:"runtime_arch"`
	RuntimeMode        string                 `json:"runtime_mode"`
	EnforcementCapable bool                   `json:"enforcement_capable"`
	AgentID            string                 `json:"agent_id"`
	Target             string                 `json:"target"`
	ReasonCode         string                 `json:"reason_code"`
	Metadata           map[string]interface{} `json:"metadata"`
}

type RuntimeState struct {
	Mode               string
	EnforcementCapable bool
	AuthStatus         string
}

func main() {
	log.SetPrefix("[GAVEL-SHIELD-WIN] ")
	state := currentRuntimeState()
	log.Printf(
		"Gavel Shield starting on %s/%s mode=%s enforcement_capable=%t auth_status=%s",
		runtime.GOOS,
		runtime.GOARCH,
		state.Mode,
		state.EnforcementCapable,
		state.AuthStatus,
	)
	enforcer, enforcerWarning := selectWindowsTrafficEnforcer()
	enforcer, policyWarning := syncWindowsRuntimePolicy(enforcer)

	stop := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go heartbeatLoop(done)

	processStream := make(chan WindowsProcessEvent, 100)
	monitor, processWarning := startWindowsProcessMonitor(processStream)
	if monitor == nil {
		log.Printf("No process monitor is available; running in audit-only visibility mode")
	} else {
		log.Printf("Using Windows process monitor provider=%s native=%t", monitor.Name(), monitor.Native())
	}
	networkStream := make(chan WindowsNetworkEvent, 100)
	networkMonitor, networkWarning := startWindowsNetworkMonitor(networkStream)
	if networkMonitor == nil {
		log.Printf("No network monitor is available; runtime cannot observe outbound traffic")
	} else {
		log.Printf("Using Windows network monitor provider=%s native=%t", networkMonitor.Name(), networkMonitor.Native())
	}
	reportWindowsProviderStatus(monitor, networkMonitor, enforcer, processWarning, networkWarning, enforcerWarning, policyWarning)

	reportedAgents := map[string]bool{}
	knownAgentSeen := false
	monitoredPIDs := map[uint32]string{}
	var agentStateMu sync.RWMutex

	go func() {
		for proc := range processStream {
			if proc.CommandLine == "" || proc.Name == "powershell.exe" {
				continue
			}

			if suspicious := detectSuspiciousCommands(proc); suspicious != "" {
				eventKey := "cmd:" + suspicious
				if !reportedAgents[eventKey] {
					target := "suspicious_command:" + suspicious
					log.Printf("Suspicious command detected for %s", target)
					pushTelemetry("network_verdict", target, runtimeVerdict(), "SUSPICIOUS_COMMAND", map[string]interface{}{
						"component":           "windows-runtime",
						"target_kind":         "command",
						"runtime_mode":        currentRuntimeState().Mode,
						"enforcement_capable": currentRuntimeState().EnforcementCapable,
					})
					reportedAgents[eventKey] = true
				}
				continue
			}

			agentDetected := false
			for _, agent := range knownAgentProcesses {
				if strings.Contains(proc.Name, agent) || strings.Contains(proc.CommandLine, agent) {
					agentDetected = true
					if !reportedAgents[proc.Name] {
						log.Printf("Detected AI agent process: %s", proc.Name)
						reportAgentDetection(proc.Name)
						reportedAgents[proc.Name] = true
					}
					agentStateMu.Lock()
					knownAgentSeen = true
					if proc.ProcessID != 0 {
						monitoredPIDs[proc.ProcessID] = proc.Name
					}
					agentStateMu.Unlock()
					break
				}
			}
			_ = agentDetected
		}
	}()

	go func() {
		for event := range networkStream {
			host := strings.TrimSpace(event.RemoteAddress)
			if host == "" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "::1") || strings.HasPrefix(host, "0.") {
				continue
			}

			agentStateMu.RLock()
			activeAgentSeen := knownAgentSeen
			_, pidTracked := monitoredPIDs[event.ProcessID]
			agentStateMu.RUnlock()
			if event.ProcessID != 0 && !pidTracked {
				continue
			}
			if event.ProcessID == 0 && !activeAgentSeen {
				continue
			}

			reasonCode := "POLICY_ALLOW"
			verdict := "ALLOW"
			if enforcer != nil && enforcer.IsBlocked(host) {
				verdict = runtimeVerdict()
				reasonCode = "LOCAL_BLOCKLIST"
			} else {
				allowed, denyReasonCode, controlPlaneStatus := validateWithGovernor(host)
				if !allowed {
					verdict = runtimeVerdict()
					reasonCode = denyReasonCode
					if controlPlaneStatus == "online" || !shouldFailOpen() {
						if enforcer != nil {
							enforcer.MarkDenied(host)
						}
					}
					log.Printf("Governor denied connection to %s reason=%s", host, reasonCode)
				}
			}

			pushTelemetry("network_verdict", host, verdict, reasonCode, map[string]interface{}{
				"component":           "windows-runtime",
				"target_kind":         "network",
				"process_id":          event.ProcessID,
				"remote_port":         event.RemotePort,
				"network_source":      event.Source,
				"runtime_mode":        currentRuntimeState().Mode,
				"enforcement_capable": currentRuntimeState().EnforcementCapable,
			})
		}
	}()

	log.Println("Gavel Shield active. Press Ctrl+C to stop.")
	<-stop
	close(done)
	if monitor != nil {
		_ = monitor.Stop()
	}
	if networkMonitor != nil {
		_ = networkMonitor.Stop()
	}
	if enforcer != nil {
		_ = enforcer.Cleanup()
	}
	log.Println("Gavel Shield shutting down.")
}

func currentRuntimeState() RuntimeState {
	mode := runtimeMode()
	return RuntimeState{
		Mode:               mode,
		EnforcementCapable: supportsNativeEnforcement(),
		AuthStatus:         authStatus(),
	}
}

func runtimeHostID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "windows-host"
	}
	sum := sha256.Sum256([]byte(host + ":" + runtime.GOARCH))
	return hex.EncodeToString(sum[:8])
}

func machineKey() string {
	return os.Getenv("GAVEL_MACHINE_KEY")
}

func authStatus() string {
	if machineKey() == "" {
		return "missing_machine_key"
	}
	return "authenticated"
}

func supportsNativeEnforcement() bool {
	return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64"
}

func runtimeMode() string {
	if strings.EqualFold(os.Getenv("GAVEL_WINDOWS_MODE"), "audit_only") {
		return "audit_only"
	}
	if !supportsNativeEnforcement() || machineKey() == "" {
		return "audit_only"
	}
	return "enforce"
}

func runtimeVerdict() string {
	if runtimeMode() == "audit_only" {
		return "AUDIT"
	}
	return "DENY"
}

func syncWindowsRuntimePolicy(enforcer WindowsTrafficEnforcer) (WindowsTrafficEnforcer, string) {
	state := currentRuntimeState()
	if machineKey() == "" {
		return enforcer, "runtime policy sync skipped because machine authentication is not configured"
	}

	policy, err := fetchRuntimePolicy(
		runtimeHostID(),
		runtime.GOOS,
		runtime.GOARCH,
		state.Mode,
		state.EnforcementCapable,
		"windows-runtime",
		"windows-runtime",
	)
	if err != nil {
		log.Printf("Failed to sync runtime policy: %v", err)
		return enforcer, "runtime policy sync failed and the runtime is using last-known local state"
	}
	return syncPolicyToWindowsRuntime(policy, enforcer)
}

func applyWindowsRuntimePolicy(policy RuntimePolicyResponse) {
	for _, target := range policy.BlockedTargets {
		trimmed := strings.ToLower(strings.TrimSpace(target))
		if trimmed == "" {
			continue
		}
		blockedHosts[trimmed] = true
	}
	if len(policy.MonitoredProcesses) > 0 {
		knownAgentProcesses = mergeWindowsProcessWatchList(knownAgentProcesses, policy.MonitoredProcesses)
	}
}

func mergeWindowsProcessWatchList(base []string, extra []string) []string {
	seen := map[string]bool{}
	merged := []string{}

	for _, candidate := range append(append([]string{}, base...), extra...) {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		merged = append(merged, normalized)
	}

	return merged
}

func shouldFailOpen() bool {
	return strings.EqualFold(os.Getenv("GAVEL_FAIL_OPEN"), "true")
}

func governorURL() string {
	if value := os.Getenv("GAVEL_ENGINE_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return "http://localhost:8000"
}

func detectSuspiciousCommands(proc WindowsProcessEvent) string {
	suspicious := []string{"ipconfig", "whoami", "net user", "curl ", "wget ", "tracert", "ping "}
	for _, value := range suspicious {
		if strings.Contains(proc.CommandLine, value) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func postJSON(path string, payload interface{}) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, governorURL()+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := machineKey(); key != "" {
		req.Header.Set("X-Gavel-Machine-Key", key)
	}
	req.Header.Set("X-Gavel-Host-Id", runtimeHostID())

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Do(req)
}

func validateWithGovernor(host string) (bool, string, string) {
	state := currentRuntimeState()
	req := RuntimeValidateRequest{
		HostID:             runtimeHostID(),
		RuntimeOS:          runtime.GOOS,
		RuntimeArch:        runtime.GOARCH,
		RuntimeMode:        state.Mode,
		EnforcementCapable: state.EnforcementCapable,
		Action:             host,
		Method:             "CONNECT",
		TargetTenantID:     "default",
		RequiredClearance:  1,
		AgentID:            "windows-runtime",
	}
	resp, err := postJSON("/external/runtime/validate", req)
	if err != nil {
		log.Printf("Failed to reach governor for %s: %v", host, err)
		if shouldFailOpen() {
			return true, "CONTROL_PLANE_UNAVAILABLE", "degraded"
		}
		return false, "CONTROL_PLANE_UNAVAILABLE", "degraded"
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if shouldFailOpen() {
			return true, "CONTROL_PLANE_UNAVAILABLE", "degraded"
		}
		return false, "CONTROL_PLANE_UNAVAILABLE", "degraded"
	}

	allowed, _ := result["is_allowed"].(bool)
	reasonCode, _ := result["reason_code"].(string)
	controlPlaneStatus, _ := result["control_plane_status"].(string)
	if reasonCode == "" {
		reasonCode = "POLICY_ALLOW"
	}
	if controlPlaneStatus == "" {
		controlPlaneStatus = "online"
	}
	return allowed, reasonCode, controlPlaneStatus
}

func pushTelemetry(eventType, target, verdict, reasonCode string, metadata map[string]interface{}) {
	event := RuntimeEvent{
		EventType:   eventType,
		EventTime:   time.Now().UTC().Format(time.RFC3339),
		HostID:      runtimeHostID(),
		RuntimeOS:   runtime.GOOS,
		RuntimeArch: runtime.GOARCH,
		AgentID:     "windows-runtime",
		Target:      target,
		Verdict:     verdict,
		ReasonCode:  reasonCode,
		Metadata:    metadata,
	}

	resp, err := postJSON("/internal/telemetry/push", event)
	if err != nil {
		log.Printf("Failed to push telemetry: %v", err)
		return
	}
	resp.Body.Close()
}

func reportAgentDetection(agentName string) {
	state := currentRuntimeState()
	req := AgentDetectionRequest{
		HostID:             runtimeHostID(),
		RuntimeOS:          runtime.GOOS,
		RuntimeArch:        runtime.GOARCH,
		RuntimeMode:        state.Mode,
		EnforcementCapable: state.EnforcementCapable,
		AgentID:            agentName,
		Target:             "local-agent",
		ReasonCode:         "AGENT_DETECTED",
		Metadata: map[string]interface{}{
			"component":           "windows-runtime",
			"runtime_mode":        state.Mode,
			"enforcement_capable": state.EnforcementCapable,
		},
	}

	resp, err := postJSON("/external/detect_agent", req)
	if err != nil {
		log.Printf("Failed to report agent detection for %s: %v", agentName, err)
		return
	}
	resp.Body.Close()
}

func heartbeatLoop(done <-chan struct{}) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	sendHeartbeat("starting")
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			sendHeartbeat("online")
		}
	}
}

func sendHeartbeat(controlPlaneStatus string) {
	if machineKey() == "" {
		log.Printf("Skipping heartbeat: machine authentication is not configured")
		return
	}
	state := currentRuntimeState()
	req := RuntimeHeartbeatRequest{
		HostID:             runtimeHostID(),
		RuntimeOS:          runtime.GOOS,
		RuntimeArch:        runtime.GOARCH,
		RuntimeMode:        state.Mode,
		EnforcementCapable: state.EnforcementCapable,
		AuthStatus:         state.AuthStatus,
		ControlPlaneStatus: controlPlaneStatus,
		Component:          "windows-runtime",
	}
	resp, err := postJSON("/external/heartbeat", req)
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}
	resp.Body.Close()
}

func reportWindowsProviderStatus(
	processMonitor WindowsProcessMonitor,
	networkMonitor WindowsNetworkMonitor,
	enforcer WindowsTrafficEnforcer,
	warnings ...string,
) {
	filteredWarnings := []string{}
	for _, warning := range warnings {
		trimmed := strings.TrimSpace(warning)
		if trimmed == "" {
			continue
		}
		filteredWarnings = append(filteredWarnings, trimmed)
		log.Printf("Windows runtime diagnostic: %s", trimmed)
	}

	processName, processNative := providerIdentity(processMonitor)
	networkName, networkNative := providerIdentity(networkMonitor)
	enforcerName, enforcerNative := trafficEnforcerIdentity(enforcer)
	reasonCode := "RUNTIME_READY"
	if len(filteredWarnings) > 0 {
		reasonCode = "RUNTIME_FALLBACK"
	}

	if machineKey() == "" {
		return
	}

	pushTelemetry("component_health", "windows-runtime", "ALLOW", reasonCode, map[string]interface{}{
		"component":                "windows-runtime",
		"runtime_mode":             currentRuntimeState().Mode,
		"enforcement_capable":      currentRuntimeState().EnforcementCapable,
		"process_monitor":          processName,
		"process_monitor_native":   processNative,
		"network_monitor":          networkName,
		"network_monitor_native":   networkNative,
		"traffic_enforcer":         enforcerName,
		"traffic_enforcer_native":  enforcerNative,
		"diagnostic_warnings":      filteredWarnings,
		"provider_fallback_active": len(filteredWarnings) > 0,
	})
}

func providerIdentity(provider interface{}) (string, bool) {
	switch value := provider.(type) {
	case WindowsProcessMonitor:
		if value == nil {
			return "unavailable", false
		}
		return value.Name(), value.Native()
	case WindowsNetworkMonitor:
		if value == nil {
			return "unavailable", false
		}
		return value.Name(), value.Native()
	default:
		return "unavailable", false
	}
}

func trafficEnforcerIdentity(enforcer WindowsTrafficEnforcer) (string, bool) {
	if enforcer == nil {
		return "unavailable", false
	}
	return enforcer.Name(), enforcer.Native()
}

func startWMIProcessStream(events chan<- WindowsProcessEvent) (*exec.Cmd, error) {
	script := `
$Query = "SELECT * FROM __InstanceCreationEvent WITHIN 0.1 WHERE TargetInstance ISA 'Win32_Process'"
$Action = {
    $proc = $Event.SourceEventArgs.NewEvent.TargetInstance
    @{ Name = $proc.Name; CommandLine = $proc.CommandLine; ProcessID = [int]$proc.ProcessId } | ConvertTo-Json -Compress
}
Register-WmiEvent -Query $Query -SourceIdentifier "GavelETWStream" -Action $Action | Out-Null
while ($true) { Start-Sleep -Milliseconds 250 }
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	go func() {
		defer cmd.Process.Kill()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(line, "Name") || !strings.Contains(line, "CommandLine") {
				continue
			}
			var proc WindowsProcessEvent
			if err := json.Unmarshal([]byte(line), &proc); err != nil {
				continue
			}
			proc.Name = strings.ToLower(strings.TrimSpace(proc.Name))
			proc.CommandLine = strings.ToLower(strings.TrimSpace(proc.CommandLine))
			if proc.Name == "" {
				continue
			}
			events <- proc
		}
	}()

	return cmd, nil
}
