//go:build darwin

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const darwinHeartbeatInterval = 30 * time.Second

type DarwinHeartbeatRequest struct {
	HostID             string `json:"host_id"`
	RuntimeOS          string `json:"runtime_os"`
	RuntimeArch        string `json:"runtime_arch"`
	RuntimeMode        string `json:"runtime_mode"`
	EnforcementCapable bool   `json:"enforcement_capable"`
	AuthStatus         string `json:"auth_status,omitempty"`
	ControlPlaneStatus string `json:"control_plane_status,omitempty"`
	Component          string `json:"component"`
}

type DarwinRuntimeEvent struct {
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

type DarwinRuntimeStatus struct {
	Mode                  string
	EnforcementCapable    bool
	AuthStatus            string
	ControlPlaneStatus    string
	ReasonCode            string
	PolicyVersion         string
	BlockedTargetCount    int
	MonitoredProcessCount int
}

func main() {
	statusOnly := flag.Bool("status", false, "print audit-only runtime status and exit")
	flag.Parse()

	log.SetPrefix("[GAVEL-SHIELD-MAC] ")
	status := resolveDarwinRuntimeStatus()
	if *statusOnly {
		printDarwinStatus(status)
		return
	}
	log.Printf(
		"Gavel Shield (macOS) starting on %s/%s mode=%s control_plane_status=%s auth_status=%s reason=%s",
		runtime.GOOS,
		runtime.GOARCH,
		status.Mode,
		status.ControlPlaneStatus,
		status.AuthStatus,
		status.ReasonCode,
	)
	log.Printf(
		"macOS runtime is audit-only. policy_version=%s blocked_targets=%d monitored_processes=%d",
		status.PolicyVersion,
		status.BlockedTargetCount,
		status.MonitoredProcessCount,
	)
	log.Println("Network Extension/System Extension enforcement remains a later increment; this runtime currently reports audit-only readiness and control-plane connectivity.")

	done := make(chan struct{})
	go darwinHeartbeatLoop(done, status)
	emitDarwinTelemetry("component_health", "darwin-runtime", "AUDIT", status.ReasonCode, map[string]interface{}{
		"component":             "darwin-runtime",
		"runtime_mode":          status.Mode,
		"control_plane_status":  status.ControlPlaneStatus,
		"policy_version":        status.PolicyVersion,
		"blocked_target_count":  status.BlockedTargetCount,
		"monitored_proc_count":  status.MonitoredProcessCount,
		"enforcement_capable":   status.EnforcementCapable,
		"system_extension_mode": "planned",
	})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	close(done)
	log.Println("Gavel Shield (macOS) shutting down.")
}

func printDarwinStatus(status DarwinRuntimeStatus) {
	payload, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		log.Printf("failed to encode darwin status output: %v", err)
		return
	}
	os.Stdout.Write(payload)
	os.Stdout.Write([]byte("\n"))
}

func resolveDarwinRuntimeStatus() DarwinRuntimeStatus {
	status := DarwinRuntimeStatus{
		Mode:               "audit_only",
		EnforcementCapable: false,
		AuthStatus:         darwinAuthStatus(),
		ControlPlaneStatus: "offline",
		ReasonCode:         "AUDIT_ONLY_PLATFORM",
		PolicyVersion:      "unavailable",
	}

	if !darwinArchSupported(runtime.GOARCH) {
		status.ReasonCode = "UNSUPPORTED_ARCH"
		return status
	}

	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		status.ReasonCode = "MISSING_MACHINE_KEY"
		return status
	}

	policy, err := fetchRuntimePolicy(
		darwinHostID(),
		runtime.GOOS,
		runtime.GOARCH,
		status.Mode,
		status.EnforcementCapable,
		"darwin-runtime",
		"darwin-runtime",
	)
	if err != nil {
		status.ControlPlaneStatus = "degraded"
		status.ReasonCode = "CONTROL_PLANE_POLICY_UNAVAILABLE"
		return status
	}

	status.ControlPlaneStatus = policy.ControlPlaneStatus
	if status.ControlPlaneStatus == "" {
		status.ControlPlaneStatus = "online"
	}
	status.PolicyVersion = policy.PolicyVersion
	if status.PolicyVersion == "" {
		status.PolicyVersion = "current"
	}
	status.BlockedTargetCount = len(policy.BlockedTargets)
	status.MonitoredProcessCount = len(policy.MonitoredProcesses)
	status.ReasonCode = policy.ReasonCode
	if status.ReasonCode == "" {
		status.ReasonCode = "AUDIT_ONLY_READY"
	}
	return status
}

func darwinArchSupported(goarch string) bool {
	return goarch == "amd64" || goarch == "arm64"
}

func darwinHostID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "macos-host"
	}
	return host + "-" + runtime.GOARCH
}

func darwinAuthStatus() string {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return "missing_machine_key"
	}
	return "authenticated"
}

func darwinGovernorURL() string {
	if value := os.Getenv("GAVEL_ENGINE_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return "http://localhost:8000"
}

func postDarwinJSON(path string, payload interface{}) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, darwinGovernorURL()+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("GAVEL_MACHINE_KEY"); key != "" {
		req.Header.Set("X-Gavel-Machine-Key", key)
	}
	req.Header.Set("X-Gavel-Host-Id", darwinHostID())

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Do(req)
}

func darwinHeartbeatLoop(done <-chan struct{}, status DarwinRuntimeStatus) {
	ticker := time.NewTicker(darwinHeartbeatInterval)
	defer ticker.Stop()

	sendDarwinHeartbeat(status, status.ControlPlaneStatus)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			current := resolveDarwinRuntimeStatus()
			sendDarwinHeartbeat(current, current.ControlPlaneStatus)
		}
	}
}

func sendDarwinHeartbeat(status DarwinRuntimeStatus, controlPlaneStatus string) {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return
	}
	req := DarwinHeartbeatRequest{
		HostID:             darwinHostID(),
		RuntimeOS:          runtime.GOOS,
		RuntimeArch:        runtime.GOARCH,
		RuntimeMode:        status.Mode,
		EnforcementCapable: status.EnforcementCapable,
		AuthStatus:         status.AuthStatus,
		ControlPlaneStatus: controlPlaneStatus,
		Component:          "darwin-runtime",
	}
	resp, err := postDarwinJSON("/external/heartbeat", req)
	if err != nil {
		log.Printf("macOS heartbeat failed: %v", err)
		return
	}
	resp.Body.Close()
}

func emitDarwinTelemetry(eventType, target, verdict, reasonCode string, metadata map[string]interface{}) {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return
	}
	event := DarwinRuntimeEvent{
		EventType:   eventType,
		EventTime:   time.Now().UTC().Format(time.RFC3339),
		HostID:      darwinHostID(),
		RuntimeOS:   runtime.GOOS,
		RuntimeArch: runtime.GOARCH,
		AgentID:     "darwin-runtime",
		Target:      target,
		Verdict:     verdict,
		ReasonCode:  reasonCode,
		Metadata:    metadata,
	}
	resp, err := postDarwinJSON("/internal/telemetry/push", event)
	if err != nil {
		log.Printf("macOS telemetry push failed: %v", err)
		return
	}
	resp.Body.Close()
}
