//go:build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf gavel.bpf.c -- -I../headers

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

	"github.com/cilium/ebpf/rlimit"
)

const linuxHeartbeatInterval = 30 * time.Second

type LinuxPreflightResult struct {
	RuntimeOS          string `json:"runtime_os"`
	RuntimeArch        string `json:"runtime_arch"`
	RuntimeMode        string `json:"runtime_mode"`
	EnforcementCapable bool   `json:"enforcement_capable"`
	ReasonCode         string `json:"reason_code"`
	ReasonDescription  string `json:"reason_description"`
	RecommendedAction  string `json:"recommended_action"`
	PolicySource       string `json:"policy_source"`
	KernelVersion      string `json:"kernel_version"`
	CgroupPath         string `json:"cgroup_path,omitempty"`
	CgroupV2           bool   `json:"cgroup_v2"`
	HasCapBPF          bool   `json:"has_cap_bpf"`
	HasCapSysAdmin     bool   `json:"has_cap_sys_admin"`
	MemlockReady       bool   `json:"memlock_ready"`
	EBPFProgramStatus  string `json:"ebpf_program_status"`
	AuthStatus         string `json:"auth_status"`
	ControlPlaneStatus string `json:"control_plane_status,omitempty"`
	MonitoredPIDCount  int    `json:"monitored_pid_count"`
	BlockedIPv4Count   int    `json:"blocked_ipv4_count"`
	ProxyRedirect      bool   `json:"proxy_redirect"`
}

type LinuxHeartbeatRequest struct {
	HostID             string `json:"host_id"`
	RuntimeOS          string `json:"runtime_os"`
	RuntimeArch        string `json:"runtime_arch"`
	RuntimeMode        string `json:"runtime_mode"`
	EnforcementCapable bool   `json:"enforcement_capable"`
	AuthStatus         string `json:"auth_status,omitempty"`
	ControlPlaneStatus string `json:"control_plane_status,omitempty"`
	Component          string `json:"component"`
}

type LinuxRuntimeEvent struct {
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

func main() {
	preflightOnly := flag.Bool("preflight", false, "print runtime preflight and exit")
	flag.Parse()

	preflight := runLinuxPreflight()
	log.Printf(
		"Gavel Shield (linux) starting on %s/%s mode=%s reason=%s detail=%s",
		preflight.RuntimeOS,
		preflight.RuntimeArch,
		preflight.RuntimeMode,
		preflight.ReasonCode,
		preflight.ReasonDescription,
	)

	if *preflightOnly {
		printPreflight(preflight)
		return
	}

	if preflight.RuntimeMode != "enforce" {
		log.Printf(
			"Gavel Shield entering audit-only mode: %s action=%s",
			preflight.ReasonCode,
			preflight.RecommendedAction,
		)
		startLinuxRuntime(preflight, nil)
		return
	}

	config, controlPlaneStatus, err := resolveLinuxRuntimePolicy(preflight)
	if controlPlaneStatus != "" {
		preflight.ControlPlaneStatus = controlPlaneStatus
	}
	if err != nil {
		log.Printf("Gavel Shield falling back to audit-only mode: runtime policy sync failed: %v", err)
		preflight.RuntimeMode = "audit_only"
		preflight.ReasonCode = "CONTROL_PLANE_POLICY_UNAVAILABLE"
		preflight.ReasonDescription = linuxReasonDescription(preflight.ReasonCode)
		preflight.RecommendedAction = linuxRecommendedAction(preflight.ReasonCode)
		startLinuxRuntime(preflight, nil)
		return
	}

	cleanup, err := attachEnforcer(preflight.CgroupPath, config)
	if err != nil {
		log.Printf("Gavel Shield falling back to audit-only mode: %v", err)
		preflight.RuntimeMode = "audit_only"
		preflight.ReasonCode = "EBPF_ATTACH_FAILED"
		preflight.ReasonDescription = linuxReasonDescription(preflight.ReasonCode)
		preflight.RecommendedAction = linuxRecommendedAction(preflight.ReasonCode)
		startLinuxRuntime(preflight, nil)
		return
	}

	preflight.MonitoredPIDCount = len(config.MonitoredPIDs)
	preflight.BlockedIPv4Count = len(config.BlockedIPv4)
	preflight.ProxyRedirect = config.Proxy.Enabled == 1
	log.Printf("Gavel Shield enforcement active at %s", preflight.CgroupPath)
	startLinuxRuntime(preflight, cleanup)
}

func startLinuxRuntime(preflight LinuxPreflightResult, cleanup func()) {
	done := make(chan struct{})
	go linuxHeartbeatLoop(done, preflight)
	reportLinuxComponentHealth(preflight)

	if cleanup != nil {
		defer cleanup()
	}
	if preflight.RuntimeMode != "enforce" {
		waitForStop(done)
		return
	}
	waitForStop(done)
}

func runLinuxPreflight() LinuxPreflightResult {
	result := LinuxPreflightResult{
		RuntimeOS:         runtime.GOOS,
		RuntimeArch:       runtime.GOARCH,
		KernelVersion:     readKernelVersion(),
		EBPFProgramStatus: ebpfProgramStatus(),
		AuthStatus:        linuxAuthStatus(),
		PolicySource:      linuxPolicySource(os.Getenv("GAVEL_MACHINE_KEY")),
	}
	archSupported := archSupportsEnforcement(runtime.GOARCH)
	cgroupPath, cgroupV2 := resolveLinuxCgroupPath()
	result.CgroupPath = cgroupPath
	result.CgroupV2 = cgroupV2

	capMask := readEffectiveCapabilityMask()
	result.HasCapBPF = hasCapability(capMask, 39)
	result.HasCapSysAdmin = hasCapability(capMask, 21)

	memlockReady := true
	if err := rlimit.RemoveMemlock(); err != nil {
		memlockReady = false
	}
	result.MemlockReady = memlockReady

	hasPrivilege := result.HasCapBPF || result.HasCapSysAdmin
	result.EnforcementCapable = archSupported && cgroupV2 && hasPrivilege && memlockReady
	// The shipping Linux loader constructs BPF instructions at runtime; it does not
	// ship a generated object named "available". Actual load/attach is tested
	// in attachEnforcer; this check only identifies a supported loader mode.
	ebpfReady := linuxEBPFProgramReady(result.EBPFProgramStatus) && memlockReady

	config, controlPlaneStatus, policyErr := resolveLinuxRuntimePolicy(result)
	result.ControlPlaneStatus = controlPlaneStatus
	if policyErr == nil {
		result.MonitoredPIDCount = len(config.MonitoredPIDs)
		result.BlockedIPv4Count = len(config.BlockedIPv4)
		result.ProxyRedirect = config.Proxy.Enabled == 1
	}

	if policyErr != nil {
		result.RuntimeMode = "audit_only"
		if machineKey := os.Getenv("GAVEL_MACHINE_KEY"); machineKey != "" {
			result.ReasonCode = "CONTROL_PLANE_POLICY_UNAVAILABLE"
		} else {
			result.ReasonCode = "INVALID_RUNTIME_POLICY"
		}
		result.ReasonDescription = linuxReasonDescription(result.ReasonCode)
		result.RecommendedAction = linuxRecommendedAction(result.ReasonCode)
		return result
	}

	policyConfigured := linuxPolicyConfigured(config)
	mode, reason := decideLinuxRuntimeMode(archSupported, cgroupV2, hasPrivilege, ebpfReady, policyConfigured)
	result.RuntimeMode = mode
	result.ReasonCode = reason
	result.ReasonDescription = linuxReasonDescription(result.ReasonCode)
	result.RecommendedAction = linuxRecommendedAction(result.ReasonCode)
	return result
}

// linuxEBPFProgramReady reports whether the executable includes a usable BPF
// loader implementation. This is not evidence that a BPF program has loaded
// or attached; callers must verify attachEnforcer succeeds separately.
func linuxEBPFProgramReady(status string) bool {
	return status == "available" || status == "runtime-generated"
}

func resolveLinuxRuntimePolicy(preflight LinuxPreflightResult) (LinuxEnforcerConfig, string, error) {
	if os.Getenv("GAVEL_MACHINE_KEY") != "" {
		policy, err := fetchRuntimePolicy(
			linuxHostID(),
			preflight.RuntimeOS,
			preflight.RuntimeArch,
			preflight.RuntimeMode,
			preflight.EnforcementCapable,
			"linux-runtime",
			"linux-runtime",
		)
		if err != nil {
			return LinuxEnforcerConfig{}, "degraded", err
		}
		config, err := linuxEnforcerConfigFromRuntimePolicy(policy)
		if err != nil {
			return LinuxEnforcerConfig{}, policy.ControlPlaneStatus, err
		}
		return config, policy.ControlPlaneStatus, nil
	}

	config, err := loadLinuxEnforcerConfigFromEnv()
	if err != nil {
		return LinuxEnforcerConfig{}, "offline", err
	}
	return config, "offline", nil
}

func resolveLinuxCgroupPath() (string, bool) {
	candidates := []string{}
	if envPath := os.Getenv("GAVEL_CGROUP_PATH"); envPath != "" {
		candidates = append(candidates, envPath)
	}
	candidates = append(candidates, "/sys/fs/cgroup", "/sys/fs/cgroup/unified")

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, err := os.Stat(candidate + "/cgroup.controllers"); err == nil {
			return candidate, true
		}
	}
	return "", false
}

func readKernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func readEffectiveCapabilityMask() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			mask, err := parseCapabilityMask(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")))
			if err == nil {
				return mask
			}
		}
	}
	return 0
}

func linuxAuthStatus() string {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return "missing_machine_key"
	}
	return "authenticated"
}

func printPreflight(result LinuxPreflightResult) {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("failed to encode preflight output: %v", err)
		return
	}
	os.Stdout.Write(payload)
	os.Stdout.Write([]byte("\n"))
}

func linuxHeartbeatLoop(done <-chan struct{}, preflight LinuxPreflightResult) {
	ticker := time.NewTicker(linuxHeartbeatInterval)
	defer ticker.Stop()

	sendLinuxHeartbeat(preflight, "starting")
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			sendLinuxHeartbeat(preflight, "online")
		}
	}
}

func sendLinuxHeartbeat(preflight LinuxPreflightResult, controlPlaneStatus string) {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return
	}
	req := LinuxHeartbeatRequest{
		HostID:             linuxHostID(),
		RuntimeOS:          preflight.RuntimeOS,
		RuntimeArch:        preflight.RuntimeArch,
		RuntimeMode:        preflight.RuntimeMode,
		EnforcementCapable: preflight.EnforcementCapable,
		AuthStatus:         preflight.AuthStatus,
		ControlPlaneStatus: controlPlaneStatus,
		Component:          "linux-runtime",
	}
	_, err := postLinuxJSON("/external/heartbeat", req)
	if err != nil {
		log.Printf("Linux heartbeat failed: %v", err)
	}
}

func reportLinuxComponentHealth(preflight LinuxPreflightResult) {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return
	}

	verdict := "ALLOW"
	if preflight.RuntimeMode != "enforce" {
		verdict = "AUDIT"
	}

	event := LinuxRuntimeEvent{
		EventType:   "component_health",
		EventTime:   time.Now().UTC().Format(time.RFC3339),
		HostID:      linuxHostID(),
		RuntimeOS:   preflight.RuntimeOS,
		RuntimeArch: preflight.RuntimeArch,
		AgentID:     "linux-runtime",
		Target:      "linux-runtime",
		Verdict:     verdict,
		ReasonCode:  preflight.ReasonCode,
		Metadata: map[string]interface{}{
			"component":            "linux-runtime",
			"runtime_mode":         preflight.RuntimeMode,
			"enforcement_capable":  preflight.EnforcementCapable,
			"reason_description":   preflight.ReasonDescription,
			"recommended_action":   preflight.RecommendedAction,
			"policy_source":        preflight.PolicySource,
			"kernel_version":       preflight.KernelVersion,
			"cgroup_v2":            preflight.CgroupV2,
			"ebpf_program_status":  preflight.EBPFProgramStatus,
			"control_plane_status": preflight.ControlPlaneStatus,
			"monitored_pid_count":  preflight.MonitoredPIDCount,
			"blocked_ipv4_count":   preflight.BlockedIPv4Count,
			"proxy_redirect":       preflight.ProxyRedirect,
		},
	}

	if _, err := postLinuxJSON("/internal/telemetry/push", event); err != nil {
		log.Printf("Linux component health telemetry failed: %v", err)
	}
}

func linuxHostID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "linux-host"
	}
	return host + "-" + runtime.GOARCH
}

func linuxGovernorURL() string {
	if value := os.Getenv("GAVEL_ENGINE_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return "http://localhost:8000"
}

func postLinuxJSON(path string, payload interface{}) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, linuxGovernorURL()+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("GAVEL_MACHINE_KEY"); key != "" {
		req.Header.Set("X-Gavel-Machine-Key", key)
	}
	req.Header.Set("X-Gavel-Host-Id", linuxHostID())
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}

func waitForStop(done chan<- struct{}) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	close(done)
	log.Println("Gavel Shield shutting down")
}
