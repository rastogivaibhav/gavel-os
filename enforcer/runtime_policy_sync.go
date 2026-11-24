package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type RuntimePolicyRequest struct {
	HostID             string `json:"host_id"`
	RuntimeOS          string `json:"runtime_os"`
	RuntimeArch        string `json:"runtime_arch"`
	RuntimeMode        string `json:"runtime_mode"`
	EnforcementCapable bool   `json:"enforcement_capable"`
	AgentID            string `json:"agent_id"`
	Component          string `json:"component"`
}

type RuntimePolicyResponse struct {
	HostID             string   `json:"host_id"`
	RuntimeOS          string   `json:"runtime_os"`
	RuntimeArch        string   `json:"runtime_arch"`
	RuntimeMode        string   `json:"runtime_mode"`
	EnforcementCapable bool     `json:"enforcement_capable"`
	AuthStatus         string   `json:"auth_status"`
	ControlPlaneStatus string   `json:"control_plane_status"`
	PolicyVersion      string   `json:"policy_version"`
	ReasonCode         string   `json:"reason_code"`
	MonitoredPIDs      []uint32 `json:"monitored_pids"`
	BlockedIPv4        []string `json:"blocked_ipv4"`
	BlockedIPv6        []string `json:"blocked_ipv6"`
	BlockedTargets     []string `json:"blocked_targets"`
	MonitoredProcesses []string `json:"monitored_processes"`
	ProxyIPv4          string   `json:"proxy_ipv4"`
	ProxyPort          int      `json:"proxy_port"`
}

func runtimeControlPlaneURL() string {
	if value := os.Getenv("GAVEL_ENGINE_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return "http://localhost:8000"
}

func fetchRuntimePolicy(hostID, runtimeOS, runtimeArch, runtimeMode string, enforcementCapable bool, agentID, component string) (RuntimePolicyResponse, error) {
	payload := RuntimePolicyRequest{
		HostID:             hostID,
		RuntimeOS:          runtimeOS,
		RuntimeArch:        runtimeArch,
		RuntimeMode:        runtimeMode,
		EnforcementCapable: enforcementCapable,
		AgentID:            agentID,
		Component:          component,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return RuntimePolicyResponse{}, err
	}

	req, err := http.NewRequest(http.MethodPost, runtimeControlPlaneURL()+"/external/runtime/policy", bytes.NewReader(data))
	if err != nil {
		return RuntimePolicyResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("GAVEL_MACHINE_KEY"); key != "" {
		req.Header.Set("X-Gavel-Machine-Key", key)
	}
	req.Header.Set("X-Gavel-Host-Id", hostID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return RuntimePolicyResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return RuntimePolicyResponse{}, fmt.Errorf("runtime policy request failed with status %d", resp.StatusCode)
	}

	var result RuntimePolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return RuntimePolicyResponse{}, err
	}
	return result, nil
}
