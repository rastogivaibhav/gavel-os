package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func archSupportsEnforcement(goarch string) bool {
	return goarch == "amd64" || goarch == "arm64"
}

func parseCapabilityMask(raw string) (uint64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("empty capability mask")
	}
	return strconv.ParseUint(trimmed, 16, 64)
}

func hasCapability(mask uint64, bit uint) bool {
	return mask&(1<<bit) != 0
}

type LinuxProxyConfig struct {
	IPv4    uint32
	Port    uint32
	Enabled uint32
}

type LinuxEnforcerConfig struct {
	MonitoredPIDs []uint32
	BlockedIPv4   []uint32
	Proxy         LinuxProxyConfig
}

func linuxPolicySource(machineKey string) string {
	if strings.TrimSpace(machineKey) != "" {
		return "control_plane"
	}
	return "local_env"
}

func linuxReasonDescription(reason string) string {
	switch reason {
	case "ENFORCEMENT_READY":
		return "Kernel prerequisites and runtime policy are present, so Linux enforcement can start."
	case "UNSUPPORTED_ARCH":
		return "This CPU architecture is outside the supported Linux enforcement matrix."
	case "CGROUP_V2_REQUIRED":
		return "The host is not exposing a usable cgroup v2 hierarchy for the enforcer."
	case "INSUFFICIENT_PRIVILEGES":
		return "The runtime is missing the Linux capabilities required to attach and manage eBPF programs."
	case "EBPF_PROGRAM_UNAVAILABLE":
		return "The eBPF program could not be prepared or memlock limits could not be adjusted."
	case "NO_RUNTIME_POLICY":
		return "No monitored PIDs or block/redirect policy were supplied for Linux enforcement."
	case "CONTROL_PLANE_POLICY_UNAVAILABLE":
		return "The runtime cannot fetch its policy; enforcement-required startup must abort."
	case "INVALID_RUNTIME_POLICY":
		return "The configured Linux policy could not be parsed into a valid runtime configuration."
	case "EBPF_ATTACH_FAILED":
		return "The BPF hook could not attach; no Linux protection is active."
	case "OPERATOR_AUDIT_ONLY":
		return "Operator explicitly requested unprotected audit-only operation."
	default:
		return "Linux runtime status is unavailable."
	}
}

func linuxRecommendedAction(reason string) string {
	switch reason {
	case "ENFORCEMENT_READY":
		return "Start the service normally and verify heartbeat plus eBPF attachment."
	case "UNSUPPORTED_ARCH":
		return "Use amd64 or arm64 for enforcement, or keep this host in audit-only mode."
	case "CGROUP_V2_REQUIRED":
		return "Enable cgroup v2 on the host or select a compatible kernel/runtime configuration."
	case "INSUFFICIENT_PRIVILEGES":
		return "Run with CAP_BPF or CAP_SYS_ADMIN, or install the service with the required privileges."
	case "EBPF_PROGRAM_UNAVAILABLE":
		return "Check memlock settings, eBPF support, and runtime logs before retrying."
	case "NO_RUNTIME_POLICY":
		return "Configure monitored PIDs and block/redirect policy through the control plane or local env file."
	case "CONTROL_PLANE_POLICY_UNAVAILABLE":
		return "Restore control-plane connectivity before launching the protected workload. No automatic downgrade to audit-only is permitted."
	case "INVALID_RUNTIME_POLICY":
		return "Fix the runtime policy values and rerun the Linux preflight command."
	case "EBPF_ATTACH_FAILED":
		return "Check kernel BPF verifier, privileges and cgroup path. Do not start protected workloads."
	case "OPERATOR_AUDIT_ONLY":
		return "Remove --audit-only to request OS enforcement, and verify kernel attachment before running any agent."
	default:
		return "Inspect logs and rerun preflight for a more specific Linux runtime diagnosis."
	}
}

func decideLinuxRuntimeMode(archSupported, cgroupV2, hasPrivilege, ebpfReady, policyConfigured bool) (string, string) {
	switch {
	case !archSupported:
		return "audit_only", "UNSUPPORTED_ARCH"
	case !cgroupV2:
		return "audit_only", "CGROUP_V2_REQUIRED"
	case !hasPrivilege:
		return "audit_only", "INSUFFICIENT_PRIVILEGES"
	case !ebpfReady:
		return "audit_only", "EBPF_PROGRAM_UNAVAILABLE"
	case !policyConfigured:
		return "audit_only", "NO_RUNTIME_POLICY"
	default:
		return "enforce", "ENFORCEMENT_READY"
	}
}

func loadLinuxEnforcerConfigFromEnv() (LinuxEnforcerConfig, error) {
	config := LinuxEnforcerConfig{}

	if raw := os.Getenv("GAVEL_MONITORED_PIDS"); raw != "" {
		pids, err := parseUint32CSV(raw)
		if err != nil {
			return LinuxEnforcerConfig{}, fmt.Errorf("parse monitored pids: %w", err)
		}
		config.MonitoredPIDs = pids
	}

	if raw := os.Getenv("GAVEL_BLOCKED_IPS"); raw != "" {
		ips, err := parseIPv4CSV(raw)
		if err != nil {
			return LinuxEnforcerConfig{}, fmt.Errorf("parse blocked ips: %w", err)
		}
		config.BlockedIPv4 = ips
	}

	proxyIP := strings.TrimSpace(os.Getenv("GAVEL_PROXY_IPV4"))
	proxyPort := strings.TrimSpace(os.Getenv("GAVEL_PROXY_PORT"))
	if proxyIP != "" && proxyPort != "" {
		parsedIP, err := parseIPv4(proxyIP)
		if err != nil {
			return LinuxEnforcerConfig{}, fmt.Errorf("parse proxy ip: %w", err)
		}
		port, err := strconv.ParseUint(proxyPort, 10, 16)
		if err != nil {
			return LinuxEnforcerConfig{}, fmt.Errorf("parse proxy port: %w", err)
		}
		config.Proxy = LinuxProxyConfig{
			IPv4:    parsedIP,
			Port:    uint32(port),
			Enabled: 1,
		}
	}

	return config, nil
}

func linuxPolicyConfigured(config LinuxEnforcerConfig) bool {
	return len(config.MonitoredPIDs) > 0 && (len(config.BlockedIPv4) > 0 || config.Proxy.Enabled == 1)
}

func linuxEnforcerConfigFromRuntimePolicy(policy RuntimePolicyResponse) (LinuxEnforcerConfig, error) {
	config := LinuxEnforcerConfig{
		MonitoredPIDs: append([]uint32{}, policy.MonitoredPIDs...),
	}

	for _, raw := range policy.BlockedIPv4 {
		ip, err := parseIPv4(raw)
		if err != nil {
			return LinuxEnforcerConfig{}, fmt.Errorf("parse blocked ip from policy: %w", err)
		}
		config.BlockedIPv4 = append(config.BlockedIPv4, ip)
	}

	if policy.ProxyIPv4 != "" && policy.ProxyPort > 0 {
		parsedIP, err := parseIPv4(policy.ProxyIPv4)
		if err != nil {
			return LinuxEnforcerConfig{}, fmt.Errorf("parse proxy ip from policy: %w", err)
		}
		config.Proxy = LinuxProxyConfig{
			IPv4:    parsedIP,
			Port:    uint32(policy.ProxyPort),
			Enabled: 1,
		}
	}

	return config, nil
}

func parseUint32CSV(raw string) ([]uint32, error) {
	values := []uint32{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		parsed, err := strconv.ParseUint(trimmed, 10, 32)
		if err != nil {
			return nil, err
		}
		values = append(values, uint32(parsed))
	}
	return values, nil
}

func parseIPv4CSV(raw string) ([]uint32, error) {
	values := []uint32{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		ip, err := parseIPv4(trimmed)
		if err != nil {
			return nil, err
		}
		values = append(values, ip)
	}
	return values, nil
}

func parseIPv4(raw string) (uint32, error) {
	ip := net.ParseIP(strings.TrimSpace(raw)).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address %q", raw)
	}
	// bpf_sock_addr.user_ip4 contains network-order bytes. The BPF program
	// loads them as a native-endian uint32, and Map.Put(uint32) writes the
	// key in native-endian order. A big-endian numeric value mismatches
	// the BPF lookup key on amd64/arm64.
	return binary.NativeEndian.Uint32(ip), nil
}
