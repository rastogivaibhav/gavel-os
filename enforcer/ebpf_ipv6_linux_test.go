//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A disposable privileged Linux runner is required. This adds a private
// IPv6 address to the loopback interface for a real denied local socket;
// no traffic leaves the runner. Every path removes the temporary address.
func ipv6ProofListeners(t *testing.T) (net.Listener, net.Listener) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("requires isolated privileged Linux VM")
	}
	deniedAddr := "fd00:6761:7665:6c::2"
	cmd := exec.Command("ip", "-6", "addr", "add", deniedAddr+"/128", "dev", "lo")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cannot provision isolated IPv6 loopback alias: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		cmd := exec.Command("ip", "-6", "addr", "del", deniedAddr+"/128", "dev", "lo")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("cannot remove isolated IPv6 test alias: %v (%s)", err, out)
		}
	})

	allowed, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("IPv6 allowed listener unavailable: %v", err)
	}
	t.Cleanup(func() { _ = allowed.Close() })

	denied, err := net.Listen("tcp6", "["+deniedAddr+"]:0")
	if err != nil {
		t.Fatalf("IPv6 denied listener unavailable: %v", err)
	}
	t.Cleanup(func() { _ = denied.Close() })
	return allowed, denied
}

func checkGuardedIPv6(t *testing.T) {
	t.Helper()
	allowedAddress := os.Getenv("GAVEL_GUARD_ALLOWED_V6_ADDR")
	deniedAddress := os.Getenv("GAVEL_GUARD_DENIED_V6_ADDR")
	if allowedAddress == "" || deniedAddress == "" {
		return // IPv4-only legacy test
	}
	allowed, err := net.DialTimeout("tcp6", allowedAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("security regression: permitted IPv6 destination failed: %v", err)
	}
	_ = allowed.Close()
	denied, err := net.DialTimeout("tcp6", deniedAddress, 2*time.Second)
	if denied != nil {
		_ = denied.Close()
		t.Fatal("SECURITY VIOLATION: denied IPv6 TCP connection succeeded")
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("expected kernel EPERM/EACCES for IPv6 forbidden connect, got %v", err)
	}
}

func TestParseIPv6Native128BitAndRejectMapped(t *testing.T) {
	for _, tc := range []struct{ address string; valid bool }{
		{"::1", true}, {"2001:db8:1::4", true},
		{"fd00:6761:7665:6c::2", true},
		{"127.0.0.2", false}, {"::ffff:127.0.0.2", false},
		{"not-ip", false}, {"", false},
	} {
		ip, err := parseIPv6(tc.address)
		if (err == nil) != tc.valid {
			t.Fatalf("parseIPv6(%q) error=%v, valid expected=%t", tc.address, err, tc.valid)
		}
		if err == nil {
			parsed := net.ParseIP(tc.address).To16()
			if parsed == nil || string(ip[:]) != string(parsed) {
				t.Fatalf("parseIPv6(%q) bytes do not match kernel map key", tc.address)
			}
		}
	}
	ips, err := parseIPv6CSV("::1, 2001:db8::cafe")
	if err != nil || len(ips) != 2 {
		t.Fatalf("IPv6 CSV was not parsed correctly: %#v %v", ips, err)
	}
	if _, err := parseIPv6CSV("::1,not-ip"); err == nil {
		t.Fatal("invalid IPv6 in policy must fail closed")
	}
}

func TestIPv6PolicyConfiguredFromEnvironmentAndControlPlane(t *testing.T) {
	t.Setenv("GAVEL_BLOCKED_IPV6", "2001:db8::42, ::1")
	t.Setenv("GAVEL_BLOCKED_IPS", "")
	t.Setenv("GAVEL_MONITORED_PIDS", "45")
	t.Setenv("GAVEL_PROXY_IPV4", "")
	t.Setenv("GAVEL_PROXY_PORT", "")
	cfg, err := loadLinuxEnforcerConfigFromEnv()
	if err != nil || len(cfg.BlockedIPv6) != 2 || !linuxPolicyConfigured(cfg) {
		t.Fatalf("IPv6 local policy not enforceable: %+v %v", cfg, err)
	}
	policy := RuntimePolicyResponse{MonitoredPIDs: []uint32{12}, BlockedIPv6: []string{"fd00::abc"}}
	c, err := linuxEnforcerConfigFromRuntimePolicy(policy)
	if err != nil || len(c.BlockedIPv6) != 1 || !linuxPolicyConfigured(c) {
		t.Fatalf("IPv6 control-plane policy not enforceable: %+v %v", c, err)
	}
	t.Setenv("GAVEL_BLOCKED_IPV6", "invalid")
	if _, err := loadLinuxEnforcerConfigFromEnv(); err == nil {
		t.Fatal("invalid IPv6 policy must abort startup")
	}
	if _, err := linuxEnforcerConfigFromRuntimePolicy(RuntimePolicyResponse{BlockedIPv6: []string{"invalid"}}); err == nil {
		t.Fatal("invalid control-plane IPv6 literal must abort startup")
	}
}

func TestKernelGuardedIPv6AndDescendants(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" {
		t.Skip("requires isolated privileged Linux VM")
	}
	allowed6, denied6 := ipv6ProofListeners(t)
	t.Setenv("GAVEL_MACHINE_KEY", "")
	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_BLOCKED_IPV6", "fd00:6761:7665:6c::2")
	t.Setenv("GAVEL_AGENT_UID", "65534")
	t.Setenv("GAVEL_AGENT_GID", "65534")
	t.Setenv("GAVEL_GUARD_AGENT_HELPER", "1")
	t.Setenv("GAVEL_GUARD_ALLOWED_V6_ADDR", allowed6.Addr().String())
	t.Setenv("GAVEL_GUARD_DENIED_V6_ADDR", denied6.Addr().String())
	// IPv4 positive/negative controls are still required by guardedDial.
	allowed4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer allowed4.Close()
	denied4, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil { t.Fatal(err) }
	defer denied4.Close()
	t.Setenv("GAVEL_GUARD_ALLOWED_ADDR", allowed4.Addr().String())
	t.Setenv("GAVEL_GUARD_DENIED_ADDR", denied4.Addr().String())
	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	if err := runGuardedAgent([]string{exe, "-test.run=^TestKernelGuardedAgentProbe$", "-test.v"}); err != nil {
		t.Fatalf("IPv6 protected parent or fork/exec child escaped: %v", err)
	}
	t.Log(fmt.Sprintf("KERNEL PROOF: agent and fork/exec child both denied IPv6 %s and permitted %s", denied6.Addr(), allowed6.Addr()))
}

func TestGuardedIPv6EnvironmentDoesNotLeak(t *testing.T) {
	env := guardedWorkloadEnvironment([]string{
		"GAVEL_BLOCKED_IPV6=fd00::2", "GAVEL_GUARD_ALLOWED_V6_ADDR=[::1]:5432",
		"PATH=/bin", "GAVEL_GUARD_DENIED_V6_ADDR=[fd00::2]:1234",
	})
	for _, v := range env {
		if strings.HasPrefix(v, "GAVEL_BLOCKED_IPV6=") {
			t.Fatalf("supervisor IPv6 policy leaked: %s", v)
		}
	}
}
