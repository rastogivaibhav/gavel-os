//go:build linux

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictProxyAdmissionLocal(t *testing.T) {
	t.Setenv("GAVEL_MONITORED_PIDS", "123")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_BLOCKED_IPV6", "")
	for _, tc := range []struct {
		name, ip, port string
		valid bool
	}{
		{"absent", "", "", true},
		{"valid", "127.0.0.1", "65535", true},
		{"missing-port", "127.0.0.1", "", false},
		{"missing-ip", "", "8080", false},
		{"zero", "127.0.0.1", "0", false},
		{"overflow", "127.0.0.1", "65536", false},
		{"negative", "127.0.0.1", "-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GAVEL_PROXY_IPV4", tc.ip)
			t.Setenv("GAVEL_PROXY_PORT", tc.port)
			cfg, err := loadLinuxEnforcerConfigFromEnv()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if tc.valid && (!linuxPolicyConfigured(cfg) || (cfg.Proxy.Enabled == 1) != (tc.ip != "")) {
				t.Fatalf("unexpected accepted configuration: %+v", cfg)
			}
		})
	}
}

func TestStrictProxyAdmissionRemote(t *testing.T) {
	for _, tc := range []struct {
		name, ip string
		port int
		valid bool
	}{
		{"absent", "", 0, true},
		{"valid", "127.0.0.1", 65535, true},
		{"missing-port", "127.0.0.1", 0, false},
		{"missing-ip", "", 8080, false},
		{"negative", "127.0.0.1", -1, false},
		{"negative-no-ip", "", -1, false},
		{"overflow", "127.0.0.1", 65536, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := linuxEnforcerConfigFromRuntimePolicy(RuntimePolicyResponse{
				MonitoredPIDs: []uint32{123}, BlockedIPv4: []string{"127.0.0.2"},
				ProxyIPv4: tc.ip, ProxyPort: tc.port,
			})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if tc.valid && (!linuxPolicyConfigured(cfg) || (cfg.Proxy.Enabled == 1) != (tc.ip != "")) {
				t.Fatalf("unexpected accepted configuration: %+v", cfg)
			}
		})
	}
}

func TestStrictAdmissionPayload(t *testing.T) {
	if os.Getenv("GAVEL_ADMISSION_PROBE") != "1" {
		t.Skip("guarded launch probe only")
	}
	if os.Geteuid() != 421343 {
		t.Fatal("unexpected payload UID")
	}
	if err := os.WriteFile(os.Getenv("GAVEL_ADMISSION_MARKER"), []byte("ran"), 0600); err != nil {
		t.Fatal(err)
	}
}

// Real guarded launch, using synthetic policies only. A blocklist is present
// in every malformed-proxy case, so silently dropping the proxy would otherwise
// permit a launch. No network requests leave the disposable VM.
func TestKernelGuardedStrictPolicyAdmission(t *testing.T) {
	if os.Getenv("GAVEL_RUN_KERNEL_TESTS") != "1" {
		t.Skip("requires isolated privileged VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	dir, err := os.MkdirTemp("/tmp", "gavel-admission-")
	if err != nil { t.Fatal(err) }
	defer os.RemoveAll(dir)
	if err := os.Chown(dir, 421343, 421343); err != nil { t.Fatal(err) }
	marker := filepath.Join(dir, "ran")
	exe, err := os.Executable()
	if err != nil { t.Fatal(err) }
	argv := []string{exe, "-test.run=^TestStrictAdmissionPayload$", "-test.v"}
	t.Setenv("GAVEL_AGENT_UID", "421343")
	t.Setenv("GAVEL_AGENT_GID", "421343")
	t.Setenv("GAVEL_ADMISSION_MARKER", marker)
	t.Setenv("GAVEL_ADMISSION_PROBE", "1")
	t.Setenv("GAVEL_MONITORED_PIDS", "")
	t.Setenv("GAVEL_BLOCKED_IPS", "127.0.0.2")
	t.Setenv("GAVEL_BLOCKED_IPV6", "")
	t.Setenv("GAVEL_MACHINE_KEY", "")
	assertRefusal := func(t *testing.T, expected string) {
		t.Helper()
		err := runGuardedAgent(argv)
		if err == nil || !strings.Contains(err.Error(), expected) {
			t.Fatalf("expected %q refusal, got %v", expected, err)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("payload ran or marker check failed: %v", err)
		}
		t.Logf("KERNEL PROOF: admission refused; payload marker absent (%v)", err)
	}
	for _, tc := range []struct{ name, ip, port, reason string }{
		{"local-partial", "127.0.0.1", "", "configured together"},
		{"local-zero", "127.0.0.1", "0", "1..65535"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GAVEL_PROXY_IPV4", tc.ip)
			t.Setenv("GAVEL_PROXY_PORT", tc.port)
			assertRefusal(t, tc.reason)
		})
	}
	t.Setenv("GAVEL_PROXY_IPV4", "")
	t.Setenv("GAVEL_PROXY_PORT", "")
	for _, tc := range []struct{ name string; status, port int; state, reason string }{
		{"remote-unavailable", 503, 0, "", "status 503"},
		{"remote-degraded", 200, 8080, "degraded", "not online"},
		{"remote-partial", 200, 0, "online", "configured together"},
		{"remote-overflow", 200, 65536, "online", "1..65535"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/external/runtime/policy" {
					http.NotFound(w, r); return
				}
				w.WriteHeader(tc.status)
				if tc.status == 200 {
					_ = json.NewEncoder(w).Encode(RuntimePolicyResponse{
						ControlPlaneStatus: tc.state, BlockedIPv4: []string{"127.0.0.2"},
						ProxyIPv4: "127.0.0.1", ProxyPort: tc.port,
					})
				}
			}))
			defer server.Close()
			t.Setenv("GAVEL_ENGINE_URL", server.URL)
			t.Setenv("GAVEL_MACHINE_KEY", "synthetic-test-key")
			assertRefusal(t, tc.reason)
		})
	}
	if err := runGuardedAgent(argv); err != nil {
		t.Fatalf("valid local policy failed positive launch: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "ran" {
		t.Fatalf("positive payload marker: %q %v", got, err)
	}
	t.Log("KERNEL PROOF: valid local policy launched unprivileged payload after refusal cases")
}
