package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRuntimeControlPlaneURLTrimsTrailingSlash(t *testing.T) {
	t.Setenv("GAVEL_ENGINE_URL", "http://control-plane.local:9000/")
	if got := runtimeControlPlaneURL(); got != "http://control-plane.local:9000" {
		t.Fatalf("expected trimmed control plane URL, got %q", got)
	}
}

func TestRuntimeControlPlaneURLDefaultsToLocalhost(t *testing.T) {
	t.Setenv("GAVEL_ENGINE_URL", "")
	if got := runtimeControlPlaneURL(); got != "http://localhost:8000" {
		t.Fatalf("unexpected default control plane URL: %q", got)
	}
}

func TestFetchRuntimePolicyIncludesMachineHeadersAndDecodesResponse(t *testing.T) {
	t.Setenv("GAVEL_MACHINE_KEY", "machine-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/external/runtime/policy" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Gavel-Machine-Key"); got != "machine-secret" {
			t.Fatalf("unexpected machine key header: %q", got)
		}
		if got := r.Header.Get("X-Gavel-Host-Id"); got != "host-1" {
			t.Fatalf("unexpected host id header: %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if !strings.Contains(string(body), "\"agent_id\":\"windows-runtime\"") {
			t.Fatalf("expected agent id in request body: %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"host_id":"host-1",
			"runtime_os":"windows",
			"runtime_arch":"amd64",
			"runtime_mode":"enforce",
			"enforcement_capable":true,
			"auth_status":"authenticated",
			"control_plane_status":"online",
			"policy_version":"2026-03-17",
			"reason_code":"POLICY_SYNC_READY",
			"blocked_targets":["analytics.google.com"],
			"monitored_processes":["cursor"]
		}`))
	}))
	defer server.Close()

	t.Setenv("GAVEL_ENGINE_URL", server.URL)
	policy, err := fetchRuntimePolicy("host-1", "windows", "amd64", "enforce", true, "windows-runtime", "windows-runtime")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy.ReasonCode != "POLICY_SYNC_READY" {
		t.Fatalf("unexpected reason code: %#v", policy)
	}
	if len(policy.BlockedTargets) != 1 || policy.BlockedTargets[0] != "analytics.google.com" {
		t.Fatalf("unexpected blocked targets: %#v", policy.BlockedTargets)
	}
}

func TestFetchRuntimePolicyWorksWithoutMachineKeyHeader(t *testing.T) {
	t.Setenv("GAVEL_MACHINE_KEY", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Gavel-Machine-Key"); got != "" {
			t.Fatalf("did not expect machine key header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"host_id":"host-1",
			"runtime_os":"linux",
			"runtime_arch":"amd64",
			"runtime_mode":"audit_only",
			"enforcement_capable":false,
			"auth_status":"missing_machine_key",
			"control_plane_status":"offline",
			"policy_version":"2026-03-17",
			"reason_code":"NO_RUNTIME_POLICY"
		}`))
	}))
	defer server.Close()

	t.Setenv("GAVEL_ENGINE_URL", server.URL)
	policy, err := fetchRuntimePolicy("host-1", "linux", "amd64", "audit_only", false, "linux-runtime", "linux-runtime")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy.AuthStatus != "missing_machine_key" {
		t.Fatalf("unexpected auth status: %#v", policy)
	}
}

func TestFetchRuntimePolicyFailsOnBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	t.Setenv("GAVEL_ENGINE_URL", server.URL)
	_, err := fetchRuntimePolicy("host-1", "linux", "amd64", "audit_only", false, "linux-runtime", "linux-runtime")
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected bad status error, got %v", err)
	}
}

func TestFetchRuntimePolicyFailsOnInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reason_code":`))
	}))
	defer server.Close()

	t.Setenv("GAVEL_ENGINE_URL", server.URL)
	_, err := fetchRuntimePolicy("host-1", "linux", "amd64", "audit_only", false, "linux-runtime", "linux-runtime")
	if err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestFetchRuntimePolicyFailsWhenControlPlaneIsUnreachable(t *testing.T) {
	t.Setenv("GAVEL_ENGINE_URL", "http://127.0.0.1:1")
	_, err := fetchRuntimePolicy("host-1", "linux", "amd64", "audit_only", false, "linux-runtime", "linux-runtime")
	if err == nil {
		t.Fatalf("expected network failure")
	}
}
