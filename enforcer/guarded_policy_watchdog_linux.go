//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

const guardedPolicyWatchInterval = 5 * time.Second

// Verify the remote policy still authorizes exactly the effective immutable
// launch snapshot. Never mutate a live policy, fall back to local settings,
// or treat a successful HTTP request alone as authorization.
func checkGuardedRemotePolicy(ctx context.Context, preflight LinuxPreflightResult, uid, gid uint32, fsArgs []string, filter *os.File, expected string) error {
	if os.Getenv("GAVEL_MACHINE_KEY") == "" {
		return fmt.Errorf("control-plane machine key unavailable")
	}
	policy, err := fetchRuntimePolicyContext(ctx, linuxHostID(), preflight.RuntimeOS, preflight.RuntimeArch,
		preflight.RuntimeMode, preflight.EnforcementCapable, "linux-runtime", "linux-runtime")
	if err != nil {
		return fmt.Errorf("remote policy refresh failed: %w", err)
	}
	if policy.ControlPlaneStatus != "online" {
		return fmt.Errorf("remote policy status is not online")
	}
	cfg, err := linuxEnforcerConfigFromRuntimePolicy(policy)
	if err != nil { return fmt.Errorf("remote policy invalid: %w", err) }
	cfg.MonitoredPIDs = nil
	cfg.ProtectAll = true
	if err := configureGuardedTCPProfile(&cfg); err != nil { return err }
	if !linuxPolicyConfigured(cfg) { return fmt.Errorf("remote policy empty or revoked") }
	actual, err := guardedPolicyDigest(cfg, uid, gid, "control_plane", fsArgs, filter)
	if err != nil { return err }
	if actual != expected { return fmt.Errorf("effective remote policy changed; new guarded launch required") }
	return nil
}

func watchGuardedRemotePolicy(ctx context.Context, interval time.Duration, check func(context.Context) error) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done(): return nil
		case <-timer.C:
			if err := check(ctx); err != nil {
				if ctx.Err() != nil { return nil }
				return err
			}
			timer.Reset(interval)
		}
	}
}
