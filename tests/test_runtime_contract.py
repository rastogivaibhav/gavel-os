"""
Tests for api.runtime_contract — RuntimeEventEnvelope metadata validation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from api.runtime_contract import (
    ALLOWED_METADATA_KEYS,
    BLOCKED_METADATA_KEYS,
    RuntimeEventEnvelope,
    RuntimeEventType,
    RuntimeOS,
    RuntimeVerdict,
    RuntimeMode,
    MachineHeartbeatRequest,
)


def _base_envelope(**overrides) -> dict:
    defaults = dict(
        event_type=RuntimeEventType.COMPONENT_HEALTH,
        host_id="host-1",
        runtime_os=RuntimeOS.LINUX,
        runtime_arch="amd64",
        target="linux-runtime",
        verdict=RuntimeVerdict.INFO,
        reason_code="HEARTBEAT_OK",
        metadata={},
    )
    defaults.update(overrides)
    return defaults


# ── Valid envelopes ───────────────────────────────────────────────────────────

def test_valid_envelope_with_empty_metadata():
    env = RuntimeEventEnvelope(**_base_envelope())
    assert env.host_id == "host-1"


def test_valid_envelope_with_allowed_metadata():
    env = RuntimeEventEnvelope(**_base_envelope(metadata={
        "component": "linux-runtime",
        "runtime_mode": "enforce",
        "enforcement_capable": True,
        "kernel_version": "6.1.0",
        "cgroup_v2": True,
    }))
    assert env.metadata["component"] == "linux-runtime"


def test_all_allowed_keys_accepted():
    """Every key in ALLOWED_METADATA_KEYS must be accepted by the validator."""
    metadata = {k: "value" for k in ALLOWED_METADATA_KEYS}
    env = RuntimeEventEnvelope(**_base_envelope(metadata=metadata))
    assert len(env.metadata) == len(ALLOWED_METADATA_KEYS)


# ── Blocked metadata keys ─────────────────────────────────────────────────────

@pytest.mark.parametrize("blocked_key", sorted(BLOCKED_METADATA_KEYS))
def test_blocked_metadata_key_raises(blocked_key):
    with pytest.raises(ValidationError) as exc_info:
        RuntimeEventEnvelope(**_base_envelope(metadata={blocked_key: "secret"}))
    assert blocked_key in str(exc_info.value)


# ── Unknown metadata keys ─────────────────────────────────────────────────────

def test_unknown_metadata_key_raises():
    with pytest.raises(ValidationError) as exc_info:
        RuntimeEventEnvelope(**_base_envelope(metadata={"unknown_field": "value"}))
    assert "unknown_field" in str(exc_info.value)


# ── Timezone normalisation ────────────────────────────────────────────────────

def test_naive_event_time_gets_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    env = RuntimeEventEnvelope(**_base_envelope(event_time=naive))
    assert env.event_time.tzinfo is not None


def test_aware_event_time_preserved():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    env = RuntimeEventEnvelope(**_base_envelope(event_time=aware))
    assert env.event_time == aware


# ── Windows enforcer metadata keys ───────────────────────────────────────────

def test_windows_provider_metadata_accepted():
    env = RuntimeEventEnvelope(**_base_envelope(
        runtime_os=RuntimeOS.WINDOWS,
        metadata={
            "component": "windows-runtime",
            "process_monitor": "etw-process",
            "process_monitor_native": True,
            "network_monitor": "etw-network",
            "network_monitor_native": True,
            "traffic_enforcer": "wfp",
            "traffic_enforcer_native": True,
            "provider_fallback_active": False,
        },
    ))
    assert env.metadata["traffic_enforcer"] == "wfp"


def test_windows_network_event_metadata_accepted():
    env = RuntimeEventEnvelope(**_base_envelope(
        event_type=RuntimeEventType.NETWORK_VERDICT,
        runtime_os=RuntimeOS.WINDOWS,
        verdict=RuntimeVerdict.DENY,
        reason_code="LOCAL_BLOCKLIST",
        metadata={
            "component": "windows-runtime",
            "target_kind": "network",
            "process_id": 1234,
            "remote_port": 443,
            "network_source": "etw-tcpip",
            "runtime_mode": "enforce",
            "enforcement_capable": True,
        },
    ))
    assert env.metadata["process_id"] == 1234


# ── macOS metadata keys ───────────────────────────────────────────────────────

def test_macos_audit_metadata_accepted():
    env = RuntimeEventEnvelope(**_base_envelope(
        runtime_os=RuntimeOS.MACOS,
        metadata={
            "component": "darwin-runtime",
            "runtime_mode": "audit_only",
            "enforcement_capable": False,
            "system_extension_mode": "planned",
            "policy_version": "2026-04-21",
            "blocked_target_count": 0,
            "monitored_proc_count": 3,
            "control_plane_status": "online",
        },
    ))
    assert env.metadata["system_extension_mode"] == "planned"


# ── MachineHeartbeatRequest ───────────────────────────────────────────────────

def test_heartbeat_request_valid():
    req = MachineHeartbeatRequest(
        host_id="host-1",
        runtime_os=RuntimeOS.LINUX,
        runtime_arch="amd64",
        runtime_mode=RuntimeMode.ENFORCE,
        enforcement_capable=True,
        component="linux-runtime",
    )
    assert req.component == "linux-runtime"


def test_heartbeat_request_rejects_extra_fields():
    with pytest.raises(ValidationError):
        MachineHeartbeatRequest(
            host_id="host-1",
            runtime_os=RuntimeOS.LINUX,
            runtime_arch="amd64",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
            component="linux-runtime",
            unexpected_field="bad",
        )
