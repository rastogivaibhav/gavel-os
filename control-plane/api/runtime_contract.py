"""
Shared host-runtime contract models for Gavel/Sentinel Release 1.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MACHINE_KEY_HEADER = "x-gavel-machine-key"
HOST_ID_HEADER = "x-gavel-host-id"
MACHINE_KEY_ENV = "GAVEL_MACHINE_KEY"

ALLOWED_METADATA_KEYS = {
    # ── Core runtime state ────────────────────────────────────────────────────
    "component",
    "status",
    "runtime_mode",
    "enforcement_capable",
    # ── Performance / diagnostics ─────────────────────────────────────────────
    "latency_ms",
    "error_class",
    "count",
    # ── Network event fields (Windows/Linux enforcer) ─────────────────────────
    "target_kind",
    "process_id",
    "remote_port",
    "network_source",
    # ── Provider / component identity (Windows enforcer) ─────────────────────
    "process_monitor",
    "process_monitor_native",
    "network_monitor",
    "network_monitor_native",
    "traffic_enforcer",
    "traffic_enforcer_native",
    "diagnostic_warnings",
    "provider_fallback_active",
    # ── Linux eBPF enforcer ───────────────────────────────────────────────────
    "kernel_version",
    "cgroup_v2",
    "ebpf_program_status",
    "control_plane_status",
    "monitored_pid_count",
    "blocked_ipv4_count",
    "proxy_redirect",
    "reason_description",
    "recommended_action",
    "policy_source",
    # ── macOS runtime ─────────────────────────────────────────────────────────
    "system_extension_mode",
    "policy_version",
    "blocked_target_count",
    "monitored_proc_count",
}
BLOCKED_METADATA_KEYS = {
    "prompt",
    "file_contents",
    "payload_body",
    "response_body",
    "command_output",
    "command_line",
    "query",
    "conversation_history",
}


class RuntimeMode(str, Enum):
    ENFORCE = "enforce"
    AUDIT_ONLY = "audit_only"


class RuntimeOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class RuntimeEventType(str, Enum):
    AGENT_DETECTED = "agent_detected"
    POLICY_VERDICT = "policy_verdict"
    NETWORK_VERDICT = "network_verdict"
    COMPONENT_HEALTH = "component_health"
    AUDIT_APPEND_RESULT = "audit_append_result"
    AUTHZ_FAILURE = "authz_failure"


class RuntimeVerdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    AUDIT = "AUDIT"
    INFO = "INFO"
    DEGRADED = "DEGRADED"


class MachineRuntimeState(BaseModel):
    host_id: str = Field(min_length=1)
    runtime_os: RuntimeOS
    runtime_arch: str = Field(min_length=1)
    runtime_mode: RuntimeMode
    enforcement_capable: bool
    auth_status: str = "authenticated"
    control_plane_status: str = "online"

    model_config = ConfigDict(extra="forbid")


class RuntimeEventEnvelope(BaseModel):
    event_type: RuntimeEventType
    event_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    host_id: str = Field(min_length=1)
    runtime_os: RuntimeOS
    runtime_arch: str = Field(min_length=1)
    agent_id: str | None = None
    target: str = Field(min_length=1)
    verdict: RuntimeVerdict
    reason_code: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")

    @field_validator("event_time", mode="before")
    @classmethod
    def ensure_timezone(cls, value: datetime) -> datetime:
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key in value:
            if key in BLOCKED_METADATA_KEYS:
                raise ValueError(f"metadata key '{key}' is not permitted")
            if key not in ALLOWED_METADATA_KEYS:
                raise ValueError(f"metadata key '{key}' is not part of the runtime contract")
        return value


class MachineValidateRequest(MachineRuntimeState):
    action: str = Field(min_length=1)
    method: str = "EXECUTE"
    target_tenant_id: str = "default"
    required_clearance: int = 1
    agent_id: str = "host-runtime"


class MachineAgentDetectionRequest(MachineRuntimeState):
    agent_id: str = Field(min_length=1)
    target: str = "local-agent"
    reason_code: str = "AGENT_DETECTED"
    metadata: dict[str, Any] = Field(default_factory=dict)


class MachineHeartbeatRequest(MachineRuntimeState):
    component: str = "host-runtime"


class MachineHeartbeatResponse(MachineRuntimeState):
    reason_code: str


class MachinePolicyRequest(MachineRuntimeState):
    agent_id: str = "host-runtime"
    component: str = "host-runtime"


class MachinePolicyResponse(MachineRuntimeState):
    policy_version: str = Field(min_length=1)
    reason_code: str = Field(min_length=1)
    monitored_pids: list[int] = Field(default_factory=list)
    blocked_ipv4: list[str] = Field(default_factory=list)
    blocked_ipv6: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)
    monitored_processes: list[str] = Field(default_factory=list)
    proxy_ipv4: str | None = None
    proxy_port: int | None = None
