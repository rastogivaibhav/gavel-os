"""
Shared control-plane decision helpers used by REST and gRPC entry points.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from ipaddress import IPv4Address

from fastapi import HTTPException, Request

from api.runtime_contract import MachinePolicyResponse, RuntimeMode, RuntimeOS
from auth.jwt_handler import verify_token


def require_machine_auth(request: Request) -> None:
    auth_mode = request.scope.get("state", {}).get("gavel_auth_mode")
    if auth_mode != "machine":
        raise HTTPException(status_code=401, detail="Machine authentication required")


def control_plane_status_from_app(app) -> str:
    from api.routes import query as query_route

    opa_available = query_route.opa_engine.is_available()
    required_components = (
        getattr(app.state, "audit_ledger", None),
        getattr(app.state, "policy_loader", None),
        getattr(app.state, "verdict_engine", None),
    )
    return "online" if all(required_components) and opa_available else "degraded"


def identity_context_from_headers(headers: Mapping[str, str]) -> dict:
    context = {
        "is_authenticated": False,
        "role": "anonymous",
        "customer_id": None,
        "tenant_id": headers.get("x-tenant-id", "default"),
        "clearance_level": int(headers.get("x-clearance-level", "0") or 0),
        "department": headers.get("x-department", "runtime"),
    }
    auth_header = headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return context

    token = auth_header[7:]
    try:
        payload = verify_token(token)
    except Exception:
        return context

    context.update(
        {
            "is_authenticated": True,
            "role": payload.get("role", "customer"),
            "customer_id": payload.get("customer_id"),
            "tenant_id": payload.get("tenant_id", context["tenant_id"]),
            "clearance_level": payload.get("clearance_level", max(context["clearance_level"], 1)),
            "department": payload.get("department", context["department"]),
        }
    )
    return context


def evaluate_runtime_decision(
    app,
    *,
    action: str,
    method: str,
    target_tenant_id: str,
    required_clearance: int,
    host_id: str,
    agent_id: str,
    runtime_mode: RuntimeMode | str,
    enforcement_capable: bool,
    runtime_os: str,
    runtime_arch: str,
    headers: Mapping[str, str] | None = None,
    auth_status: str = "authenticated",
) -> dict:
    from api.routes import query as query_route

    control_plane_status = control_plane_status_from_app(app)
    normalized_runtime_mode = (
        runtime_mode.value if isinstance(runtime_mode, RuntimeMode) else runtime_mode
    )
    if control_plane_status != "online":
        return {
            "is_allowed": False,
            "reason": "Control plane dependencies are degraded",
            "reason_code": "CONTROL_PLANE_DEGRADED",
            "runtime_mode": normalized_runtime_mode,
            "enforcement_capable": enforcement_capable,
            "auth_status": auth_status,
            "control_plane_status": control_plane_status,
            "host_id": host_id,
            "agent_id": agent_id,
            "runtime_os": runtime_os,
            "runtime_arch": runtime_arch,
        }

    normalized_method = (method or "EXECUTE").upper()
    request_headers = {key.lower(): value for key, value in (headers or {}).items()}
    machine_authenticated = bool(request_headers.get("x-gavel-machine-key"))

    identity_context = identity_context_from_headers(request_headers)
    if machine_authenticated:
        identity_context.update(
            {
                "is_authenticated": True,
                "role": "runtime_machine",
                "customer_id": host_id,
                "tenant_id": target_tenant_id,
                "clearance_level": identity_context.get("clearance_level", 0),
                "department": "runtime",
            }
        )

    identity_context.update(
        {
            "customer_id": identity_context.get("customer_id") or host_id,
            "tenant_id": target_tenant_id,
            "clearance_level": identity_context.get("clearance_level", 0),
            "department": "runtime",
        }
    )
    target_endpoint = {
        "method": normalized_method,
        "path": "/external/runtime/validate",
        "tenant_id": target_tenant_id,
        "target_tenant_id": target_tenant_id,
        "required_clearance": required_clearance,
        "action": action,
    }
    is_allowed, reason = query_route.opa_engine.check_routing_allowance(
        identity_context=identity_context,
        target_endpoint=target_endpoint,
    )
    return {
        "is_allowed": is_allowed,
        "reason": reason,
        "reason_code": "POLICY_ALLOW" if is_allowed else "POLICY_DENY",
        "runtime_mode": normalized_runtime_mode,
        "enforcement_capable": enforcement_capable,
        "auth_status": auth_status,
        "control_plane_status": control_plane_status,
        "host_id": host_id,
        "agent_id": agent_id,
        "runtime_os": runtime_os,
        "runtime_arch": runtime_arch,
    }


def _csv_env(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _int_csv_env(name: str) -> list[int]:
    values: list[int] = []
    for item in _csv_env(name):
        try:
            values.append(int(item))
        except ValueError:
            continue
    return values


def _normalize_ipv4_values(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        try:
            normalized.append(str(IPv4Address(value)))
        except ValueError:
            continue
    return normalized


def build_runtime_policy(
    *,
    app,
    host_id: str,
    runtime_os: RuntimeOS | str,
    runtime_arch: str,
    runtime_mode: RuntimeMode | str,
    enforcement_capable: bool,
) -> MachinePolicyResponse:
    control_plane_status = control_plane_status_from_app(app)
    normalized_runtime_mode = (
        runtime_mode.value if isinstance(runtime_mode, RuntimeMode) else runtime_mode
    )
    normalized_runtime_os = runtime_os.value if isinstance(runtime_os, RuntimeOS) else runtime_os

    monitored_pids = _int_csv_env("GAVEL_RUNTIME_MONITORED_PIDS")
    blocked_ipv4 = _normalize_ipv4_values(_csv_env("GAVEL_RUNTIME_BLOCKED_IPS"))
    blocked_targets = _csv_env("GAVEL_RUNTIME_BLOCKED_TARGETS")
    monitored_processes = _csv_env("GAVEL_RUNTIME_MONITORED_PROCESSES")
    proxy_ipv4 = None
    proxy_port = None

    proxy_candidate = os.getenv("GAVEL_RUNTIME_PROXY_IPV4", "").strip()
    if proxy_candidate:
        try:
            proxy_ipv4 = str(IPv4Address(proxy_candidate))
        except ValueError:
            proxy_ipv4 = None

    proxy_port_raw = os.getenv("GAVEL_RUNTIME_PROXY_PORT", "").strip()
    if proxy_port_raw:
        try:
            proxy_port = int(proxy_port_raw)
        except ValueError:
            proxy_port = None

    if normalized_runtime_os == "linux":
        # Linux eBPF runtime currently consumes IPv4 targets only.
        blocked_targets = []
    elif normalized_runtime_os == "windows":
        # Windows can consume both hostnames and literal IPs; fold IPs into the target set.
        blocked_targets = sorted(set(blocked_targets + blocked_ipv4))

    has_runtime_policy = any(
        (
            monitored_pids,
            blocked_ipv4,
            blocked_targets,
            monitored_processes,
            proxy_ipv4 and proxy_port,
        )
    )
    reason_code = "POLICY_SYNC_READY" if has_runtime_policy else "NO_RUNTIME_POLICY"
    if control_plane_status != "online":
        reason_code = "CONTROL_PLANE_DEGRADED"

    return MachinePolicyResponse(
        host_id=host_id,
        runtime_os=normalized_runtime_os,
        runtime_arch=runtime_arch,
        runtime_mode=normalized_runtime_mode,
        enforcement_capable=enforcement_capable,
        auth_status="authenticated",
        control_plane_status=control_plane_status,
        policy_version=os.getenv("GAVEL_RUNTIME_POLICY_VERSION", "2026-03-17"),
        reason_code=reason_code,
        monitored_pids=monitored_pids,
        blocked_ipv4=blocked_ipv4,
        blocked_targets=blocked_targets,
        monitored_processes=monitored_processes,
        proxy_ipv4=proxy_ipv4,
        proxy_port=proxy_port,
    )
