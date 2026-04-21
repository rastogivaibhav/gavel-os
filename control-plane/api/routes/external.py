"""
External integration and machine-runtime bridge endpoints.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from api.control_plane import (
    build_runtime_policy,
    control_plane_status_from_app,
    evaluate_runtime_decision,
    require_machine_auth,
)
from api.middleware.rate_limit import (
    LIMIT_HEARTBEAT,
    LIMIT_POLICY,
    LIMIT_TELEMETRY,
    LIMIT_VALIDATE,
    limiter,
)
from api.routes import query as query_route
from api.routes.telemetry import manager as telemetry_manager
from api.runtime_contract import (
    MachineAgentDetectionRequest,
    MachineHeartbeatRequest,
    MachineHeartbeatResponse,
    MachinePolicyRequest,
    MachinePolicyResponse,
    MachineValidateRequest,
    RuntimeEventEnvelope,
    RuntimeEventType,
    RuntimeVerdict,
)
from auth.jwt_handler import extract_identity_context
from srp.sdk.models import AuditEvent

router = APIRouter()
logger = logging.getLogger("sentinel.external")

# Decorator helper: no-op when limiter is unavailable
def _rate_limit(limit_string: str):
    if limiter is None:
        def _noop(fn):
            return fn
        return _noop
    return limiter.limit(limit_string)


class IngestRequest(BaseModel):
    recipe_id: str = "external-activity"
    step_id: str
    action: str
    target_system: str
    outcome: str = "SUCCESS"
    payload_hash: Optional[str] = None
    actor: Optional[str] = None


class ValidateRequest(BaseModel):
    action: str
    method: str = "EXECUTE"
    target_tenant_id: str = "default"
    required_clearance: int = 1


def _control_plane_status(request: Request) -> str:
    return control_plane_status_from_app(request.app)


async def _append_audit_event(
    request: Request,
    *,
    recipe_id: str,
    step_id: str,
    actor: str,
    action: str,
    target_system: str,
    outcome: str,
    payload_hash: str = "n/a",
):
    ledger = getattr(request.app.state, "audit_ledger", None)
    if not ledger:
        return None

    event = AuditEvent(
        recipe_id=recipe_id,
        step_id=step_id,
        actor=actor,
        action=action,
        target_system=target_system,
        payload_hash=payload_hash,
        outcome=outcome,
        timestamp=datetime.now(timezone.utc),
    )
    return await ledger.append(event)


async def _broadcast_runtime_event(event: RuntimeEventEnvelope):
    await telemetry_manager.broadcast({"type": event.event_type.value, "payload": event.model_dump(mode="json")})


@router.post("/ingest")
async def ingest_activity(request: Request, payload: IngestRequest):
    ledger = getattr(request.app.state, "audit_ledger", None)
    if not ledger:
        raise HTTPException(status_code=503, detail="Audit ledger unavailable")

    identity = extract_identity_context(request)
    actor = payload.actor or identity.get("customer_id") or "external-agent"

    try:
        entry = await _append_audit_event(
            request,
            recipe_id=payload.recipe_id,
            step_id=payload.step_id,
            actor=actor,
            action=payload.action,
            target_system=payload.target_system,
            outcome=payload.outcome,
            payload_hash=payload.payload_hash or "sha256:000000000000000000000",
        )

        await telemetry_manager.broadcast(
            {
                "type": "AUDIT_LOG",
                "payload": {
                    "actor": actor,
                    "action": payload.action,
                    "outcome": payload.outcome,
                },
            }
        )
        return {"status": "ingested", "entry_id": entry.id, "hash": entry.current_hash}
    except Exception as exc:
        logger.error("External ingestion failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to append to ledger") from exc


@router.post("/validate")
async def validate_action(request: Request, payload: ValidateRequest):
    identity = extract_identity_context(request)
    target_endpoint = {
        "method": payload.method,
        "target_tenant_id": payload.target_tenant_id,
        "required_clearance": payload.required_clearance,
        "action": payload.action,
    }
    is_allowed, reason = query_route.opa_engine.check_routing_allowance(
        identity_context=identity,
        target_endpoint=target_endpoint,
    )

    if not is_allowed:
        await _append_audit_event(
            request,
            recipe_id="policy-violation",
            step_id="external-validation",
            actor=identity.get("customer_id") or "external-agent",
            action=payload.action,
            target_system="internal-policy",
            outcome="FAILURE",
        )
        await telemetry_manager.broadcast(
            {
                "type": "FIREWALL_ALERT",
                "payload": {
                    "verdict": "DENY",
                    "target": payload.action,
                    "pid": "ExternalAgent",
                    "reason": reason,
                },
            }
        )

    return {"is_allowed": is_allowed, "reason": reason}


@router.post("/detect_agent")
async def detect_agent(request: Request, payload: MachineAgentDetectionRequest):
    require_machine_auth(request)
    actor = payload.host_id
    await _append_audit_event(
        request,
        recipe_id="runtime-agent-detection",
        step_id="detect-agent",
        actor=actor,
        action=f"detect:{payload.agent_id}",
        target_system=payload.target,
        outcome="SUCCESS",
    )

    await _broadcast_runtime_event(
        RuntimeEventEnvelope(
            event_type=RuntimeEventType.AGENT_DETECTED,
            host_id=payload.host_id,
            runtime_os=payload.runtime_os,
            runtime_arch=payload.runtime_arch,
            agent_id=payload.agent_id,
            target=payload.target,
            verdict=RuntimeVerdict.INFO,
            reason_code=payload.reason_code,
            metadata=payload.metadata,
        )
    )
    return {
        "status": "detected",
        "agent_id": payload.agent_id,
        "runtime_mode": payload.runtime_mode.value,
        "control_plane_status": _control_plane_status(request),
    }


@router.post("/heartbeat", response_model=MachineHeartbeatResponse)
@_rate_limit(LIMIT_HEARTBEAT)
async def runtime_heartbeat(request: Request, payload: MachineHeartbeatRequest):
    require_machine_auth(request)
    control_plane_status = _control_plane_status(request)
    await _broadcast_runtime_event(
        RuntimeEventEnvelope(
            event_type=RuntimeEventType.COMPONENT_HEALTH,
            host_id=payload.host_id,
            runtime_os=payload.runtime_os,
            runtime_arch=payload.runtime_arch,
            target=payload.component,
            verdict=RuntimeVerdict.INFO if control_plane_status == "online" else RuntimeVerdict.DEGRADED,
            reason_code="HEARTBEAT_OK" if control_plane_status == "online" else "CONTROL_PLANE_DEGRADED",
            metadata={
                "component": payload.component,
                "status": control_plane_status,
                "runtime_mode": payload.runtime_mode.value,
                "enforcement_capable": payload.enforcement_capable,
            },
        )
    )
    return MachineHeartbeatResponse(
        host_id=payload.host_id,
        runtime_os=payload.runtime_os,
        runtime_arch=payload.runtime_arch,
        runtime_mode=payload.runtime_mode,
        enforcement_capable=payload.enforcement_capable,
        auth_status="authenticated",
        control_plane_status=control_plane_status,
        reason_code="HEARTBEAT_OK" if control_plane_status == "online" else "CONTROL_PLANE_DEGRADED",
    )


@router.post("/runtime/validate")
@_rate_limit(LIMIT_VALIDATE)
async def validate_runtime_action(request: Request, payload: MachineValidateRequest):
    require_machine_auth(request)
    decision = evaluate_runtime_decision(
        request.app,
        action=payload.action,
        method=payload.method,
        target_tenant_id=payload.target_tenant_id,
        required_clearance=payload.required_clearance,
        host_id=payload.host_id,
        agent_id=payload.agent_id,
        runtime_mode=payload.runtime_mode,
        enforcement_capable=payload.enforcement_capable,
        runtime_os=payload.runtime_os.value,
        runtime_arch=payload.runtime_arch,
        headers={key.lower(): value for key, value in request.headers.items()},
    )

    if not decision["is_allowed"]:
        await _append_audit_event(
            request,
            recipe_id="runtime-policy-validation",
            step_id="validate-connection",
            actor=payload.host_id,
            action=payload.action,
            target_system=payload.target_tenant_id,
            outcome="FAILURE",
        )

    await _broadcast_runtime_event(
        RuntimeEventEnvelope(
            event_type=RuntimeEventType.POLICY_VERDICT,
            host_id=payload.host_id,
            runtime_os=payload.runtime_os,
            runtime_arch=payload.runtime_arch,
            agent_id=payload.agent_id,
            target=payload.action,
            verdict=RuntimeVerdict.ALLOW if decision["is_allowed"] else RuntimeVerdict.DENY,
            reason_code=decision["reason_code"],
            metadata={
                "component": "control-plane",
                "target_kind": payload.method,
                "runtime_mode": payload.runtime_mode.value,
                "enforcement_capable": payload.enforcement_capable,
            },
        )
    )

    return decision


@router.post("/runtime/policy", response_model=MachinePolicyResponse)
@_rate_limit(LIMIT_POLICY)
async def get_runtime_policy(request: Request, payload: MachinePolicyRequest):
    require_machine_auth(request)
    policy = build_runtime_policy(
        app=request.app,
        host_id=payload.host_id,
        runtime_os=payload.runtime_os,
        runtime_arch=payload.runtime_arch,
        runtime_mode=payload.runtime_mode,
        enforcement_capable=payload.enforcement_capable,
    )
    await _broadcast_runtime_event(
        RuntimeEventEnvelope(
            event_type=RuntimeEventType.COMPONENT_HEALTH,
            host_id=payload.host_id,
            runtime_os=payload.runtime_os,
            runtime_arch=payload.runtime_arch,
            agent_id=payload.agent_id,
            target=payload.component,
            verdict=RuntimeVerdict.INFO if policy.reason_code != "CONTROL_PLANE_DEGRADED" else RuntimeVerdict.DEGRADED,
            reason_code=policy.reason_code,
            metadata={
                "component": payload.component,
                "status": policy.control_plane_status,
                "runtime_mode": policy.runtime_mode.value,
                "enforcement_capable": policy.enforcement_capable,
            },
        )
    )
    return policy
