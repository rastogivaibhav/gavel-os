"""
External integration and machine-runtime bridge endpoints.
"""

import logging
from datetime import UTC, datetime

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
    payload_hash: str | None = None
    actor: str | None = None


class ValidateRequest(BaseModel):
    action: str
    method: str = "EXECUTE"
    target_tenant_id: str = "default"
    required_clearance: int = 1


class NetworkPolicyRequest(BaseModel):
    """Request for runtime network action policy evaluation."""

    action: str  # Target hostname or IP
    method: str = "CONNECT"  # CONNECT | GET | POST | EXECUTE
    host_id: str
    runtime_os: str  # linux | windows | macos
    agent_id: str


class ToolProposalRequest(BaseModel):
    """Request for SRP VerdictEngine tool call proposal evaluation."""

    agent_id: str
    tool_call_id: str
    api_ref: str  # e.g., "payments.api"
    operation: str  # e.g., "transfer", "delete", "write"
    environment: str  # dev, staging, prod
    parameters: dict
    tenant_id: str = "default"
    user_id: str | None = None
    replay_nonce: str = ""  # 16+ bytes for replay protection


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
        timestamp=datetime.now(UTC),
    )
    return await ledger.append(event)


async def _broadcast_runtime_event(event: RuntimeEventEnvelope):
    await telemetry_manager.broadcast(
        {"type": event.event_type.value, "payload": event.model_dump(mode="json")}
    )


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
            verdict=RuntimeVerdict.INFO
            if control_plane_status == "online"
            else RuntimeVerdict.DEGRADED,
            reason_code="HEARTBEAT_OK"
            if control_plane_status == "online"
            else "CONTROL_PLANE_DEGRADED",
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
        reason_code="HEARTBEAT_OK"
        if control_plane_status == "online"
        else "CONTROL_PLANE_DEGRADED",
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

    # Always log policy decisions (both ALLOW and DENY) to audit ledger
    audit_outcome = "SUCCESS" if decision["is_allowed"] else "FAILURE"
    await _append_audit_event(
        request,
        recipe_id="runtime-policy-validation",
        step_id="validate-connection",
        actor=payload.host_id,
        action=payload.action,
        target_system=payload.target_tenant_id,
        outcome=audit_outcome,
        payload_hash=f"policy-decision:{decision['reason_code']}",
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
                "reason_description": decision.get("reason", ""),
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
            verdict=RuntimeVerdict.INFO
            if policy.reason_code != "CONTROL_PLANE_DEGRADED"
            else RuntimeVerdict.DEGRADED,
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


@router.post("/network/policy")
@_rate_limit(LIMIT_VALIDATE)
async def evaluate_network_policy(request: Request, payload: NetworkPolicyRequest):
    """
    Evaluate runtime network action policy (sentinel.runtime.policy).

    Used by enforcers to validate network connections against centralized
    runtime policies. This queries the sentinel.runtime.policy OPA package.

    Request:
        action: target hostname or IP
        method: CONNECT | GET | POST | EXECUTE
        host_id: enforcer host identifier
        runtime_os: linux | windows | macos
        agent_id: agent process name

    Response:
        {
            "is_allowed": bool,
            "reason": string,
            "verdict": "ALLOW" | "DENY"
        }
    """
    require_machine_auth(request)

    is_allowed, reason = query_route.opa_engine.evaluate_runtime_policy(
        action=payload.action,
        method=payload.method,
        host_id=payload.host_id,
        runtime_os=payload.runtime_os,
        agent_id=payload.agent_id,
    )

    # Log both ALLOW and DENY to audit ledger
    audit_outcome = "SUCCESS" if is_allowed else "FAILURE"
    await _append_audit_event(
        request,
        recipe_id="runtime-network-policy",
        step_id="network-validation",
        actor=payload.host_id,
        action=f"network.{payload.method.lower()}",
        target_system=payload.action,
        outcome=audit_outcome,
        payload_hash=f"network-policy:{payload.action}",
    )

    await _broadcast_runtime_event(
        RuntimeEventEnvelope(
            event_type=RuntimeEventType.POLICY_VERDICT,
            host_id=payload.host_id,
            agent_id=payload.agent_id,
            target=payload.action,
            verdict=RuntimeVerdict.ALLOW if is_allowed else RuntimeVerdict.DENY,
            reason_code="NETWORK_ALLOW" if is_allowed else "NETWORK_DENY",
            metadata={
                "policy_engine": "opa",
                "policy_package": "sentinel.runtime.policy",
                "method": payload.method,
                "runtime_os": payload.runtime_os,
                "reason": reason,
            },
        )
    )

    return {
        "is_allowed": is_allowed,
        "reason": reason,
        "verdict": "ALLOW" if is_allowed else "DENY",
    }


@router.post("/tool/verdict")
@_rate_limit(LIMIT_VALIDATE)
async def evaluate_tool_proposal(request: Request, payload: ToolProposalRequest):
    """
    Evaluate a tool call proposal using SRP VerdictEngine.

    Deterministic evaluation of structured tool proposals against
    governance policies. Returns ALLOW, ESCALATE, or DENY.

    Request:
        agent_id: calling agent identifier
        tool_call_id: unique identifier for this proposal
        api_ref: API reference (e.g., "payments.api")
        operation: operation type (transfer, delete, write, etc.)
        environment: dev | staging | prod
        parameters: tool parameters as dict
        tenant_id: tenant context
        user_id: optional user context
        replay_nonce: replay attack protection (16+ bytes)

    Response:
        {
            "verdict": "ALLOW" | "ESCALATE" | "DENY",
            "reason_code": string,
            "reasons": [{"code": string, "message": string, ...}],
            "escalation_ticket": string (if ESCALATE),
            "metadata": dict
        }
    """
    require_machine_auth(request)

    verdict_engine = getattr(request.app.state, "verdict_engine", None)
    if not verdict_engine:
        logger.error("SRP VerdictEngine not initialized")
        await _append_audit_event(
            request,
            recipe_id="tool-proposal-verdict",
            step_id="verdict-evaluation",
            actor=payload.agent_id,
            action=f"tool:{payload.operation}",
            target_system=payload.api_ref,
            outcome="FAILURE",
            payload_hash="verdict-engine-unavailable",
        )
        return {
            "verdict": "DENY",
            "reason_code": "VERDICT_ENGINE_UNAVAILABLE",
            "reasons": [{"code": "ENGINE_ERROR", "message": "Verdict engine not available"}],
            "escalation_ticket": None,
            "metadata": {"error": "verdict_engine_unavailable"},
        }

    try:
        # Build proposal for SRP evaluation
        from srp.models import Proposal, ToolCall

        tool_call = ToolCall(
            tool_name="external-tool",
            api_ref=payload.api_ref,
            operation=payload.operation,
            parameters=payload.parameters,
        )

        proposal = Proposal(
            agent_id=payload.agent_id,
            tool_call=tool_call,
            environment=payload.environment,
            replay_nonce=payload.replay_nonce or "default-nonce",
            tenant_id=payload.tenant_id,
        )

        # Evaluate against policies
        verdict = verdict_engine.evaluate(proposal)

        # Determine outcome for audit
        verdict_str = verdict.verdict.value
        audit_outcome = "SUCCESS" if verdict_str == "ALLOW" else "FAILURE"

        # Log to audit ledger (all verdicts)
        await _append_audit_event(
            request,
            recipe_id="tool-proposal-verdict",
            step_id="verdict-evaluation",
            actor=payload.agent_id,
            action=f"tool:{payload.operation}",
            target_system=payload.api_ref,
            outcome=audit_outcome,
            payload_hash=f"proposal:{payload.tool_call_id}",
        )

        # Broadcast verdict event
        await _broadcast_runtime_event(
            RuntimeEventEnvelope(
                event_type=RuntimeEventType.POLICY_VERDICT,
                host_id=request.client.host if request.client else "unknown",
                agent_id=payload.agent_id,
                target=payload.api_ref,
                verdict=(
                    RuntimeVerdict.ALLOW
                    if verdict_str == "ALLOW"
                    else RuntimeVerdict.ESCALATE
                    if verdict_str == "ESCALATE"
                    else RuntimeVerdict.DENY
                ),
                reason_code=f"TOOL_PROPOSAL_{verdict_str}",
                metadata={
                    "tool_call_id": payload.tool_call_id,
                    "api_ref": payload.api_ref,
                    "operation": payload.operation,
                    "environment": payload.environment,
                    "num_reasons": len(verdict.reasons),
                },
            )
        )

        # Handle ESCALATE verdict - create escalation record and send notification
        escalation_ticket = None
        if verdict_str == "ESCALATE":
            try:
                escalation_service = getattr(request.app.state, "escalation_service", None)
                notification_service = getattr(request.app.state, "notification_service", None)

                if escalation_service:
                    # Create escalation record in database
                    escalation_ticket = await escalation_service.create_escalation(
                        tenant_id=payload.tenant_id,
                        tool_call_id=payload.tool_call_id,
                        agent_id=payload.agent_id,
                        api_ref=payload.api_ref,
                        operation=payload.operation,
                        environment=payload.environment,
                        parameters=payload.parameters,
                        risk_level="high" if "payment" in payload.api_ref.lower() else "medium",
                    )
                    logger.info(
                        f"Created escalation {escalation_ticket} for {payload.tool_call_id}"
                    )

                    # Send approval required notification
                    if notification_service:
                        from datetime import timedelta

                        deadline = datetime.now(UTC) + timedelta(hours=24)
                        await notification_service.send_approval_required(
                            tenant_id=payload.tenant_id,
                            escalation_id=f"esc_{payload.tool_call_id[:16]}",
                            ticket_number=escalation_ticket,
                            tool_call_id=payload.tool_call_id,
                            operation=payload.operation,
                            agent_id=payload.agent_id,
                            deadline=deadline,
                            parameters=payload.parameters,
                        )
                        logger.info(f"Sent approval notification for {escalation_ticket}")
            except Exception as exc:
                logger.error(f"Failed to create escalation: {exc}", exc_info=True)
                # Don't fail the request if escalation creation fails, just log it

        # Format response
        return {
            "verdict": verdict_str,
            "reason_code": f"TOOL_PROPOSAL_{verdict_str}",
            "reasons": [
                {
                    "code": reason.code,
                    "message": reason.message,
                    "details": reason.details,
                }
                for reason in verdict.reasons
            ],
            "escalation_ticket": escalation_ticket,
            "metadata": {
                "tool_call_id": payload.tool_call_id,
                "evaluated_at": datetime.now(UTC).isoformat(),
                "engine": "srp",
            },
        }

    except Exception as exc:
        logger.exception(f"Tool proposal verdict evaluation failed: {exc}")
        await _append_audit_event(
            request,
            recipe_id="tool-proposal-verdict",
            step_id="verdict-evaluation",
            actor=payload.agent_id,
            action=f"tool:{payload.operation}",
            target_system=payload.api_ref,
            outcome="FAILURE",
            payload_hash="verdict-evaluation-error",
        )
        return {
            "verdict": "DENY",
            "reason_code": "EVALUATION_ERROR",
            "reasons": [{"code": "ERROR", "message": str(exc), "details": {}}],
            "escalation_ticket": None,
            "metadata": {"error": "evaluation_failed"},
        }
