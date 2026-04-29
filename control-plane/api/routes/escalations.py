"""Escalation workflow endpoints."""

import logging
from fastapi import APIRouter, HTTPException, Depends, Request

from api.dependencies import get_tenant_context
from models.escalation import EscalationApprove, EscalationStatus
from models.tenant import TenantContext
from service.escalation_service import EscalationService

logger = logging.getLogger("sentinel.escalations")
router = APIRouter(prefix="/escalations", tags=["escalations"])


# This would be injected from the app
_escalation_service: EscalationService | None = None


def set_escalation_service(service: EscalationService):
    """Set the escalation service (called during app initialization)."""
    global _escalation_service
    _escalation_service = service


async def get_escalation_service() -> EscalationService:
    """Dependency to get escalation service."""
    if not _escalation_service:
        raise HTTPException(
            status_code=503,
            detail="Escalation service not initialized"
        )
    return _escalation_service


@router.get("/{escalation_id}")
async def get_escalation_status(
    escalation_id: str,
    tenant_context: TenantContext = Depends(get_tenant_context),
    service: EscalationService = Depends(get_escalation_service),
) -> EscalationStatus:
    """Get status of an escalation."""
    status = await service.get_escalation_status(
        tenant_context.tenant_id,
        escalation_id
    )

    if not status:
        raise HTTPException(
            status_code=404,
            detail=f"Escalation {escalation_id} not found"
        )

    return status


@router.post("/{escalation_id}/approve")
async def approve_escalation(
    escalation_id: str,
    decision: EscalationApprove,
    request: Request,
    tenant_context: TenantContext = Depends(get_tenant_context),
    service: EscalationService = Depends(get_escalation_service),
) -> dict:
    """Approve or deny an escalation."""
    if not tenant_context.is_authenticated:
        raise HTTPException(
            status_code=401,
            detail="Authentication required to approve escalations"
        )

    success, message = await service.approve_escalation(
        tenant_context.tenant_id,
        escalation_id,
        tenant_context.user_id or "unknown",
        decision.decision,
        decision.reason
    )

    if not success:
        raise HTTPException(
            status_code=400,
            detail=message
        )

    # Send notification about approval/denial
    notification_service = getattr(request.app.state, "notification_service", None)
    if notification_service and success:
        try:
            # Get escalation details to include in notification
            esc_status = await service.get_escalation_status(
                tenant_context.tenant_id,
                escalation_id
            )

            if esc_status:
                if decision.decision == "approved":
                    await notification_service.send_approval_granted(
                        tenant_id=tenant_context.tenant_id,
                        escalation_id=escalation_id,
                        ticket_number=esc_status.get("ticket_number", "UNKNOWN"),
                        tool_call_id=esc_status.get("ticket_number", "").split("-")[1] if "-" in esc_status.get("ticket_number", "") else "UNKNOWN",
                        operation="unknown",
                        agent_id="unknown",
                        approver_id=tenant_context.user_id or "unknown",
                        reason=decision.reason,
                    )
                else:
                    await notification_service.send_approval_denied(
                        tenant_id=tenant_context.tenant_id,
                        escalation_id=escalation_id,
                        ticket_number=esc_status.get("ticket_number", "UNKNOWN"),
                        tool_call_id=esc_status.get("ticket_number", "").split("-")[1] if "-" in esc_status.get("ticket_number", "") else "UNKNOWN",
                        operation="unknown",
                        agent_id="unknown",
                        approver_id=tenant_context.user_id or "unknown",
                        reason=decision.reason,
                    )
                logger.info(f"Sent {decision.decision} notification for {escalation_id}")
        except Exception as exc:
            logger.error(f"Failed to send approval notification: {exc}")
            # Don't fail the request if notification fails

    return {
        "escalation_id": escalation_id,
        "decision": decision.decision,
        "message": message,
    }


@router.get("")
async def list_pending_escalations(
    tenant_context: TenantContext = Depends(get_tenant_context),
    service: EscalationService = Depends(get_escalation_service),
) -> dict:
    """List pending escalations for current tenant."""
    escalations = await service.get_pending_escalations(tenant_context.tenant_id)

    return {
        "count": len(escalations),
        "escalations": escalations,
    }
