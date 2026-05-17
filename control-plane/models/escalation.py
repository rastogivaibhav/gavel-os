"""Escalation workflow models."""

from datetime import datetime

from pydantic import BaseModel, Field


class EscalationReason(BaseModel):
    """Reason for escalation."""

    code: str = Field(..., description="Reason code")
    message: str = Field(..., description="Human-readable reason")
    risk_level: str = Field(default="medium", description="Risk assessment")


class EscalationCreate(BaseModel):
    """Request to create escalation."""

    agent_id: str
    tool_call_id: str
    api_ref: str
    operation: str
    environment: str
    parameters: dict
    reason: EscalationReason


class EscalationApprove(BaseModel):
    """Request to approve escalation."""

    decision: str = Field(..., description="'approved' or 'denied'")
    reason: str | None = None


class EscalationStatus(BaseModel):
    """Escalation status response."""

    id: str
    ticket_number: str
    status: str  # pending, approved, denied, expired
    created_at: datetime
    deadline: datetime
    approvals: list[dict] = Field(default_factory=list)
    reason: str | None = None


class Escalation(BaseModel):
    """Complete escalation record."""

    id: str
    tenant_id: str
    tool_call_id: str
    agent_id: str
    api_ref: str
    operation: str
    environment: str
    status: str
    ticket_number: str
    created_at: datetime
    updated_at: datetime
    deadline: datetime
    parameters: dict = Field(default_factory=dict)
    risk_level: str
