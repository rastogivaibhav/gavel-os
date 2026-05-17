from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, constr, field_validator


class VerdictType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class CallerContext(BaseModel):
    """Context about the caller of the proposal."""

    tenant_id: constr(strip_whitespace=True, min_length=1)
    caller_id: constr(strip_whitespace=True, min_length=1)
    role: constr(strip_whitespace=True, min_length=1) | None = None
    session_id: constr(strip_whitespace=True, min_length=1) | None = None
    ip_address: str | None = None
    user_agent: str | None = None


class ToolCall(BaseModel):
    """A single tool/API call proposed by an agent."""

    api_ref: constr(strip_whitespace=True, min_length=1)
    operation: constr(strip_whitespace=True, min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)

    recipe_id: str | None = None
    recipe_version: str | None = None
    tool_name: str | None = None


class Proposal(BaseModel):
    """Canonical proposal schema for enforcement decisions."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    caller: CallerContext
    tool_call: ToolCall

    environment: constr(strip_whitespace=True, min_length=1) = "dev"
    origin: Literal["openai", "crew", "langgraph", "openclaw", "internal", "other"] = "other"

    # Accept hostile/invalid inputs; enforcement layer determines strength.
    replay_nonce: constr(strip_whitespace=True, min_length=1)

    model_config = ConfigDict(extra="forbid")

    @field_validator("timestamp", mode="before")
    def _ensure_timezone(cls, value: datetime) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
        return value


class VerdictReason(BaseModel):
    """Explanation for a verdict decision."""

    code: constr(strip_whitespace=True, min_length=1)
    message: constr(strip_whitespace=True, min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)


class Verdict(BaseModel):
    """Deterministic verdict for a proposal."""

    proposal_id: UUID
    verdict: VerdictType
    reasons: list[VerdictReason] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = ConfigDict(extra="forbid")
