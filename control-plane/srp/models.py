from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, constr, field_validator, ConfigDict


class VerdictType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class CallerContext(BaseModel):
    """Context about the caller of the proposal."""

    tenant_id: constr(strip_whitespace=True, min_length=1)
    caller_id: constr(strip_whitespace=True, min_length=1)
    role: Optional[constr(strip_whitespace=True, min_length=1)] = None
    session_id: Optional[constr(strip_whitespace=True, min_length=1)] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class ToolCall(BaseModel):
    """A single tool/API call proposed by an agent."""

    api_ref: constr(strip_whitespace=True, min_length=1)
    operation: constr(strip_whitespace=True, min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)

    recipe_id: Optional[str] = None
    recipe_version: Optional[str] = None
    tool_name: Optional[str] = None


class Proposal(BaseModel):
    """Canonical proposal schema for enforcement decisions."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    caller: CallerContext
    tool_call: ToolCall

    environment: Literal["dev", "staging", "prod"] = "dev"
    origin: Literal["openai", "crew", "langgraph", "openclaw", "internal", "other"] = "other"

    # Accept hostile/invalid inputs; enforcement layer determines strength.
    replay_nonce: constr(strip_whitespace=True, min_length=1)

    model_config = ConfigDict(extra="forbid")

    @field_validator("timestamp", mode="before")
    def _ensure_timezone(cls, value: datetime) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
        return value


class VerdictReason(BaseModel):
    """Explanation for a verdict decision."""

    code: constr(strip_whitespace=True, min_length=1)
    message: constr(strip_whitespace=True, min_length=1)
    details: Dict[str, Any] = Field(default_factory=dict)


class Verdict(BaseModel):
    """Deterministic verdict for a proposal."""

    proposal_id: UUID
    verdict: VerdictType
    reasons: List[VerdictReason] = Field(default_factory=list)
    policy_ids: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="forbid")

