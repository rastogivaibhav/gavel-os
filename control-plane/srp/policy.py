from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, conlist, constr

from .models import Proposal, VerdictReason, VerdictType


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class PolicyCondition(BaseModel):
    """Match conditions for a policy rule.

    All specified fields must match (logical AND). Each field is treated as
    a set membership check (value must be in the configured list).
    """

    tenants: conlist(constr(strip_whitespace=True, min_length=1), min_length=1) | None = None
    roles: conlist(constr(strip_whitespace=True, min_length=1), min_length=1) | None = None
    environments: conlist(constr(strip_whitespace=True, min_length=1), min_length=1) | None = None
    api_refs: conlist(constr(strip_whitespace=True, min_length=1), min_length=1) | None = None
    operations: conlist(constr(strip_whitespace=True, min_length=1), min_length=1) | None = None

    # Minimal numeric parameter constraints: parameters[field] <= max_value
    max_numeric_parameters: dict[str, float] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    """Single policy rule."""

    id: constr(strip_whitespace=True, min_length=1)
    description: constr(strip_whitespace=True, min_length=1)
    effect: PolicyEffect
    condition: PolicyCondition

    priority: int = 1000


class PolicySet(BaseModel):
    """Ordered set of policy rules."""

    name: constr(strip_whitespace=True, min_length=1)
    version: constr(strip_whitespace=True, min_length=1)
    rules: list[PolicyRule]

    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class PolicyEvaluationResult:
    verdict: VerdictType | None
    reasons: list[VerdictReason]
    policy_ids: list[str]


def evaluate_policies(policy_set: PolicySet, proposal: Proposal) -> PolicyEvaluationResult:
    """Evaluate policies against a proposal.

    Rules are evaluated in ascending priority order, then by id. First
    matching rule decides the effect.
    """
    sorted_rules: Sequence[PolicyRule] = sorted(policy_set.rules, key=lambda r: (r.priority, r.id))

    for rule in sorted_rules:
        if not _matches(rule.condition, proposal):
            continue

        verdict = VerdictType(rule.effect.value)
        reason = VerdictReason(
            code=f"POLICY_{rule.effect.value}",
            message=rule.description,
            details={"policy_id": rule.id},
        )
        return PolicyEvaluationResult(
            verdict=verdict,
            reasons=[reason],
            policy_ids=[rule.id],
        )

    # No rule matched
    return PolicyEvaluationResult(verdict=None, reasons=[], policy_ids=[])


def _matches(cond: PolicyCondition, proposal: Proposal) -> bool:
    caller = proposal.caller
    tool_call = proposal.tool_call

    if cond.tenants is not None and caller.tenant_id not in cond.tenants:
        return False

    if cond.roles is not None:
        if caller.role is None or caller.role not in cond.roles:
            return False

    if cond.environments is not None and proposal.environment not in cond.environments:
        return False

    if cond.api_refs is not None and tool_call.api_ref not in cond.api_refs:
        return False

    if cond.operations is not None and tool_call.operation not in cond.operations:
        return False

    # Numeric parameter constraints
    #
    # Semantics: `max_numeric_parameters` defines deterministic *limits*.
    # The rule matches when at least one specified field exists and exceeds
    # its max value. (This supports "BLOCK above X" policies.)
    params: dict[str, Any] = tool_call.parameters or {}
    if cond.max_numeric_parameters:
        exceeded = False
        for field, max_value in cond.max_numeric_parameters.items():
            value = params.get(field)
            if value is None:
                continue
            if not isinstance(value, int | float):
                return False
            if float(value) > float(max_value):
                exceeded = True
        if not exceeded:
            return False

    return True
