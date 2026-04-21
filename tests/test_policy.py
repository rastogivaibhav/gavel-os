"""
Tests for srp.policy — evaluate_policies and _matches.
"""

from __future__ import annotations

import pytest

from srp.models import CallerContext, ToolCall, VerdictType
from srp.policy import (
    PolicyCondition,
    PolicyEffect,
    PolicyEvaluationResult,
    PolicyRule,
    PolicySet,
    evaluate_policies,
)
from tests.conftest import make_proposal


def _rule(
    effect: PolicyEffect = PolicyEffect.BLOCK,
    priority: int = 100,
    rule_id: str = "r1",
    **condition_kwargs,
) -> PolicyRule:
    return PolicyRule(
        id=rule_id,
        description="test",
        effect=effect,
        condition=PolicyCondition(**condition_kwargs),
        priority=priority,
    )


def _policy(*rules: PolicyRule) -> PolicySet:
    return PolicySet(name="test", version="1.0", rules=list(rules))


# ── No rules → no verdict ─────────────────────────────────────────────────────

def test_empty_policy_set_returns_no_verdict():
    result = evaluate_policies(_policy(), make_proposal())
    assert result.verdict is None
    assert result.reasons == []
    assert result.policy_ids == []


# ── Tenant matching ───────────────────────────────────────────────────────────

def test_tenant_match_triggers_rule():
    result = evaluate_policies(_policy(_rule(tenants=["test-tenant"])), make_proposal())
    assert result.verdict == VerdictType.BLOCK


def test_tenant_mismatch_skips_rule():
    result = evaluate_policies(_policy(_rule(tenants=["other-tenant"])), make_proposal())
    assert result.verdict is None


# ── Role matching ─────────────────────────────────────────────────────────────

def test_role_match_triggers_rule():
    result = evaluate_policies(_policy(_rule(roles=["customer"])), make_proposal())
    assert result.verdict == VerdictType.BLOCK


def test_role_mismatch_skips_rule():
    result = evaluate_policies(_policy(_rule(roles=["admin"])), make_proposal())
    assert result.verdict is None


def test_no_role_on_caller_skips_role_rule():
    p = make_proposal(
        caller=CallerContext(tenant_id="test-tenant", caller_id="agent-1", role=None)
    )
    result = evaluate_policies(_policy(_rule(roles=["customer"])), p)
    assert result.verdict is None


# ── Environment matching ──────────────────────────────────────────────────────

def test_environment_match():
    result = evaluate_policies(_policy(_rule(environments=["dev"])), make_proposal())
    assert result.verdict == VerdictType.BLOCK


def test_environment_mismatch():
    result = evaluate_policies(_policy(_rule(environments=["prod"])), make_proposal())
    assert result.verdict is None


# ── api_ref matching ──────────────────────────────────────────────────────────

def test_api_ref_match():
    result = evaluate_policies(_policy(_rule(api_refs=["payments.api"])), make_proposal())
    assert result.verdict == VerdictType.BLOCK


def test_api_ref_mismatch():
    result = evaluate_policies(_policy(_rule(api_refs=["other.api"])), make_proposal())
    assert result.verdict is None


# ── Operation matching ────────────────────────────────────────────────────────

def test_operation_match():
    result = evaluate_policies(_policy(_rule(operations=["read"])), make_proposal())
    assert result.verdict == VerdictType.BLOCK


def test_operation_mismatch():
    result = evaluate_policies(_policy(_rule(operations=["write"])), make_proposal())
    assert result.verdict is None


# ── Numeric parameter constraints ─────────────────────────────────────────────

def test_numeric_param_exceeded_triggers_rule():
    p = make_proposal(
        tool_call=ToolCall(
            api_ref="payments.api",
            operation="transfer",
            parameters={"amount": 1001.0},
        )
    )
    rule = _rule(max_numeric_parameters={"amount": 1000.0})
    result = evaluate_policies(_policy(rule), p)
    assert result.verdict == VerdictType.BLOCK


def test_numeric_param_at_limit_does_not_trigger():
    p = make_proposal(
        tool_call=ToolCall(
            api_ref="payments.api",
            operation="transfer",
            parameters={"amount": 1000.0},
        )
    )
    rule = _rule(max_numeric_parameters={"amount": 1000.0})
    result = evaluate_policies(_policy(rule), p)
    assert result.verdict is None


def test_numeric_param_missing_does_not_trigger():
    p = make_proposal(
        tool_call=ToolCall(api_ref="payments.api", operation="transfer", parameters={})
    )
    rule = _rule(max_numeric_parameters={"amount": 100.0})
    result = evaluate_policies(_policy(rule), p)
    assert result.verdict is None


def test_numeric_param_non_numeric_skips_rule():
    p = make_proposal(
        tool_call=ToolCall(
            api_ref="payments.api",
            operation="transfer",
            parameters={"amount": "lots"},
        )
    )
    rule = _rule(max_numeric_parameters={"amount": 100.0})
    result = evaluate_policies(_policy(rule), p)
    assert result.verdict is None


# ── Priority ordering ─────────────────────────────────────────────────────────

def test_lower_priority_rule_wins():
    allow_rule = _rule(effect=PolicyEffect.ALLOW, priority=50, rule_id="allow")
    block_rule = _rule(effect=PolicyEffect.BLOCK, priority=200, rule_id="block")
    result = evaluate_policies(_policy(block_rule, allow_rule), make_proposal())
    assert result.verdict == VerdictType.ALLOW
    assert result.policy_ids == ["allow"]


def test_same_priority_sorted_by_id():
    rule_b = _rule(effect=PolicyEffect.BLOCK, priority=100, rule_id="b-rule")
    rule_a = _rule(effect=PolicyEffect.ALLOW, priority=100, rule_id="a-rule")
    result = evaluate_policies(_policy(rule_b, rule_a), make_proposal())
    # "a-rule" sorts before "b-rule" alphabetically
    assert result.policy_ids == ["a-rule"]


# ── AND semantics: all conditions must match ──────────────────────────────────

def test_all_conditions_must_match():
    # tenant matches but role does not → no trigger
    rule = _rule(tenants=["test-tenant"], roles=["admin"])
    result = evaluate_policies(_policy(rule), make_proposal())
    assert result.verdict is None


def test_all_conditions_match_triggers():
    rule = _rule(tenants=["test-tenant"], roles=["customer"], environments=["dev"])
    result = evaluate_policies(_policy(rule), make_proposal())
    assert result.verdict == VerdictType.BLOCK
