"""
Tests for srp.verdict_engine.VerdictEngine — deterministic proposal evaluation.
"""

from __future__ import annotations

import json

import pytest

from srp.models import CallerContext, Proposal, ToolCall, VerdictType
from srp.policy import PolicyCondition, PolicyEffect, PolicyRule, PolicySet
from srp.verdict_engine import VerdictEngine, VerdictEngineConfig
from tests.conftest import make_proposal


# ── Helpers ───────────────────────────────────────────────────────────────────

def _engine(**config_kwargs) -> VerdictEngine:
    return VerdictEngine(VerdictEngineConfig(**config_kwargs))


# ── Rule 1: environment validation ───────────────────────────────────────────

def test_allow_valid_environments():
    for env in ("dev", "staging", "prod"):
        p = make_proposal(environment=env)
        v = VerdictEngine().evaluate(p)
        assert v.verdict == VerdictType.ALLOW, f"Expected ALLOW for env={env}"


def test_block_invalid_environment():
    p = make_proposal(environment="production")  # not in the allowed set
    v = VerdictEngine().evaluate(p)
    assert v.verdict == VerdictType.BLOCK
    assert any(r.code == "ENV_INVALID" for r in v.reasons)


# ── Rule 2: replay nonce strength ────────────────────────────────────────────

def test_block_short_nonce():
    p = make_proposal(replay_nonce="short")
    v = VerdictEngine().evaluate(p)
    assert v.verdict == VerdictType.BLOCK
    assert any(r.code == "REPLAY_NONCE_WEAK" for r in v.reasons)


def test_allow_exactly_16_char_nonce():
    p = make_proposal(replay_nonce="a" * 16)
    v = VerdictEngine().evaluate(p)
    assert v.verdict == VerdictType.ALLOW


def test_allow_long_nonce():
    p = make_proposal(replay_nonce="x" * 64)
    v = VerdictEngine().evaluate(p)
    assert v.verdict == VerdictType.ALLOW


# ── Rule 3: api_ref allowlist ─────────────────────────────────────────────────

def test_block_api_ref_not_in_allowlist():
    engine = _engine(allowed_api_refs={"allowed.api"})
    p = make_proposal()  # tool_call.api_ref = "payments.api"
    v = engine.evaluate(p)
    assert v.verdict == VerdictType.BLOCK
    assert any(r.code == "API_NOT_ALLOWED" for r in v.reasons)


def test_allow_api_ref_in_allowlist():
    engine = _engine(allowed_api_refs={"payments.api"})
    p = make_proposal()
    v = engine.evaluate(p)
    assert v.verdict == VerdictType.ALLOW


def test_no_allowlist_permits_any_api_ref():
    engine = _engine(allowed_api_refs=None)
    p = make_proposal()
    v = engine.evaluate(p)
    assert v.verdict == VerdictType.ALLOW


# ── Rule 4: parameter size limit ─────────────────────────────────────────────

def test_block_oversized_parameters():
    big_params = {"data": "x" * 20_000}
    p = make_proposal(
        tool_call=ToolCall(api_ref="payments.api", operation="read", parameters=big_params)
    )
    v = _engine(max_parameters_bytes=100).evaluate(p)
    assert v.verdict == VerdictType.BLOCK
    assert any(r.code == "PARAM_TOO_LARGE" for r in v.reasons)


def test_allow_parameters_within_limit():
    p = make_proposal(
        tool_call=ToolCall(api_ref="payments.api", operation="read", parameters={"k": "v"})
    )
    v = VerdictEngine().evaluate(p)
    assert v.verdict == VerdictType.ALLOW


# ── Reason truncation ─────────────────────────────────────────────────────────

def test_reasons_truncated_to_max():
    # Trigger multiple blocking reasons simultaneously
    p = make_proposal(
        environment="bad-env",
        replay_nonce="x",  # too short
        tool_call=ToolCall(api_ref="blocked.api", operation="read", parameters={"d": "x" * 20_000}),
    )
    engine = _engine(
        allowed_api_refs={"other.api"},
        max_parameters_bytes=10,
        max_reasons=2,
    )
    v = engine.evaluate(p)
    assert len(v.reasons) <= 2


# ── OK reason on clean pass ───────────────────────────────────────────────────

def test_ok_reason_on_clean_allow():
    v = VerdictEngine().evaluate(make_proposal())
    assert v.verdict == VerdictType.ALLOW
    assert any(r.code == "OK" for r in v.reasons)


# ── Policy set integration ────────────────────────────────────────────────────

def _make_policy_set(effect: PolicyEffect, **condition_kwargs) -> PolicySet:
    return PolicySet(
        name="test",
        version="1.0",
        rules=[
            PolicyRule(
                id="rule-1",
                description="test rule",
                effect=effect,
                condition=PolicyCondition(**condition_kwargs),
                priority=100,
            )
        ],
    )


def test_policy_set_block_overrides_base_allow():
    policy = _make_policy_set(PolicyEffect.BLOCK, tenants=["test-tenant"])
    engine = _engine(policy_set=policy)
    v = engine.evaluate(make_proposal())
    assert v.verdict == VerdictType.BLOCK
    assert "rule-1" in v.policy_ids


def test_policy_set_escalate():
    policy = _make_policy_set(PolicyEffect.ESCALATE, tenants=["test-tenant"])
    engine = _engine(policy_set=policy)
    v = engine.evaluate(make_proposal())
    assert v.verdict == VerdictType.ESCALATE


def test_policy_set_no_match_does_not_change_verdict():
    policy = _make_policy_set(PolicyEffect.BLOCK, tenants=["other-tenant"])
    engine = _engine(policy_set=policy)
    v = engine.evaluate(make_proposal())
    assert v.verdict == VerdictType.ALLOW


# ── Proposal ID is preserved ──────────────────────────────────────────────────

def test_verdict_carries_proposal_id():
    p = make_proposal()
    v = VerdictEngine().evaluate(p)
    assert v.proposal_id == p.id
