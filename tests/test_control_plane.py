"""
Tests for api.control_plane — evaluate_runtime_decision and build_runtime_policy.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from api.control_plane import (
    build_runtime_policy,
    evaluate_runtime_decision,
    identity_context_from_headers,
)
from api.runtime_contract import RuntimeMode, RuntimeOS
from auth.jwt_handler import create_token


# ── Helpers ───────────────────────────────────────────────────────────────────

def _online_app():
    """Return a mock app whose state has all required components."""
    app = MagicMock()
    app.state.audit_ledger = MagicMock()
    app.state.policy_loader = MagicMock()
    app.state.verdict_engine = MagicMock()
    return app


def _degraded_app():
    """Return a mock app missing the audit ledger (degraded)."""
    app = MagicMock()
    app.state.audit_ledger = None
    app.state.policy_loader = MagicMock()
    app.state.verdict_engine = MagicMock()
    return app


def _opa_allow():
    return patch(
        "api.control_plane.query_route" if False else "api.routes.query.opa_engine.check_routing_allowance",
        return_value=(True, "Authorized by OPA"),
    )


# ── identity_context_from_headers ─────────────────────────────────────────────

def test_anonymous_context_without_auth_header():
    ctx = identity_context_from_headers({})
    assert ctx["is_authenticated"] is False
    assert ctx["role"] == "anonymous"


def test_authenticated_context_from_valid_jwt():
    token = create_token(role="admin", tenant_id="acme", clearance_level=5)
    ctx = identity_context_from_headers({"authorization": f"Bearer {token}"})
    assert ctx["is_authenticated"] is True
    assert ctx["role"] == "admin"
    assert ctx["tenant_id"] == "acme"
    assert ctx["clearance_level"] == 5


def test_anonymous_context_from_invalid_jwt():
    ctx = identity_context_from_headers({"authorization": "Bearer garbage.token.here"})
    assert ctx["is_authenticated"] is False


def test_tenant_id_from_header_when_no_jwt():
    ctx = identity_context_from_headers({"x-tenant-id": "my-tenant"})
    assert ctx["tenant_id"] == "my-tenant"


# ── evaluate_runtime_decision — degraded control plane ───────────────────────

def test_degraded_control_plane_returns_deny():
    app = _degraded_app()
    with patch("api.control_plane.control_plane_status_from_app", return_value="degraded"):
        result = evaluate_runtime_decision(
            app,
            action="connect:api.example.com",
            method="CONNECT",
            target_tenant_id="default",
            required_clearance=1,
            host_id="host-1",
            agent_id="agent-1",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
            runtime_os="linux",
            runtime_arch="amd64",
        )
    assert result["is_allowed"] is False
    assert result["reason_code"] == "CONTROL_PLANE_DEGRADED"
    assert result["control_plane_status"] == "degraded"


# ── evaluate_runtime_decision — machine auth path ────────────────────────────

def test_machine_auth_sets_runtime_machine_role():
    app = _online_app()
    captured_identity = {}

    def _fake_check(identity_context, target_endpoint):
        captured_identity.update(identity_context)
        return True, "ok"

    with patch("api.control_plane.control_plane_status_from_app", return_value="online"), \
         patch("api.routes.query.opa_engine.check_routing_allowance", side_effect=_fake_check):
        evaluate_runtime_decision(
            app,
            action="connect:api.example.com",
            method="CONNECT",
            target_tenant_id="default",
            required_clearance=1,
            host_id="host-1",
            agent_id="agent-1",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
            runtime_os="linux",
            runtime_arch="amd64",
            headers={"x-gavel-machine-key": "test-machine-key-32-bytes-xxxxxxx"},
        )

    assert captured_identity.get("role") == "runtime_machine"
    assert captured_identity.get("is_authenticated") is True


def test_runtime_decision_does_not_raise_identity_clearance():
    app = _online_app()
    captured_identity = {}

    def _fake_check(identity_context, target_endpoint):
        captured_identity.update(identity_context)
        return False, "insufficient clearance"

    with patch("api.control_plane.control_plane_status_from_app", return_value="online"), \
         patch("api.routes.query.opa_engine.check_routing_allowance", side_effect=_fake_check):
        evaluate_runtime_decision(
            app,
            action="connect:restricted.example.com",
            method="CONNECT",
            target_tenant_id="default",
            required_clearance=7,
            host_id="host-1",
            agent_id="agent-1",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
            runtime_os="linux",
            runtime_arch="amd64",
            headers={"x-gavel-machine-key": "test-machine-key-32-bytes-xxxxxxx"},
        )

    assert captured_identity.get("clearance_level") == 0


# ── build_runtime_policy ──────────────────────────────────────────────────────

def test_build_runtime_policy_no_policy_configured(monkeypatch):
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PIDS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_BLOCKED_IPS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_BLOCKED_TARGETS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PROCESSES", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_IPV4", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_PORT", raising=False)

    app = _online_app()
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"):
        policy = build_runtime_policy(
            app=app,
            host_id="host-1",
            runtime_os=RuntimeOS.LINUX,
            runtime_arch="amd64",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
        )

    assert policy.reason_code == "NO_RUNTIME_POLICY"
    assert policy.monitored_pids == []
    assert policy.blocked_ipv4 == []


def test_build_runtime_policy_with_blocked_ips(monkeypatch):
    monkeypatch.setenv("GAVEL_RUNTIME_BLOCKED_IPS", "10.0.0.1,10.0.0.2")
    monkeypatch.setenv("GAVEL_RUNTIME_MONITORED_PIDS", "101")
    monkeypatch.delenv("GAVEL_RUNTIME_BLOCKED_TARGETS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PROCESSES", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_IPV4", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_PORT", raising=False)

    app = _online_app()
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"):
        policy = build_runtime_policy(
            app=app,
            host_id="host-1",
            runtime_os=RuntimeOS.LINUX,
            runtime_arch="amd64",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
        )

    assert policy.reason_code == "POLICY_SYNC_READY"
    assert "10.0.0.1" in policy.blocked_ipv4
    # Linux: blocked_targets should be empty (IPv4 only)
    assert policy.blocked_targets == []


def test_build_runtime_policy_windows_folds_ips_into_targets(monkeypatch):
    monkeypatch.setenv("GAVEL_RUNTIME_BLOCKED_IPS", "10.0.0.1")
    monkeypatch.setenv("GAVEL_RUNTIME_BLOCKED_TARGETS", "evil.example.com")
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PIDS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PROCESSES", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_IPV4", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_PORT", raising=False)

    app = _online_app()
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"):
        policy = build_runtime_policy(
            app=app,
            host_id="host-1",
            runtime_os=RuntimeOS.WINDOWS,
            runtime_arch="amd64",
            runtime_mode=RuntimeMode.ENFORCE,
            enforcement_capable=True,
        )

    assert "10.0.0.1" in policy.blocked_targets
    assert "evil.example.com" in policy.blocked_targets


def test_build_runtime_policy_degraded_control_plane(monkeypatch):
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PIDS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_BLOCKED_IPS", raising=False)

    app = _degraded_app()
    with patch("api.control_plane.control_plane_status_from_app", return_value="degraded"):
        policy = build_runtime_policy(
            app=app,
            host_id="host-1",
            runtime_os=RuntimeOS.LINUX,
            runtime_arch="amd64",
            runtime_mode=RuntimeMode.AUDIT_ONLY,
            enforcement_capable=False,
        )

    assert policy.reason_code == "CONTROL_PLANE_DEGRADED"
    assert policy.control_plane_status == "degraded"
