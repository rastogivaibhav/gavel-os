"""
Tests for sentinel.opa_engine.OPAValidationEngine.

All tests mock the HTTP layer — no real OPA instance required.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from sentinel.opa_engine import OPAValidationEngine


def _engine() -> OPAValidationEngine:
    return OPAValidationEngine()


def _identity(authenticated: bool = True, clearance: int = 1, role: str = "customer") -> dict:
    return {
        "is_authenticated": authenticated,
        "role": role,
        "clearance_level": clearance,
        "tenant_id": "default",
        "department": "runtime",
    }


def _endpoint(action: str = "read.data", required_clearance: int = 1) -> dict:
    return {
        "method": "GET",
        "path": "/external/validate",
        "action": action,
        "required_clearance": required_clearance,
        "target_tenant_id": "default",
    }


# ── is_available ──────────────────────────────────────────────────────────────

def test_is_available_returns_true_on_200():
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = b"{}"

    with patch("sentinel.opa_engine.urlopen", return_value=mock_resp):
        assert _engine().is_available() is True


def test_is_available_returns_false_on_connection_error():
    with patch("sentinel.opa_engine.urlopen", side_effect=URLError("refused")):
        assert _engine().is_available() is False


def test_is_available_returns_false_on_timeout():
    with patch("sentinel.opa_engine.urlopen", side_effect=TimeoutError()):
        assert _engine().is_available() is False


# ── check_routing_allowance ───────────────────────────────────────────────────

def _mock_opa_response(result: bool):
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = json.dumps({"result": result}).encode()
    return mock_resp


def test_allow_when_opa_returns_true():
    engine = _engine()
    health_resp = MagicMock()
    health_resp.__enter__ = lambda s: s
    health_resp.__exit__ = MagicMock(return_value=False)
    health_resp.read.return_value = b"{}"

    allow_resp = _mock_opa_response(True)

    with patch("sentinel.opa_engine.urlopen", side_effect=[health_resp, allow_resp]):
        allowed, reason = engine.check_routing_allowance(
            identity_context=_identity(),
            target_endpoint=_endpoint(),
        )
    assert allowed is True
    assert "Authorized" in reason


def test_deny_when_opa_returns_false():
    engine = _engine()
    health_resp = MagicMock()
    health_resp.__enter__ = lambda s: s
    health_resp.__exit__ = MagicMock(return_value=False)
    health_resp.read.return_value = b"{}"

    deny_resp = _mock_opa_response(False)

    with patch("sentinel.opa_engine.urlopen", side_effect=[health_resp, deny_resp]):
        allowed, reason = engine.check_routing_allowance(
            identity_context=_identity(),
            target_endpoint=_endpoint(),
        )
    assert allowed is False
    assert "Denied" in reason or "denied" in reason.lower()


def test_deny_when_opa_unavailable():
    with patch("sentinel.opa_engine.urlopen", side_effect=URLError("refused")):
        allowed, reason = _engine().check_routing_allowance(
            identity_context=_identity(),
            target_endpoint=_endpoint(),
        )
    assert allowed is False
    assert "Unavailable" in reason or "unavailable" in reason.lower()


def test_deny_on_opa_exception_during_evaluation():
    engine = _engine()
    health_resp = MagicMock()
    health_resp.__enter__ = lambda s: s
    health_resp.__exit__ = MagicMock(return_value=False)
    health_resp.read.return_value = b"{}"

    with patch(
        "sentinel.opa_engine.urlopen",
        side_effect=[health_resp, Exception("unexpected")],
    ):
        allowed, reason = engine.check_routing_allowance(
            identity_context=_identity(),
            target_endpoint=_endpoint(),
        )
    assert allowed is False


def test_opa_url_from_env(monkeypatch):
    monkeypatch.setenv("OPA_URL", "http://custom-opa:9999")
    engine = OPAValidationEngine()
    assert engine.base_url == "http://custom-opa:9999"


def test_opa_package_path_from_env(monkeypatch):
    monkeypatch.setenv("OPA_PACKAGE_PATH", "my/custom/authz")
    engine = OPAValidationEngine()
    assert engine.package_path == "my/custom/authz"
