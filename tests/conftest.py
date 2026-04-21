"""
conftest.py — Shared pytest fixtures for Gavel OS control plane tests.

All fixtures that need the FastAPI app use a fully isolated app instance
with mocked external dependencies (OPA, Postgres, Redis) so tests run
without any infrastructure.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Make control-plane packages importable ────────────────────────────────────
_CP = Path(__file__).resolve().parent.parent / "control-plane"
if str(_CP) not in sys.path:
    sys.path.insert(0, str(_CP))

# ── Minimal env so module-level guards don't fire ────────────────────────────
os.environ.setdefault("ENV", "development")
os.environ.setdefault("ALLOW_INSECURE_DEV_AUTH", "false")
os.environ.setdefault("GAVEL_MACHINE_KEY", "test-machine-key-32-bytes-xxxxxxx")
os.environ.setdefault("API_SECRET_KEY", "test-api-key")
os.environ.setdefault("ADMIN_SECRET_KEY", "test-admin-secret")
os.environ.setdefault("GRPC_INSECURE", "true")
os.environ.setdefault("OPA_URL", "http://localhost:18181")   # nothing listening — mocked


# ── Shared proposal factory ───────────────────────────────────────────────────

def make_proposal(**overrides):
    """Return a minimal valid Proposal dict, with optional field overrides."""
    from srp.models import CallerContext, Proposal, ToolCall

    defaults = dict(
        caller=CallerContext(tenant_id="test-tenant", caller_id="agent-1", role="customer"),
        tool_call=ToolCall(api_ref="payments.api", operation="read", parameters={}),
        environment="dev",
        replay_nonce="a" * 16,
    )
    defaults.update(overrides)
    return Proposal(**defaults)


@pytest.fixture
def proposal():
    return make_proposal()


# ── App fixture with all external deps mocked ─────────────────────────────────

@pytest.fixture
def mock_app_state():
    """Return a namespace that looks like FastAPI app.state with all deps present."""
    state = MagicMock()
    state.audit_ledger = AsyncMock()
    state.policy_loader = MagicMock()
    state.verdict_engine = MagicMock()
    state.db_pool = AsyncMock()
    return state


@pytest.fixture
def mock_opa_allow(monkeypatch):
    """Patch OPAValidationEngine to always allow."""
    from sentinel.opa_engine import OPAValidationEngine
    monkeypatch.setattr(OPAValidationEngine, "is_available", lambda self: True)
    monkeypatch.setattr(
        OPAValidationEngine,
        "check_routing_allowance",
        lambda self, **kw: (True, "Authorized by OPA"),
    )


@pytest.fixture
def mock_opa_deny(monkeypatch):
    """Patch OPAValidationEngine to always deny."""
    from sentinel.opa_engine import OPAValidationEngine
    monkeypatch.setattr(OPAValidationEngine, "is_available", lambda self: True)
    monkeypatch.setattr(
        OPAValidationEngine,
        "check_routing_allowance",
        lambda self, **kw: (False, "Access Denied by PBAC Rego Rules"),
    )


@pytest.fixture
def mock_opa_unavailable(monkeypatch):
    """Patch OPAValidationEngine to report unavailable."""
    from sentinel.opa_engine import OPAValidationEngine
    monkeypatch.setattr(OPAValidationEngine, "is_available", lambda self: False)
