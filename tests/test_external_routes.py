"""
Integration tests for api.routes.external — all 5 enforcer-facing endpoints.

Uses httpx AsyncClient with a minimal FastAPI app. External deps (OPA, ledger)
are mocked so no infrastructure is required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.middleware.auth import AuthMiddleware
from api.routes import external as external_router
from auth.jwt_handler import create_token


# ── App factory ───────────────────────────────────────────────────────────────

def _make_app(opa_allow: bool = True) -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.include_router(external_router.router, prefix="/external")

    # Mock app state
    app.state.audit_ledger = AsyncMock()
    app.state.audit_ledger.append = AsyncMock(
        return_value=MagicMock(id=1, current_hash="sha256:abc123")
    )
    app.state.policy_loader = MagicMock()
    app.state.verdict_engine = MagicMock()

    return app


def _machine_headers() -> dict:
    return {"X-Gavel-Machine-Key": "test-machine-key-32-bytes-xxxxxxx"}


def _bearer_headers() -> dict:
    token = create_token(role="customer", clearance_level=2)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def client(monkeypatch):
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "test-machine-key-32-bytes-xxxxxxx")
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── /external/heartbeat ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_heartbeat_requires_machine_auth(client):
    resp = await client.post("/external/heartbeat", json={
        "host_id": "host-1",
        "runtime_os": "linux",
        "runtime_arch": "amd64",
        "runtime_mode": "enforce",
        "enforcement_capable": True,
        "component": "linux-runtime",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_heartbeat_with_machine_key_succeeds(client):
    with patch("api.control_plane.control_plane_status_from_app", return_value="degraded"), \
         patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock):
        resp = await client.post(
            "/external/heartbeat",
            json={
                "host_id": "host-1",
                "runtime_os": "linux",
                "runtime_arch": "amd64",
                "runtime_mode": "enforce",
                "enforcement_capable": True,
                "component": "linux-runtime",
            },
            headers=_machine_headers(),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["host_id"] == "host-1"
    assert "reason_code" in body


# ── /external/runtime/validate ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_runtime_validate_requires_machine_auth(client):
    resp = await client.post("/external/runtime/validate", json={
        "host_id": "host-1",
        "runtime_os": "linux",
        "runtime_arch": "amd64",
        "runtime_mode": "enforce",
        "enforcement_capable": True,
        "action": "connect:api.example.com",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_runtime_validate_allow(client):
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"), \
         patch("api.routes.query.opa_engine.check_routing_allowance") as mock_check, \
         patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock):
        mock_check.return_value = (True, "Authorized by OPA")
        resp = await client.post(
            "/external/runtime/validate",
            json={
                "host_id": "host-1",
                "runtime_os": "linux",
                "runtime_arch": "amd64",
                "runtime_mode": "enforce",
                "enforcement_capable": True,
                "action": "connect:api.example.com",
            },
            headers=_machine_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["is_allowed"] is True


@pytest.mark.asyncio
async def test_runtime_validate_deny(client):
    with patch("api.control_plane.control_plane_status_from_app", return_value="online"), \
         patch("api.routes.query.opa_engine.check_routing_allowance") as mock_check, \
         patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock):
        mock_check.return_value = (False, "Access Denied")
        resp = await client.post(
            "/external/runtime/validate",
            json={
                "host_id": "host-1",
                "runtime_os": "linux",
                "runtime_arch": "amd64",
                "runtime_mode": "enforce",
                "enforcement_capable": True,
                "action": "connect:evil.example.com",
            },
            headers=_machine_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["is_allowed"] is False
    assert resp.json()["reason_code"] == "POLICY_DENY"


# ── /external/runtime/policy ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_runtime_policy_requires_machine_auth(client):
    resp = await client.post("/external/runtime/policy", json={
        "host_id": "host-1",
        "runtime_os": "linux",
        "runtime_arch": "amd64",
        "runtime_mode": "enforce",
        "enforcement_capable": True,
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_runtime_policy_returns_policy_response(client, monkeypatch):
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PIDS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_BLOCKED_IPS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_BLOCKED_TARGETS", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_MONITORED_PROCESSES", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_IPV4", raising=False)
    monkeypatch.delenv("GAVEL_RUNTIME_PROXY_PORT", raising=False)

    with patch("api.control_plane.control_plane_status_from_app", return_value="online"), \
         patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock):
        resp = await client.post(
            "/external/runtime/policy",
            json={
                "host_id": "host-1",
                "runtime_os": "linux",
                "runtime_arch": "amd64",
                "runtime_mode": "enforce",
                "enforcement_capable": True,
            },
            headers=_machine_headers(),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["host_id"] == "host-1"
    assert "reason_code" in body
    assert "policy_version" in body


# ── /external/detect_agent ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detect_agent_requires_machine_auth(client):
    resp = await client.post("/external/detect_agent", json={
        "host_id": "host-1",
        "runtime_os": "windows",
        "runtime_arch": "amd64",
        "runtime_mode": "enforce",
        "enforcement_capable": True,
        "agent_id": "cursor",
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_detect_agent_with_machine_key(client):
    with patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock), \
         patch("api.control_plane.control_plane_status_from_app", return_value="online"):
        resp = await client.post(
            "/external/detect_agent",
            json={
                "host_id": "host-1",
                "runtime_os": "windows",
                "runtime_arch": "amd64",
                "runtime_mode": "enforce",
                "enforcement_capable": True,
                "agent_id": "cursor",
            },
            headers=_machine_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "cursor"


# ── /external/validate (JWT-authenticated) ────────────────────────────────────

@pytest.mark.asyncio
async def test_validate_action_allow(client):
    with patch("api.routes.external.query_route") as mock_qr, \
         patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock):
        mock_qr.opa_engine.check_routing_allowance.return_value = (True, "Authorized by OPA")
        resp = await client.post(
            "/external/validate",
            json={"action": "read.data", "method": "GET", "required_clearance": 1},
            headers=_bearer_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["is_allowed"] is True


@pytest.mark.asyncio
async def test_validate_action_deny(client):
    with patch("api.routes.external.query_route") as mock_qr, \
         patch("api.routes.external.telemetry_manager.broadcast", new_callable=AsyncMock):
        mock_qr.opa_engine.check_routing_allowance.return_value = (False, "Access Denied")
        resp = await client.post(
            "/external/validate",
            json={"action": "data.delete", "method": "EXECUTE", "required_clearance": 1},
            headers=_bearer_headers(),
        )
    assert resp.status_code == 200
    assert resp.json()["is_allowed"] is False
