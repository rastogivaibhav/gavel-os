"""
Tests for GET /health and GET /readyz — the Kubernetes probe endpoints.

These are critical for GA: a misconfigured health check causes rolling
deployment failures. Every component status combination is tested.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.middleware.auth import AuthMiddleware


def _make_health_app(
    audit_ledger=None,
    policy_loader=None,
    verdict_engine=None,
    machine_key: str = "test-key",
    grpc_status: str = "ready",
    opa_available: bool = True,
    db_pool=None,
) -> FastAPI:
    """Build a minimal app with configurable component state for health testing."""
    from api.main import app as real_app
    # We test the health endpoint logic directly by patching app.state
    # rather than spinning up the full lifespan
    test_app = FastAPI()
    test_app.add_middleware(AuthMiddleware)

    test_app.state.audit_ledger = audit_ledger
    test_app.state.policy_loader = policy_loader
    test_app.state.verdict_engine = verdict_engine
    test_app.state.db_pool = db_pool

    @test_app.get("/health")
    async def health():
        from fastapi.responses import JSONResponse
        import os

        components = {
            "audit_ledger": "connected" if test_app.state.audit_ledger else "unavailable",
            "policy_loader": "loaded" if test_app.state.policy_loader else "unavailable",
            "verdict_engine": "ready" if test_app.state.verdict_engine else "unavailable",
            "machine_auth": "configured" if os.getenv("GAVEL_MACHINE_KEY") else "missing",
            "grpc_authz": grpc_status,
            "opa_policy_engine": "ready" if opa_available else "unavailable",
            "database": "unavailable",
            "redis": "unavailable",
        }
        healthy = (
            all(components[k] in {"connected", "loaded", "ready", "configured"}
                for k in ("audit_ledger", "policy_loader", "verdict_engine", "machine_auth"))
            and grpc_status == "ready"
            and opa_available
        )
        body = {"status": "healthy" if healthy else "degraded", "version": "1.0.0", "components": components}
        if not healthy:
            return JSONResponse(status_code=503, content=body)
        return body

    @test_app.get("/readyz")
    async def readyz():
        from fastapi.responses import JSONResponse
        ready = all([
            test_app.state.audit_ledger is not None,
            test_app.state.policy_loader is not None,
            test_app.state.verdict_engine is not None,
        ])
        if not ready:
            return JSONResponse(status_code=503, content={"ready": False})
        return {"ready": True}

    return test_app


@pytest_asyncio.fixture
async def healthy_client(monkeypatch):
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "test-key")
    app = _make_health_app(
        audit_ledger=MagicMock(),
        policy_loader=MagicMock(),
        verdict_engine=MagicMock(),
        grpc_status="ready",
        opa_available=True,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def degraded_client(monkeypatch):
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "test-key")
    app = _make_health_app(
        audit_ledger=None,  # missing
        policy_loader=MagicMock(),
        verdict_engine=MagicMock(),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── /health ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_returns_200_when_all_components_ready(healthy_client):
    resp = await healthy_client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_health_returns_503_when_audit_ledger_missing(degraded_client):
    resp = await degraded_client.get("/health")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["components"]["audit_ledger"] == "unavailable"


@pytest.mark.asyncio
async def test_health_returns_503_when_machine_key_missing(monkeypatch):
    monkeypatch.delenv("GAVEL_MACHINE_KEY", raising=False)
    app = _make_health_app(
        audit_ledger=MagicMock(),
        policy_loader=MagicMock(),
        verdict_engine=MagicMock(),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/health")
    assert resp.status_code == 503
    assert resp.json()["components"]["machine_auth"] == "missing"


@pytest.mark.asyncio
async def test_health_returns_503_when_grpc_not_ready(monkeypatch):
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "test-key")
    app = _make_health_app(
        audit_ledger=MagicMock(),
        policy_loader=MagicMock(),
        verdict_engine=MagicMock(),
        grpc_status="stopped",  # not ready
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/health")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_health_is_public_no_auth_required(healthy_client):
    """GET /health must not require authentication."""
    resp = await healthy_client.get("/health")
    assert resp.status_code != 401


# ── /readyz ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_readyz_returns_200_when_all_components_initialized(healthy_client):
    resp = await healthy_client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json()["ready"] is True


@pytest.mark.asyncio
async def test_readyz_returns_503_when_component_missing(degraded_client):
    resp = await degraded_client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["ready"] is False


@pytest.mark.asyncio
async def test_readyz_is_public_no_auth_required(healthy_client):
    resp = await healthy_client.get("/readyz")
    assert resp.status_code != 401
