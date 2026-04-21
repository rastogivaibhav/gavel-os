"""
Tests for api.middleware.auth.AuthMiddleware.

Uses httpx AsyncClient against a minimal FastAPI app that mounts the middleware.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from api.middleware.auth import AuthMiddleware
from auth.jwt_handler import create_token


# ── Minimal app fixture ───────────────────────────────────────────────────────

def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


@pytest_asyncio.fixture
async def client():
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── Public paths bypass auth ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_is_public(client):
    resp = await client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_protected_without_auth_returns_401(client):
    resp = await client.get("/protected")
    assert resp.status_code == 401


# ── Bearer JWT auth ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_bearer_token_allows_access(client):
    token = create_token(role="customer")
    resp = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_invalid_bearer_token_returns_401(client):
    resp = await client.get("/protected", headers={"Authorization": "Bearer not.a.real.token"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_expired_bearer_token_returns_401(monkeypatch, client):
    import auth.jwt_handler as jh
    monkeypatch.setattr(jh, "_JWT_EXPIRY_SECONDS", -10)
    token = jh.create_token()
    monkeypatch.setattr(jh, "_JWT_EXPIRY_SECONDS", 3600)
    resp = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


# ── API key auth ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_api_key_allows_access(client, monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "test-api-key-value")
    resp = await client.get("/protected", headers={"X-API-Key": "test-api-key-value"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_wrong_api_key_returns_401(client, monkeypatch):
    monkeypatch.setenv("API_SECRET_KEY", "correct-key")
    resp = await client.get("/protected", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


# ── Machine key auth ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_machine_key_allows_access(client, monkeypatch):
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "test-machine-key-32-bytes-xxxxxxx")
    resp = await client.get(
        "/protected",
        headers={"X-Gavel-Machine-Key": "test-machine-key-32-bytes-xxxxxxx"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_wrong_machine_key_returns_401(client, monkeypatch):
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "correct-machine-key-32-bytes-xxx")
    resp = await client.get(
        "/protected",
        headers={"X-Gavel-Machine-Key": "wrong-machine-key"},
    )
    assert resp.status_code == 401


# ── Dev auth bypass guard ─────────────────────────────────────────────────────

def test_insecure_dev_auth_rejected_in_production(monkeypatch):
    """Module-level guard: sys.exit(1) if ALLOW_INSECURE_DEV_AUTH=true and ENV!=development."""
    import importlib
    import sys

    monkeypatch.setenv("ALLOW_INSECURE_DEV_AUTH", "true")
    monkeypatch.setenv("ENV", "production")

    # Remove cached module so the guard re-runs on import
    mod_name = "api.middleware.auth"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    with pytest.raises(SystemExit) as exc_info:
        import api.middleware.auth  # noqa: F401

    assert exc_info.value.code == 1

    # Restore
    monkeypatch.setenv("ENV", "development")
    if mod_name in sys.modules:
        del sys.modules[mod_name]
