"""Regression tests for control-plane token minting controls."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from api.main import app, validate_production_config
from auth.jwt_handler import verify_token


@pytest_asyncio.fixture
async def client(monkeypatch):
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("ADMIN_SECRET_KEY", "test-admin-secret-32-bytes-long")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_public_dev_token_uses_fixed_low_privilege_claims(client):
    response = await client.post(
        "/auth/token",
        json={"role": "customer", "tenant_id": "default", "clearance_level": 1},
    )

    assert response.status_code == 200
    claims = verify_token(response.json()["access_token"])
    assert claims["role"] == "customer"
    assert claims["tenant_id"] == "default"
    assert claims["clearance_level"] == 1
    assert claims["department"] == "external"


@pytest.mark.asyncio
async def test_public_dev_token_rejects_custom_claims(client):
    response = await client.post(
        "/auth/token",
        json={"role": "customer", "tenant_id": "other-tenant", "clearance_level": 999},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_public_dev_token_rejects_valid_but_custom_claims(client):
    response = await client.post(
        "/auth/token",
        json={"role": "customer", "tenant_id": "other-tenant", "clearance_level": 5},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_secret_can_mint_custom_claims(client):
    response = await client.post(
        "/auth/token",
        json={"role": "auditor", "tenant_id": "acme", "clearance_level": 5},
        headers={"X-Admin-Secret": "test-admin-secret-32-bytes-long"},
    )

    assert response.status_code == 200
    claims = verify_token(response.json()["access_token"])
    assert claims["role"] == "auditor"
    assert claims["tenant_id"] == "acme"
    assert claims["clearance_level"] == 5


@pytest.mark.asyncio
async def test_production_token_minting_requires_admin_secret(client, monkeypatch):
    monkeypatch.setenv("ENV", "production")
    response = await client.post("/auth/token", json={})

    assert response.status_code == 401


def test_production_config_rejects_dev_defaults(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("GAVEL_MACHINE_KEY", "dev-machine-key-change-in-production")
    monkeypatch.setenv("API_SECRET_KEY", "dev-api-key-change-in-production")
    monkeypatch.setenv("ADMIN_SECRET_KEY", "dev-admin-secret-change-in-production")
    monkeypatch.setenv("METRICS_SECRET_KEY", "dev-metrics-key")
    monkeypatch.setenv("ALLOW_INSECURE_DEV_AUTH", "false")

    with pytest.raises(RuntimeError, match="Refusing to start"):
        validate_production_config()
