"""Test fixtures for UI integration tests."""

import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import sys
import os

# Add control-plane to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "control-plane"))

from api.main import app


@pytest.fixture
async def client():
    """Create async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost:8000") as ac:
        yield ac


@pytest.fixture
async def auth_token(client):
    """Get a valid JWT token for testing."""
    response = await client.post("/auth/token", json={
        "role": "customer",
        "clearance_level": 1,
        "tenant_id": "default"
    })
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
async def authenticated_client(client, auth_token):
    """Create authenticated async HTTP client."""
    client.headers.update({"Authorization": f"Bearer {auth_token}"})
    return client


