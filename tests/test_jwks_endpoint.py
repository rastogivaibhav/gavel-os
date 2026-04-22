"""
Tests for GET /auth/jwks and GET /.well-known/jwks.json

These endpoints are critical for key rotation — downstream services
cache the JWKS and verify tokens without calling back to the control plane.
"""

from __future__ import annotations

import base64

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from api.middleware.auth import AuthMiddleware
from auth.jwt_handler import create_token, get_jwks, _LOCAL_KID


def _make_jwks_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/auth/jwks")
    async def jwks():
        import os
        from fastapi.responses import JSONResponse
        from auth.jwt_handler import get_jwks as _get_jwks
        ttl = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
        return JSONResponse(
            content=_get_jwks(),
            headers={"Cache-Control": f"public, max-age={ttl}"},
        )

    @app.get("/.well-known/jwks.json")
    async def jwks_well_known():
        import os
        from fastapi.responses import JSONResponse
        from auth.jwt_handler import get_jwks as _get_jwks
        ttl = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
        return JSONResponse(
            content=_get_jwks(),
            headers={"Cache-Control": f"public, max-age={ttl}"},
        )

    return app


@pytest_asyncio.fixture
async def client():
    app = _make_jwks_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── /auth/jwks ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_jwks_endpoint_returns_200(client):
    resp = await client.get("/auth/jwks")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_jwks_endpoint_returns_rsa_key(client):
    resp = await client.get("/auth/jwks")
    body = resp.json()
    assert "keys" in body
    assert len(body["keys"]) == 1
    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "n" in key
    assert "e" in key


@pytest.mark.asyncio
async def test_jwks_endpoint_kid_matches_issued_tokens(client):
    resp = await client.get("/auth/jwks")
    jwks_kid = resp.json()["keys"][0]["kid"]
    token = create_token()
    import jwt as pyjwt
    header = pyjwt.get_unverified_header(token)
    assert header["kid"] == jwks_kid


@pytest.mark.asyncio
async def test_jwks_endpoint_has_cache_control_header(client):
    resp = await client.get("/auth/jwks")
    assert "Cache-Control" in resp.headers
    assert "max-age" in resp.headers["Cache-Control"]


@pytest.mark.asyncio
async def test_jwks_endpoint_is_public_no_auth_required(client):
    """JWKS must be accessible without authentication."""
    resp = await client.get("/auth/jwks")
    assert resp.status_code != 401


# ── /.well-known/jwks.json ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_well_known_jwks_returns_same_key(client):
    resp1 = await client.get("/auth/jwks")
    resp2 = await client.get("/.well-known/jwks.json")
    assert resp1.json() == resp2.json()


# ── Round-trip: JWKS → verify token ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_jwks_key_can_verify_issued_token(client):
    """Token issued by the control plane must be verifiable using the JWKS public key."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    resp = await client.get("/auth/jwks")
    key_data = resp.json()["keys"][0]

    def _b64_to_int(s: str) -> int:
        padded = s + "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    pub = RSAPublicNumbers(
        e=_b64_to_int(key_data["e"]),
        n=_b64_to_int(key_data["n"]),
    ).public_key()
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    token = create_token(role="customer", tenant_id="acme", clearance_level=3)
    payload = pyjwt.decode(token, pub_pem, algorithms=["RS256"])

    assert payload["role"] == "customer"
    assert payload["tenant_id"] == "acme"
    assert payload["clearance_level"] == 3
