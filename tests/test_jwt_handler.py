"""
Tests for auth.jwt_handler — token creation, verification, expiry, JWKS.
"""

from __future__ import annotations

import time

import pytest
import jwt as pyjwt

from auth.jwt_handler import (
    _LOCAL_KID,
    _PRIVATE_KEY,
    _PUBLIC_KEY,
    create_token,
    get_jwks,
    verify_token,
)


# ── Token creation ────────────────────────────────────────────────────────────

def test_create_token_returns_string():
    token = create_token()
    assert isinstance(token, str)
    assert len(token) > 50


def test_created_token_has_kid_header():
    token = create_token()
    header = pyjwt.get_unverified_header(token)
    assert header.get("kid") == _LOCAL_KID


def test_created_token_has_correct_claims():
    token = create_token(
        role="admin",
        customer_id="cust-123",
        tenant_id="acme",
        clearance_level=3,
        department="security",
    )
    payload = verify_token(token)
    assert payload["role"] == "admin"
    assert payload["customer_id"] == "cust-123"
    assert payload["tenant_id"] == "acme"
    assert payload["clearance_level"] == 3
    assert payload["department"] == "security"


def test_created_token_has_iat_and_exp():
    before = int(time.time())
    token = create_token()
    after = int(time.time())
    payload = verify_token(token)
    assert before <= payload["iat"] <= after
    assert payload["exp"] > payload["iat"]


# ── Token verification ────────────────────────────────────────────────────────

def test_verify_valid_token():
    token = create_token(role="customer")
    payload = verify_token(token)
    assert payload["role"] == "customer"


def test_verify_rejects_tampered_token():
    token = create_token()
    parts = token.split(".")
    # Flip a byte in the signature
    tampered = parts[0] + "." + parts[1] + "." + parts[2][:-4] + "XXXX"
    with pytest.raises(pyjwt.InvalidTokenError):
        verify_token(tampered)


def test_verify_rejects_expired_token(monkeypatch):
    import auth.jwt_handler as jh
    # Issue a token that expired 10 seconds ago
    original_expiry = jh._JWT_EXPIRY_SECONDS
    monkeypatch.setattr(jh, "_JWT_EXPIRY_SECONDS", -10)
    token = jh.create_token()
    monkeypatch.setattr(jh, "_JWT_EXPIRY_SECONDS", original_expiry)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        verify_token(token)


def test_verify_rejects_garbage():
    with pytest.raises(pyjwt.InvalidTokenError):
        verify_token("not.a.token")


def test_verify_rejects_wrong_algorithm():
    # HS256-signed token should be rejected
    hs_token = pyjwt.encode({"sub": "x", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
    with pytest.raises(pyjwt.InvalidTokenError):
        verify_token(hs_token)


# ── JWKS export ───────────────────────────────────────────────────────────────

def test_get_jwks_returns_rsa_key():
    jwks = get_jwks()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert key["kid"] == _LOCAL_KID
    assert "n" in key and "e" in key


def test_get_jwks_n_and_e_are_base64url():
    import base64
    jwks = get_jwks()
    key = jwks["keys"][0]
    # Should decode without error
    for field in ("n", "e"):
        padded = key[field] + "=" * (-len(key[field]) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        assert len(decoded) > 0


def test_jwks_key_can_verify_issued_token():
    """Round-trip: issue a token, reconstruct the public key from JWKS, verify."""
    import base64
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    jwks = get_jwks()
    key_data = jwks["keys"][0]

    def _b64_to_int(s: str) -> int:
        padded = s + "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    pub = RSAPublicNumbers(
        e=_b64_to_int(key_data["e"]),
        n=_b64_to_int(key_data["n"]),
    ).public_key()
    pub_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    token = create_token(role="customer")
    payload = pyjwt.decode(token, pub_pem, algorithms=["RS256"])
    assert payload["role"] == "customer"
