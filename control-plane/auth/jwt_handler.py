"""
jwt_handler.py — RS256 JWT Authentication

Provides RSA asymmetric key JWT token generation and verification.
Auto-generates a 2048-bit RSA key pair on first startup if not configured.

Production: Set JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH env vars.
Development: Keys are auto-generated to auth/keys/ on first use.
"""

from __future__ import annotations

import os
import time
import logging
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Request

logger = logging.getLogger("auth")

_JWT_EXPIRY_SECONDS = int(os.getenv("JWT_EXPIRY_SECONDS", "3600"))

# ── Key Management ────────────────────────────────────────────────────────────

_KEYS_DIR = Path(__file__).resolve().parent / "keys"
_PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", str(_KEYS_DIR / "private.pem"))
_PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", str(_KEYS_DIR / "public.pem"))


def _load_or_generate_keys() -> tuple[bytes, bytes]:
    """Load existing RSA keys or generate a new 2048-bit pair.

    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    priv_path = Path(_PRIVATE_KEY_PATH)
    pub_path = Path(_PUBLIC_KEY_PATH)

    if priv_path.exists() and pub_path.exists():
        private_key = priv_path.read_bytes()
        public_key = pub_path.read_bytes()
        logger.info("Loaded RSA keys from %s", priv_path.parent)
        return private_key, public_key

    # Generate new RSA key pair
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Persist to disk
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)

    logger.info("Generated new RSA-2048 key pair at %s", priv_path.parent)
    return private_pem, public_pem


# Load keys at module init — fail fast if something is wrong
_PRIVATE_KEY, _PUBLIC_KEY = _load_or_generate_keys()


# ── Token Operations ──────────────────────────────────────────────────────────

def create_token(
    role: str = "customer",
    customer_id: Optional[str] = None,
    tenant_id: str = "default",
    clearance_level: int = 1,
    department: str = "external",
) -> str:
    """Generate an RS256-signed JWT token with the given claims.

    The token is signed with the RSA private key, so only the holder
    of the private key can issue tokens. Anyone with the public key
    can verify them.

    Returns:
        An RS256-signed JWT string.
    """
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + _JWT_EXPIRY_SECONDS,
        "role": role,
        "customer_id": customer_id,
        "tenant_id": tenant_id,
        "clearance_level": clearance_level,
        "department": department,
    }
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256")


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token using the RSA public key.

    Raises:
        jwt.ExpiredSignatureError: If the token has expired.
        jwt.InvalidTokenError: If the token is malformed or signature invalid.

    Returns:
        The decoded payload dictionary.
    """
    return jwt.decode(token, _PUBLIC_KEY, algorithms=["RS256"])


def get_public_key_pem() -> str:
    """Return the public key PEM for external verification (e.g., JWKS endpoint)."""
    return _PUBLIC_KEY.decode("utf-8")


def extract_identity_context(request: Request) -> dict:
    """Extracts PBAC identity attributes from the request's JWT.

    Checks the Authorization header for a Bearer token. If valid, returns
    the decoded claims. If missing or invalid, returns anonymous context.
    """
    context = {
        "is_authenticated": False,
        "role": "anonymous",
        "customer_id": None,
        "tenant_id": "default",
        "clearance_level": 0,
        "department": "public",
    }

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return context

    token = auth_header[7:]
    try:
        payload = verify_token(token)
        context.update(
            {
                "is_authenticated": True,
                "role": payload.get("role", "customer"),
                "customer_id": payload.get("customer_id"),
                "tenant_id": payload.get("tenant_id", "default"),
                "clearance_level": payload.get("clearance_level", 1),
                "department": payload.get("department", "external"),
            }
        )
        logger.debug(
            "Extracted verified JWT context: role=%s tenant=%s",
            context["role"],
            context["tenant_id"],
        )
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid JWT token: %s", e)

    return context
