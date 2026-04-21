"""
jwt_handler.py — RS256 JWT Authentication with JWKS support

Token issuance:  RS256, signed with the local RSA private key.
Token verification: checks local public key first; if JWKS_URL is set,
                    also fetches remote keys so tokens issued by a key-rotation
                    event are still accepted during the overlap window.

Key management:
  Production:   Set JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH.
  Development:  Keys are auto-generated to auth/keys/ on first use.
  Key rotation: Set JWKS_URL to an external JWKS endpoint. Tokens signed
                by any key in the JWKS are accepted. The local key is always
                tried first to avoid a network round-trip on the hot path.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import threading
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen

import jwt
from fastapi import Request

logger = logging.getLogger("auth")

_JWT_EXPIRY_SECONDS = int(os.getenv("JWT_EXPIRY_SECONDS", "3600"))

# ── Key paths ─────────────────────────────────────────────────────────────────

_KEYS_DIR = Path(__file__).resolve().parent / "keys"
_PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", str(_KEYS_DIR / "private.pem"))
_PUBLIC_KEY_PATH  = os.getenv("JWT_PUBLIC_KEY_PATH",  str(_KEYS_DIR / "public.pem"))

# ── Key ID (kid) — used in JWKS and JWT header ────────────────────────────────
# Defaults to a hash of the public key so it changes automatically on rotation.
_KEY_ID: str = os.getenv("JWT_KEY_ID", "")


def _load_or_generate_keys() -> tuple[bytes, bytes]:
    priv_path = Path(_PRIVATE_KEY_PATH)
    pub_path  = Path(_PUBLIC_KEY_PATH)

    if priv_path.exists() and pub_path.exists():
        private_key = priv_path.read_bytes()
        public_key  = pub_path.read_bytes()
        logger.info("Loaded RSA keys from %s", priv_path.parent)
        return private_key, public_key

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    logger.info("Generated new RSA-2048 key pair at %s", priv_path.parent)
    return private_pem, public_pem


_PRIVATE_KEY, _PUBLIC_KEY = _load_or_generate_keys()


def _derive_key_id(public_key_pem: bytes) -> str:
    """Derive a stable key ID from the public key bytes (first 8 hex chars of SHA-256)."""
    import hashlib
    return hashlib.sha256(public_key_pem).hexdigest()[:16]


_LOCAL_KID: str = _KEY_ID or _derive_key_id(_PUBLIC_KEY)


# ── JWKS remote key cache ─────────────────────────────────────────────────────

class _JWKSCache:
    """
    Thread-safe cache for remote JWKS public keys.

    Refreshes every JWKS_CACHE_TTL_SECONDS (default 300) seconds.
    Keys are indexed by 'kid' claim. If a token has no 'kid', all cached
    keys are tried in order.
    """

    _TTL = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))

    def __init__(self, jwks_url: str) -> None:
        self._url = jwks_url
        self._keys: dict[str, bytes] = {}   # kid → public key PEM
        self._fetched_at: float = 0.0
        self._lock = threading.Lock()

    def _fetch(self) -> None:
        try:
            with urlopen(self._url, timeout=5) as resp:
                data = json.loads(resp.read())
        except (URLError, json.JSONDecodeError, Exception) as exc:
            logger.warning("JWKS fetch from %s failed: %s", self._url, exc)
            return

        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        def _b64_to_int(s: str) -> int:
            padded = s + "=" * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        keys: dict[str, bytes] = {}
        for jwk in data.get("keys", []):
            if jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig":
                continue
            try:
                pub = RSAPublicNumbers(
                    e=_b64_to_int(jwk["e"]),
                    n=_b64_to_int(jwk["n"]),
                ).public_key()
                pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                kid = jwk.get("kid", _derive_key_id(pem))
                keys[kid] = pem
            except Exception as exc:
                logger.warning("Failed to parse JWK (kid=%s): %s", jwk.get("kid"), exc)

        with self._lock:
            self._keys = keys
            self._fetched_at = time.monotonic()
        logger.info("JWKS refreshed: %d key(s) loaded from %s", len(keys), self._url)

    def get_keys(self) -> dict[str, bytes]:
        with self._lock:
            age = time.monotonic() - self._fetched_at
            stale = age > self._TTL

        if stale:
            self._fetch()

        with self._lock:
            return dict(self._keys)


_JWKS_URL = os.getenv("JWKS_URL", "").strip()
_jwks_cache: _JWKSCache | None = _JWKSCache(_JWKS_URL) if _JWKS_URL else None


# ── Token operations ──────────────────────────────────────────────────────────

def create_token(
    role: str = "customer",
    customer_id: Optional[str] = None,
    tenant_id: str = "default",
    clearance_level: int = 1,
    department: str = "external",
) -> str:
    """Issue an RS256-signed JWT. The 'kid' header identifies the signing key."""
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
    return jwt.encode(
        payload,
        _PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": _LOCAL_KID},
    )


def verify_token(token: str) -> dict:
    """
    Verify an RS256 JWT.

    Verification order:
      1. Local public key (fast path, no network).
      2. Remote JWKS keys (if JWKS_URL is configured and the local key fails).

    Raises jwt.InvalidTokenError on any failure.
    """
    # Decode the header to get kid without full verification
    unverified_header = jwt.get_unverified_header(token)
    token_kid = unverified_header.get("kid", "")

    # 1. Try local key — always attempt if kid matches or is absent.
    #    Also try if kid is present but doesn't match, in case the caller
    #    is using a stale kid value but the key itself is still valid.
    local_exc: Exception | None = None
    try:
        return jwt.decode(token, _PUBLIC_KEY, algorithms=["RS256"])
    except jwt.InvalidTokenError as exc:
        local_exc = exc
        if not _jwks_cache:
            raise

    # 2. Try remote JWKS keys (only reached when JWKS_URL is configured)
    if _jwks_cache:
        remote_keys = _jwks_cache.get_keys()
        candidates = (
            [remote_keys[token_kid]] if token_kid and token_kid in remote_keys
            else list(remote_keys.values())
        )
        last_exc: Exception = local_exc or jwt.InvalidTokenError("No matching key found in JWKS")
        for key_pem in candidates:
            try:
                return jwt.decode(token, key_pem, algorithms=["RS256"])
            except jwt.InvalidTokenError as exc:
                last_exc = exc
        raise last_exc

    raise jwt.InvalidTokenError("Token verification failed: no valid key found")


def get_public_key_pem() -> str:
    """Return the local public key PEM (for the /auth/jwks endpoint)."""
    return _PUBLIC_KEY.decode("utf-8")


def get_jwks() -> dict:
    """
    Return the local public key as a JWKS document.

    Suitable for serving at /.well-known/jwks.json or /auth/jwks so that
    downstream services can verify tokens without calling back to this service.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    pub = load_pem_public_key(_PUBLIC_KEY)
    if not isinstance(pub, RSAPublicKey):
        raise ValueError("Only RSA public keys are supported for JWKS export")

    # load_pem_public_key returns a public key directly — call public_numbers() on it.
    pub_numbers = pub.public_numbers()

    def _int_to_b64(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": _LOCAL_KID,
                "n": _int_to_b64(pub_numbers.n),
                "e": _int_to_b64(pub_numbers.e),
            }
        ]
    }


def extract_identity_context(request: Request) -> dict:
    """Extract PBAC identity attributes from the request JWT."""
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
        context.update({
            "is_authenticated": True,
            "role": payload.get("role", "customer"),
            "customer_id": payload.get("customer_id"),
            "tenant_id": payload.get("tenant_id", "default"),
            "clearance_level": payload.get("clearance_level", 1),
            "department": payload.get("department", "external"),
        })
        logger.debug(
            "Verified JWT: role=%s tenant=%s kid=%s",
            context["role"],
            context["tenant_id"],
            jwt.get_unverified_header(token).get("kid", ""),
        )
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
    except jwt.InvalidTokenError as exc:
        logger.warning("Invalid JWT token: %s", exc)

    return context
