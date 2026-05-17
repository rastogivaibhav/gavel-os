"""Authentication routes."""

import logging

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

logger = logging.getLogger("sentinel.auth")

router = APIRouter()


class TokenRequest(BaseModel):
    """JWT token request."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str


@router.post("/token", response_model=TokenResponse)
async def get_token(request: TokenRequest):
    """Legacy credential endpoint.

    Password-based token minting is intentionally disabled. Use the canonical
    ``POST /auth/token`` endpoint in ``api.main`` with the admin minting secret
    for custom claims, or with an empty body for the fixed development token.
    """
    logger.info(f"Token request for user: {request.username}")
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Password-based token minting is disabled; use POST /auth/token.",
    )


@router.get("/verify")
async def verify_token(authorization: str = Header("", alias="Authorization")):
    """Verify a bearer token with the canonical JWT verifier."""
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    logger.info("Token verification requested")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    try:
        from auth.jwt_handler import verify_token as _verify_token

        claims = _verify_token(authorization[7:])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from exc

    return {"valid": True, "claims": claims}
