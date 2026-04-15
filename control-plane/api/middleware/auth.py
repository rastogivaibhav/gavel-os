"""
API authentication middleware for bearer tokens, API keys, and machine keys.
"""

from __future__ import annotations

import hmac
import logging
import os

from fastapi.responses import JSONResponse

from api.runtime_contract import MACHINE_KEY_ENV, MACHINE_KEY_HEADER

logger = logging.getLogger("sentinel.auth")

_PUBLIC_PATHS = {"/", "/health", "/readyz", "/docs", "/redoc", "/openapi.json", "/auth/token"}


class AuthMiddleware:
    """ASGI middleware for JWT, API-key, and machine-key authentication."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        env = os.getenv("ENV", "production")
        insecure_dev_auth = os.getenv("ALLOW_INSECURE_DEV_AUTH", "false").lower() == "true"
        if (
            (env == "development" and insecure_dev_auth)
            or path in _PUBLIC_PATHS
            or path == "/ui"
            or path.startswith("/ui/")
        ):
            # In dev-bypass mode, stamp gavel_auth_mode so require_machine_auth
            # and any other scope-state consumers don't 401 on internal endpoints.
            if env == "development" and insecure_dev_auth:
                scope.setdefault("state", {})["gavel_auth_mode"] = "machine"
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("utf-8").lower(): value.decode("utf-8")
            for key, value in scope.get("headers", [])
        }
        auth_header = headers.get("authorization", "")
        api_key_header = headers.get("x-api-key", "")
        machine_key_header = headers.get(MACHINE_KEY_HEADER, "")

        configured_api_key = os.getenv("API_SECRET_KEY", "")
        configured_machine_key = os.getenv(MACHINE_KEY_ENV, "")

        scope_state = scope.setdefault("state", {})
        failure_detail = "Missing or invalid authentication credentials"

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from auth.jwt_handler import verify_token

                scope_state["gavel_auth_mode"] = "bearer"
                scope_state["gavel_auth_claims"] = verify_token(token)
                await self.app(scope, receive, send)
                return
            except Exception as exc:
                logger.warning("Bearer authentication failed: %s", exc)
                failure_detail = "Invalid or expired bearer token"

        if configured_api_key and hmac.compare_digest(api_key_header, configured_api_key):
            scope_state["gavel_auth_mode"] = "api_key"
            await self.app(scope, receive, send)
            return

        if configured_machine_key and hmac.compare_digest(machine_key_header, configured_machine_key):
            scope_state["gavel_auth_mode"] = "machine"
            await self.app(scope, receive, send)
            return

        if scope["type"] == "http":
            response = JSONResponse(status_code=401, content={"detail": failure_detail})
            await response(scope, receive, send)
            return

        await send({"type": "websocket.close", "code": 4001})
