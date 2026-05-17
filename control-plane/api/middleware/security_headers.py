"""
security_headers.py — Security Headers Middleware

Injects standard security headers on every HTTP response to protect
against common web vulnerabilities (clickjacking, MIME sniffing, etc.).
"""

from __future__ import annotations

import os


class SecurityHeadersMiddleware:
    """ASGI middleware that adds security headers to all HTTP responses."""

    def __init__(self, app):
        self.app = app
        self._env = os.getenv("ENV", "production")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                security_headers = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"x-xss-protection", b"1; mode=block"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
                ]
                if self._env == "production":
                    security_headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=63072000; includeSubDomains; preload",
                        )
                    )
                headers.extend(security_headers)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
