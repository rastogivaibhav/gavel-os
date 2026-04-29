"""Tenant context middleware for multi-tenant isolation."""

import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from auth.jwt_handler import extract_identity_context
from models.tenant import TenantContext


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Inject TenantContext into each request from JWT claims."""

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Extract tenant context from JWT and inject into request state."""
        # Extract identity from JWT
        identity = extract_identity_context(request)

        # Generate request_id for tracing if not present
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # Create tenant context
        tenant_context = TenantContext(
            tenant_id=identity.get("tenant_id", "default"),
            user_id=identity.get("customer_id"),
            role=identity.get("role", "guest"),
            clearance_level=identity.get("clearance_level", 0),
            is_authenticated=identity.get("is_authenticated", False),
            request_id=request_id,
        )

        # Store in request state for downstream handlers
        request.state.tenant_context = tenant_context
        request.state.request_id = request_id

        # Call next handler
        response = await call_next(request)

        # Add request_id to response headers for tracing
        response.headers["X-Request-ID"] = request_id

        return response
