"""Logging middleware with structured output and correlation tracking."""

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from gavel_logging.structured_logger import get_logger, set_request_context, clear_request_context

logger = get_logger("sentinel.api")


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests with structured output and correlation tracking."""

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Log request and response with correlation ID."""
        # Get request_id and tenant_id from request state
        request_id = getattr(request.state, 'request_id', None)
        tenant_context = getattr(request.state, 'tenant_context', None)
        tenant_id = tenant_context.tenant_id if tenant_context else None

        # Set context for all logs in this request
        set_request_context(request_id, tenant_id)

        # Record request start
        start_time = time.monotonic()
        method = request.method
        path = request.url.path
        query = request.url.query

        logger.info(
            f"Request started: {method} {path}",
            extra={'extra_fields': {
                'method': method,
                'path': path,
                'query': query,
                'client': request.client[0] if request.client else None,
            }}
        )

        # Call next handler
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            elapsed = time.monotonic() - start_time
            logger.error(
                f"Request failed with exception: {exc}",
                exc_info=True,
                extra={'extra_fields': {
                    'method': method,
                    'path': path,
                    'elapsed_ms': int(elapsed * 1000),
                }}
            )
            raise
        finally:
            # Clear context
            clear_request_context()

        # Record request completion
        elapsed = time.monotonic() - start_time
        logger.info(
            f"Request completed: {method} {path} -> {status_code}",
            extra={'extra_fields': {
                'method': method,
                'path': path,
                'status_code': status_code,
                'elapsed_ms': int(elapsed * 1000),
            }}
        )

        return response
