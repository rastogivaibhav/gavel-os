"""Structured logging with correlation ID injection."""

import logging
import json
from typing import Any, Dict, Optional
from contextvars import ContextVar

# Context variable for storing request_id across async contexts
_request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
_tenant_id_var: ContextVar[Optional[str]] = ContextVar('tenant_id', default=None)


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging with contextual fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with context fields."""
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }

        # Add context variables if present
        request_id = _request_id_var.get()
        if request_id:
            log_data['request_id'] = request_id

        tenant_id = _tenant_id_var.get()
        if tenant_id:
            log_data['tenant_id'] = tenant_id

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Add extra fields if provided
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        return json.dumps(log_data)


def set_request_context(request_id: str, tenant_id: Optional[str] = None):
    """Set context variables for correlation and tenancy tracking."""
    _request_id_var.set(request_id)
    if tenant_id:
        _tenant_id_var.set(tenant_id)


def clear_request_context():
    """Clear context variables."""
    _request_id_var.set(None)
    _tenant_id_var.set(None)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with structured formatting."""
    logger = logging.getLogger(name)

    # Only configure if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = StructuredFormatter()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger


class ContextualLogRecord(logging.LogRecord):
    """LogRecord that includes contextual fields."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_id = _request_id_var.get()
        self.tenant_id = _tenant_id_var.get()
