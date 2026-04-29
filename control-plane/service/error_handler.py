"""Error handling and graceful degradation service."""

import logging
from typing import Optional, Tuple
from enum import Enum

logger = logging.getLogger("sentinel.errors")


class ErrorSeverity(str, Enum):
    """Error severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GavelError(Exception):
    """Base exception for Gavel OS errors."""

    def __init__(
        self,
        message: str,
        code: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        recoverable: bool = True,
    ):
        """Initialize Gavel error."""
        self.message = message
        self.code = code
        self.severity = severity
        self.recoverable = recoverable
        super().__init__(message)

    def to_response(self) -> dict:
        """Convert to API response format."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "severity": self.severity.value,
                "recoverable": self.recoverable,
            }
        }


class DatabaseError(GavelError):
    """Database operation error."""

    def __init__(self, message: str, recoverable: bool = True):
        """Initialize database error."""
        super().__init__(
            message=message,
            code="DATABASE_ERROR",
            severity=ErrorSeverity.HIGH,
            recoverable=recoverable,
        )


class DatabaseConnectionPoolExhausted(DatabaseError):
    """Database connection pool exhausted."""

    def __init__(self):
        """Initialize pool exhausted error."""
        super().__init__(
            message="Database connection pool exhausted. Please retry.",
            recoverable=True,
        )


class OPAError(GavelError):
    """OPA policy engine error."""

    def __init__(self, message: str, recoverable: bool = True):
        """Initialize OPA error."""
        super().__init__(
            message=message,
            code="OPA_ERROR",
            severity=ErrorSeverity.HIGH,
            recoverable=recoverable,
        )


class OPACircuitBreakerOpen(OPAError):
    """OPA circuit breaker is open."""

    def __init__(self):
        """Initialize circuit breaker open error."""
        super().__init__(
            message="OPA service temporarily unavailable due to repeated failures. Retrying with fail-closed policy.",
            recoverable=True,
        )


class OPATimeout(OPAError):
    """OPA request timeout."""

    def __init__(self, timeout_seconds: float):
        """Initialize timeout error."""
        super().__init__(
            message=f"OPA policy engine request timed out after {timeout_seconds} seconds.",
            recoverable=True,
        )


class ValidationError(GavelError):
    """Input validation error."""

    def __init__(self, message: str, field: Optional[str] = None):
        """Initialize validation error."""
        code = f"VALIDATION_ERROR_{field.upper()}" if field else "VALIDATION_ERROR"
        super().__init__(
            message=message,
            code=code,
            severity=ErrorSeverity.LOW,
            recoverable=False,
        )


class RequestTimeoutError(GavelError):
    """Request timeout error."""

    def __init__(self, timeout_seconds: float):
        """Initialize request timeout error."""
        super().__init__(
            message=f"Request timed out after {timeout_seconds} seconds.",
            code="REQUEST_TIMEOUT",
            severity=ErrorSeverity.MEDIUM,
            recoverable=True,
        )


class EscalationServiceError(GavelError):
    """Escalation service error."""

    def __init__(self, message: str, recoverable: bool = True):
        """Initialize escalation service error."""
        super().__init__(
            message=message,
            code="ESCALATION_ERROR",
            severity=ErrorSeverity.HIGH,
            recoverable=recoverable,
        )


class NotificationError(GavelError):
    """Notification service error."""

    def __init__(self, message: str, backend: Optional[str] = None):
        """Initialize notification error."""
        code = f"NOTIFICATION_ERROR_{backend.upper()}" if backend else "NOTIFICATION_ERROR"
        super().__init__(
            message=message,
            code=code,
            severity=ErrorSeverity.MEDIUM,
            recoverable=True,
        )


class ErrorContext:
    """Context for error handling and recovery."""

    def __init__(self):
        """Initialize error context."""
        self.last_error: Optional[GavelError] = None
        self.error_count = 0
        self.recovery_attempts = 0

    def record_error(self, error: GavelError) -> None:
        """Record an error."""
        self.last_error = error
        self.error_count += 1
        logger.error(
            f"Error recorded: {error.code}",
            extra={
                "code": error.code,
                "severity": error.severity.value,
                "recoverable": error.recoverable,
                "count": self.error_count,
            },
        )

    def attempt_recovery(self) -> bool:
        """Attempt recovery from error."""
        if not self.last_error or not self.last_error.recoverable:
            return False

        self.recovery_attempts += 1
        logger.info(
            f"Attempting recovery: {self.last_error.code}",
            extra={"attempt": self.recovery_attempts},
        )
        return True

    def reset(self) -> None:
        """Reset error context."""
        self.last_error = None
        self.error_count = 0
        self.recovery_attempts = 0


class ErrorHandler:
    """Centralized error handling for Gavel OS."""

    def __init__(self):
        """Initialize error handler."""
        self.context = ErrorContext()

    def handle_database_error(
        self, error: Exception, operation: str = "unknown"
    ) -> Tuple[bool, dict]:
        """Handle database error.

        Args:
            error: The database error
            operation: The operation that failed

        Returns:
            (recoverable, response_dict)
        """
        logger.error(f"Database error during {operation}: {error}")

        # Check for specific error patterns
        if "connection pool" in str(error).lower():
            gavel_error = DatabaseConnectionPoolExhausted()
        elif "timeout" in str(error).lower():
            gavel_error = DatabaseError(
                f"Database operation '{operation}' timed out",
                recoverable=True,
            )
        else:
            gavel_error = DatabaseError(
                f"Database error during {operation}: {str(error)}",
                recoverable=True,
            )

        self.context.record_error(gavel_error)
        return gavel_error.recoverable, gavel_error.to_response()

    def handle_opa_error(
        self, error: Exception, circuit_breaker_open: bool = False
    ) -> Tuple[bool, dict]:
        """Handle OPA error.

        Args:
            error: The OPA error
            circuit_breaker_open: Whether circuit breaker is open

        Returns:
            (recoverable, response_dict)
        """
        logger.error(f"OPA error: {error}")

        if circuit_breaker_open:
            gavel_error = OPACircuitBreakerOpen()
        elif "timeout" in str(error).lower():
            gavel_error = OPATimeout(2.0)  # Default OPA timeout
        else:
            gavel_error = OPAError(str(error), recoverable=True)

        self.context.record_error(gavel_error)
        return gavel_error.recoverable, gavel_error.to_response()

    def handle_validation_error(self, message: str, field: Optional[str] = None) -> dict:
        """Handle validation error.

        Args:
            message: Error message
            field: Field that failed validation

        Returns:
            Response dict
        """
        logger.warning(f"Validation error: {message}")
        gavel_error = ValidationError(message, field)
        self.context.record_error(gavel_error)
        return gavel_error.to_response()

    def handle_timeout_error(self, timeout_seconds: float) -> dict:
        """Handle request timeout.

        Args:
            timeout_seconds: Timeout duration

        Returns:
            Response dict
        """
        logger.warning(f"Request timeout after {timeout_seconds}s")
        gavel_error = RequestTimeoutError(timeout_seconds)
        self.context.record_error(gavel_error)
        return gavel_error.to_response()

    def should_fail_closed(self) -> bool:
        """Determine if system should fail closed.

        Returns True if error rate is too high or system is degraded.
        """
        # Fail closed if more than 5 critical errors in recent window
        if self.context.error_count > 5:
            return True

        # Fail closed if last error was not recoverable
        if self.context.last_error and not self.context.last_error.recoverable:
            return True

        return False

    def get_health_status(self) -> dict:
        """Get error handler health status.

        Returns:
            Health status dict
        """
        return {
            "error_count": self.context.error_count,
            "recovery_attempts": self.context.recovery_attempts,
            "last_error": {
                "code": self.context.last_error.code,
                "message": self.context.last_error.message,
                "severity": self.context.last_error.severity.value,
            }
            if self.context.last_error
            else None,
            "fail_closed": self.should_fail_closed(),
        }
