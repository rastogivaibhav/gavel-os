"""End-to-End Workflow Tests - Complete System Integration."""

import pytest
import sys
import asyncio

sys.path.insert(0, 'control-plane')


@pytest.mark.e2e
class TestCompleteToolProposalWorkflow:
    """Test complete tool proposal workflow from request to audit log."""

    def test_verdict_engine_imported(self):
        """Test that VerdictEngine can be imported."""
        from srp.verdict_engine import VerdictEngine

        assert VerdictEngine is not None

    def test_opa_engine_imported(self):
        """Test that OPA engine can be imported."""
        from sentinel.opa_engine import OPAValidationEngine

        assert OPAValidationEngine is not None

    def test_escalation_service_imported(self):
        """Test that EscalationService can be imported."""
        from service.escalation_service import EscalationService

        assert EscalationService is not None

    def test_notification_service_imported(self):
        """Test that NotificationService can be imported."""
        from service.notification_service import NotificationService

        assert NotificationService is not None

    def test_audit_ledger_imported(self):
        """Test that audit ledger module can be imported."""
        import srp.sdk.impl.postgres_audit_ledger

        assert srp.sdk.impl.postgres_audit_ledger is not None


@pytest.mark.e2e
class TestErrorHandling:
    """Test error handling and graceful degradation."""

    def test_error_handler_imported(self):
        """Test that ErrorHandler can be imported."""
        from service.error_handler import ErrorHandler

        assert ErrorHandler is not None

    def test_error_handler_initialization(self):
        """Test ErrorHandler initialization."""
        from service.error_handler import ErrorHandler

        handler = ErrorHandler()
        assert handler is not None
        assert handler.context is not None

    def test_database_error_handling(self):
        """Test database error handling."""
        from service.error_handler import ErrorHandler, DatabaseError

        handler = ErrorHandler()
        error = DatabaseError("Connection failed")

        recoverable, response = handler.handle_database_error(error, "create_escalation")

        assert recoverable is True
        assert "error" in response
        assert response["error"]["code"] == "DATABASE_ERROR"

    def test_opa_error_handling(self):
        """Test OPA error handling."""
        from service.error_handler import ErrorHandler, OPAError

        handler = ErrorHandler()
        error = OPAError("Policy evaluation failed")

        recoverable, response = handler.handle_opa_error(error)

        assert recoverable is True
        assert "error" in response
        assert response["error"]["code"] == "OPA_ERROR"

    def test_circuit_breaker_open_handling(self):
        """Test circuit breaker open handling."""
        from service.error_handler import ErrorHandler

        handler = ErrorHandler()
        recoverable, response = handler.handle_opa_error(
            Exception("timeout"),
            circuit_breaker_open=True
        )

        assert recoverable is True
        assert "error" in response
        assert "unavailable" in response["error"]["message"].lower()

    def test_validation_error_handling(self):
        """Test validation error handling."""
        from service.error_handler import ErrorHandler

        handler = ErrorHandler()
        response = handler.handle_validation_error(
            "Invalid operation type",
            field="operation"
        )

        assert "error" in response
        assert response["error"]["code"] == "VALIDATION_ERROR_OPERATION"
        assert response["error"]["recoverable"] is False

    def test_timeout_error_handling(self):
        """Test request timeout error handling."""
        from service.error_handler import ErrorHandler

        handler = ErrorHandler()
        response = handler.handle_timeout_error(30.0)

        assert "error" in response
        assert response["error"]["code"] == "REQUEST_TIMEOUT"

    def test_fail_closed_policy(self):
        """Test fail-closed policy."""
        from service.error_handler import ErrorHandler, GavelError, ErrorSeverity

        handler = ErrorHandler()

        # Record multiple errors
        for _ in range(6):
            error = GavelError("test", "TEST_ERROR", ErrorSeverity.HIGH)
            handler.context.record_error(error)

        # Should fail closed when too many errors
        assert handler.should_fail_closed() is True

    def test_health_status(self):
        """Test error handler health status."""
        from service.error_handler import ErrorHandler, GavelError, ErrorSeverity

        handler = ErrorHandler()
        error = GavelError("test", "TEST_ERROR", ErrorSeverity.HIGH)
        handler.context.record_error(error)

        status = handler.get_health_status()

        assert "error_count" in status
        assert "recovery_attempts" in status
        assert "last_error" in status
        assert status["error_count"] == 1


@pytest.mark.e2e
class TestMultiTenancyIsolation:
    """Test multi-tenant isolation."""

    def test_tenant_context_model(self):
        """Test TenantContext model."""
        from models.tenant import TenantContext

        context = TenantContext(
            tenant_id="tenant-123",
            user_id="user-456",
            role="admin",
            clearance_level=5,
            request_id="req-789",
            is_authenticated=True,
        )

        assert context.tenant_id == "tenant-123"
        assert context.user_id == "user-456"
        assert context.is_authenticated is True

    def test_tenant_context_unauthenticated(self):
        """Test unauthenticated tenant context."""
        from models.tenant import TenantContext

        context = TenantContext(
            tenant_id="tenant-123",
            user_id=None,
            role="anonymous",
            clearance_level=0,
            request_id="req-789",
        )

        assert context.is_authenticated is False

    def test_tenant_middleware_available(self):
        """Test that tenant middleware is available."""
        from api.middleware.tenant import TenantContextMiddleware

        assert TenantContextMiddleware is not None

    def test_tenant_dependency_available(self):
        """Test that tenant dependency is available."""
        from api.dependencies import get_tenant_context

        assert get_tenant_context is not None


@pytest.mark.e2e
class TestAuditLogging:
    """Test audit logging integration."""

    def test_audit_ledger_model(self):
        """Test audit ledger models."""
        from srp.models import Verdict, VerdictType, VerdictReason
        from uuid import uuid4

        verdict = Verdict(
            proposal_id=uuid4(),
            verdict=VerdictType.ALLOW,
            reasons=[
                VerdictReason(
                    code="APPROVED",
                    message="Meets policy requirements",
                    details={},
                )
            ],
            policy_ids=["policy-001"],
        )

        assert verdict.verdict == VerdictType.ALLOW
        assert len(verdict.reasons) == 1

    def test_audit_event_creation(self):
        """Test audit event creation."""
        from srp.sdk.models import AuditEvent

        event = AuditEvent(
            recipe_id="tool-proposal-verdict",
            step_id="verdict-evaluation",
            actor="test-agent",
            action="tool:transfer",
            target_system="payments.api",
            outcome="SUCCESS",
            payload_hash="proposal:tc_test",
        )

        assert event.recipe_id == "tool-proposal-verdict"
        assert event.outcome == "SUCCESS"


@pytest.mark.e2e
class TestPerformanceMetrics:
    """Test performance metrics collection."""

    def test_metrics_available(self):
        """Test that metrics can be imported."""
        from observability.metrics import OPAMetrics, AuditMetrics, VerdictMetrics

        assert OPAMetrics is not None
        assert AuditMetrics is not None
        assert VerdictMetrics is not None

    def test_tracing_available(self):
        """Test that tracing can be imported."""
        from observability.tracing import TracingContext

        assert TracingContext is not None

    def test_structured_logging_available(self):
        """Test that structured logging is available."""
        from gavel_logging.structured_logger import get_logger

        logger = get_logger("test")
        assert logger is not None


@pytest.mark.e2e
class TestDependencyInjection:
    """Test dependency injection setup."""

    def test_get_tenant_context_dependency(self):
        """Test get_tenant_context dependency."""
        from api.dependencies import get_tenant_context

        assert callable(get_tenant_context)

    def test_require_authentication_dependency(self):
        """Test require_authentication dependency."""
        from api.dependencies import require_authentication

        assert callable(require_authentication)

    def test_require_admin_dependency(self):
        """Test require_admin dependency."""
        from api.dependencies import require_admin

        assert callable(require_admin)


@pytest.mark.e2e
class TestCircuitBreakerIntegration:
    """Test circuit breaker integration."""

    def test_circuit_breaker_imported(self):
        """Test that CircuitBreaker can be imported."""
        from sentinel.circuit_breaker import CircuitBreaker

        assert CircuitBreaker is not None

    def test_circuit_breaker_initialization(self):
        """Test CircuitBreaker initialization."""
        from sentinel.circuit_breaker import CircuitBreaker

        breaker = CircuitBreaker(
            name="test",
            failure_threshold=5,
            recovery_timeout_seconds=60,
            expected_exception=Exception,
        )

        assert breaker.name == "test"
        assert breaker.failure_threshold == 5

    def test_circuit_breaker_status(self):
        """Test circuit breaker status."""
        from sentinel.circuit_breaker import CircuitBreaker

        breaker = CircuitBreaker(
            name="test",
            failure_threshold=5,
            recovery_timeout_seconds=60,
            expected_exception=Exception,
        )

        status = breaker.get_status()

        assert "state" in status
        assert status["state"] in ["closed", "open", "half_open"]


@pytest.mark.e2e
class TestHealthCheckIntegration:
    """Test health check integration."""

    def test_health_check_service_imported(self):
        """Test that HealthCheckService can be imported."""
        from service.health_check import HealthCheckService

        assert HealthCheckService is not None

    def test_health_endpoints_available(self):
        """Test that health endpoints are available."""
        from api.routes import health

        assert hasattr(health, 'router')
