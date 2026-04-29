"""Integration tests for health checks and circuit breaker resilience."""

import pytest
import sys
sys.path.insert(0, 'control-plane')


@pytest.mark.integration
class TestHealthChecks:
    """Integration tests for health check service."""

    @pytest.mark.asyncio
    async def test_health_check_service_creation(self, db_pool):
        """Test creating health check service."""
        from sentinel.opa_engine import OPAValidationEngine
        from service.health_check import HealthCheckService

        opa_engine = OPAValidationEngine()
        service = HealthCheckService(opa_engine, db_pool)

        assert service is not None
        assert service.opa_engine is not None
        assert service.db_pool is not None

    @pytest.mark.asyncio
    async def test_opa_health_check(self, db_pool):
        """Test OPA health check."""
        from sentinel.opa_engine import OPAValidationEngine
        from service.health_check import HealthCheckService

        opa_engine = OPAValidationEngine()
        service = HealthCheckService(opa_engine, db_pool)

        ok, msg = await service.check_opa_health()

        assert isinstance(ok, bool)
        assert isinstance(msg, str)

    @pytest.mark.asyncio
    async def test_db_health_check(self, db_pool):
        """Test database health check."""
        from sentinel.opa_engine import OPAValidationEngine
        from service.health_check import HealthCheckService

        opa_engine = OPAValidationEngine()
        service = HealthCheckService(opa_engine, db_pool)

        ok, msg = await service.check_db_health()

        # With proper database pool, this should succeed
        assert isinstance(ok, bool)
        assert isinstance(msg, str)

    @pytest.mark.asyncio
    async def test_get_system_health(self, db_pool):
        """Test getting overall system health."""
        from sentinel.opa_engine import OPAValidationEngine
        from service.health_check import HealthCheckService

        opa_engine = OPAValidationEngine()
        service = HealthCheckService(opa_engine, db_pool)

        health = await service.get_system_health()

        assert "status" in health
        assert "timestamp" in health
        assert "components" in health
        assert "opa" in health["components"]
        assert "database" in health["components"]


@pytest.mark.integration
class TestCircuitBreaker:
    """Integration tests for circuit breaker pattern."""

    def test_circuit_breaker_initialization(self):
        """Test circuit breaker creation."""
        from sentinel.circuit_breaker import CircuitBreaker, CircuitState

        cb = CircuitBreaker(
            name="test_service",
            failure_threshold=3,
            recovery_timeout_seconds=60,
        )

        assert cb.name == "test_service"
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0

    def test_circuit_breaker_call_success(self):
        """Test successful call through circuit breaker."""
        from sentinel.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker(name="test", failure_threshold=3)

        def success_func():
            return "success"

        result = cb.call(success_func)
        assert result == "success"
        assert cb.failure_count == 0

    def test_circuit_breaker_opens_after_threshold(self):
        """Test circuit breaker opens after failure threshold."""
        from sentinel.circuit_breaker import CircuitBreaker, CircuitState

        cb = CircuitBreaker(name="test", failure_threshold=2)

        def fail_func():
            raise Exception("Test failure")

        # First failure
        with pytest.raises(Exception):
            cb.call(fail_func)
        assert cb.failure_count == 1
        assert cb.state == CircuitState.CLOSED

        # Second failure - should open circuit
        with pytest.raises(Exception):
            cb.call(fail_func)
        assert cb.failure_count == 2
        assert cb.state == CircuitState.OPEN

        # Third call should fail with circuit open, not execute function
        with pytest.raises(Exception):
            cb.call(fail_func)

    def test_circuit_breaker_get_status(self):
        """Test getting circuit breaker status."""
        from sentinel.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker(name="test")

        status = cb.get_status()

        assert status["name"] == "test"
        assert "state" in status
        assert "failure_count" in status


@pytest.mark.integration
class TestOPAEngineResilience:
    """Integration tests for OPA engine resilience with circuit breaker."""

    def test_opa_engine_has_circuit_breaker(self):
        """Test OPA engine includes circuit breaker."""
        from sentinel.opa_engine import OPAValidationEngine

        engine = OPAValidationEngine()

        assert hasattr(engine, 'circuit_breaker')
        assert engine.circuit_breaker is not None

    def test_opa_engine_get_circuit_breaker_status(self):
        """Test getting OPA circuit breaker status."""
        from sentinel.opa_engine import OPAValidationEngine

        engine = OPAValidationEngine()

        status = engine.get_circuit_breaker_status()

        assert isinstance(status, dict)
        assert "state" in status
        assert "failure_count" in status
