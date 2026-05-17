"""Health check service for system dependencies."""

import logging
from datetime import UTC, datetime
from typing import Any

from sentinel.opa_engine import OPAValidationEngine

logger = logging.getLogger("sentinel.health")


class HealthCheckService:
    """Provides system health status."""

    def __init__(self, opa_engine: OPAValidationEngine, db_pool=None):
        """Initialize with system dependencies."""
        self.opa_engine = opa_engine
        self.db_pool = db_pool

    async def check_opa_health(self) -> tuple[bool, str]:
        """Check OPA service availability."""
        # Check both OPA availability and circuit breaker status
        if not self.opa_engine.is_available():
            return (False, "OPA unavailable - health check failed")

        cb_status = self.opa_engine.get_circuit_breaker_status()
        if cb_status["state"] == "open":
            return (False, f"OPA circuit breaker open (failures: {cb_status['failure_count']})")

        return (True, "OPA healthy")

    async def check_db_health(self) -> tuple[bool, str]:
        """Check PostgreSQL database availability."""
        if not self.db_pool:
            return (False, "Database pool not configured")

        try:
            async with self.db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            return (True, "Database healthy")
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return (False, f"Database error: {e}")

    async def get_system_health(self) -> dict[str, Any]:
        """Get overall system health status."""
        opa_ok, opa_msg = await self.check_opa_health()
        db_ok, db_msg = await self.check_db_health()

        overall_healthy = opa_ok and db_ok
        cb_status = self.opa_engine.get_circuit_breaker_status()

        return {
            "status": "healthy" if overall_healthy else "degraded",
            "timestamp": datetime.now(UTC).isoformat(),
            "components": {
                "opa": {
                    "status": "healthy" if opa_ok else "unhealthy",
                    "message": opa_msg,
                    "circuit_breaker": cb_status,
                },
                "database": {
                    "status": "healthy" if db_ok else "unhealthy",
                    "message": db_msg,
                },
            },
        }
