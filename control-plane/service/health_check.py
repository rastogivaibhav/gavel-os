"""Health check service for system dependencies."""

import logging
from typing import Dict, Any, Tuple

from sentinel.opa_engine import OPAValidationEngine

logger = logging.getLogger("sentinel.health")


class HealthCheckService:
    """Provides system health status."""

    def __init__(self, opa_engine: OPAValidationEngine, db_pool=None):
        """Initialize with system dependencies."""
        self.opa_engine = opa_engine
        self.db_pool = db_pool

    async def check_opa_health(self) -> Tuple[bool, str]:
        """Check OPA service availability."""
        if self.opa_engine.is_available():
            return (True, "OPA healthy")
        return (False, "OPA unavailable")

    async def check_db_health(self) -> Tuple[bool, str]:
        """Check PostgreSQL database availability."""
        if not self.db_pool:
            return (False, "Database pool not configured")

        try:
            async with self.db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            return (True, "Database healthy")
        except Exception as e:
            return (False, f"Database error: {e}")

    async def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status."""
        opa_ok, opa_msg = await self.check_opa_health()
        db_ok, db_msg = await self.check_db_health()

        overall_healthy = opa_ok and db_ok

        return {
            "status": "healthy" if overall_healthy else "degraded",
            "timestamp": None,  # TODO: Add timestamp
            "components": {
                "opa": {
                    "status": "healthy" if opa_ok else "unhealthy",
                    "message": opa_msg,
                },
                "database": {
                    "status": "healthy" if db_ok else "unhealthy",
                    "message": db_msg,
                },
            },
        }
