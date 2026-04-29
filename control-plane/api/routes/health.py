"""Health check endpoint."""

from fastapi import APIRouter, Depends, HTTPException
from typing import Optional

from service.health_check import HealthCheckService

logger_name = "sentinel.health"
router = APIRouter(prefix="/health", tags=["health"])

# This would be injected from the app
_health_service: Optional[HealthCheckService] = None


def set_health_service(service: HealthCheckService):
    """Set the health check service (called during app initialization)."""
    global _health_service
    _health_service = service


async def get_health_service() -> HealthCheckService:
    """Dependency to get health check service."""
    if not _health_service:
        raise HTTPException(
            status_code=503,
            detail="Health check service not initialized"
        )
    return _health_service


@router.get("")
async def health_check(
    service: HealthCheckService = Depends(get_health_service),
) -> dict:
    """Get system health status."""
    health_status = await service.get_system_health()
    
    # Return 503 if system is degraded
    status_code = 200 if health_status["status"] == "healthy" else 503
    
    if status_code == 503:
        raise HTTPException(
            status_code=status_code,
            detail=health_status
        )
    
    return health_status


@router.get("/opa")
async def opa_health(
    service: HealthCheckService = Depends(get_health_service),
) -> dict:
    """Check OPA service health."""
    ok, message = await service.check_opa_health()
    
    return {
        "service": "opa",
        "status": "healthy" if ok else "unhealthy",
        "message": message,
    }


@router.get("/db")
async def db_health(
    service: HealthCheckService = Depends(get_health_service),
) -> dict:
    """Check database health."""
    ok, message = await service.check_db_health()
    
    return {
        "service": "database",
        "status": "healthy" if ok else "unhealthy",
        "message": message,
    }
