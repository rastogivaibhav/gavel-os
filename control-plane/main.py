"""Gavel OS Control Plane - Main FastAPI Application."""

import logging
import os
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor

from api.middleware.tenant import TenantContextMiddleware
from api.middleware.logging import LoggingMiddleware
from api.routes import escalations, health, external, auth
from sentinel.opa_engine import OPAValidationEngine
from service.escalation_service import EscalationService
from service.health_check import HealthCheckService
from service.notification_service import NotificationService
from gavel_logging.structured_logger import get_logger

logger = get_logger("sentinel.main")

# Global state
db_pool: asyncpg.Pool | None = None
opa_engine: OPAValidationEngine | None = None
escalation_service: EscalationService | None = None
health_check_service: HealthCheckService | None = None
notification_service: NotificationService | None = None


async def init_database():
    """Initialize database connection pool."""
    global db_pool

    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql://user:password@localhost:5432/gavel"
    )

    db_pool = await asyncpg.create_pool(
        database_url,
        min_size=int(os.getenv("DB_POOL_MIN_SIZE", "5")),
        max_size=int(os.getenv("DB_POOL_MAX_SIZE", "20")),
        command_timeout=int(os.getenv("DB_COMMAND_TIMEOUT", "30")),
    )

    logger.info("Database pool initialized")


async def init_services():
    """Initialize application services."""
    global opa_engine, escalation_service, health_check_service, notification_service

    # OPA engine
    opa_engine = OPAValidationEngine(
        host=os.getenv("OPA_HOST", "localhost"),
        port=int(os.getenv("OPA_PORT", "8181")),
    )
    logger.info("OPA engine initialized")

    # Escalation service
    escalation_service = EscalationService(db_pool)
    escalations.set_escalation_service(escalation_service)
    logger.info("Escalation service initialized")

    # Health check service
    health_check_service = HealthCheckService(opa_engine, db_pool)
    health.set_health_service(health_check_service)
    logger.info("Health check service initialized")

    # Notification service
    notification_service = NotificationService()
    logger.info("Notification service initialized")


async def shutdown_database():
    """Close database connection pool."""
    global db_pool

    if db_pool:
        await db_pool.close()
        logger.info("Database pool closed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context manager."""
    # Startup
    logger.info("Gavel OS Control Plane starting up")
    await init_database()
    await init_services()
    logger.info("Gavel OS Control Plane ready")

    yield

    # Shutdown
    logger.info("Gavel OS Control Plane shutting down")
    await shutdown_database()
    logger.info("Gavel OS Control Plane stopped")


# Create FastAPI application
app = FastAPI(
    title="Gavel OS Control Plane",
    description="OS-level enforcement runtime for AI agents",
    version="1.0.0",
    lifespan=lifespan,
)

# Add middleware (order matters - innermost last)
app.add_middleware(LoggingMiddleware)
app.add_middleware(TenantContextMiddleware)

# Instrument with OpenTelemetry
FastAPIInstrumentor().instrument_app(app)
AsyncPGInstrumentor().instrument()

# Include routers
app.include_router(auth.router, prefix="/auth")
app.include_router(health.router)
app.include_router(escalations.router)
app.include_router(external.router, prefix="/external")

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": getattr(request.state, "request_id", None),
        },
    )


# Root endpoint
@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "service": "Gavel OS Control Plane",
        "status": "operational",
        "version": "1.0.0",
    }


# Readiness probe (for Kubernetes)
@app.get("/ready")
async def readiness():
    """Readiness probe for orchestration."""
    if not db_pool or not opa_engine:
        return JSONResponse(status_code=503, content={"ready": False})

    return {"ready": True}


# Liveness probe (for Kubernetes)
@app.get("/live")
async def liveness():
    """Liveness probe for orchestration."""
    return {"alive": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "info"),
        workers=int(os.getenv("WORKERS", "4")),
    )
