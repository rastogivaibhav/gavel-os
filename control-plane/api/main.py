"""
main.py — Gavel OS Control Plane Entry Point

Initialises the Gavel control plane API with middleware,
database connections, and all route registrations.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
import logging

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from typing import Optional

load_dotenv()

logger = logging.getLogger("gavel-control-plane")

# ─── Rate Limiting ────────────────────────────────────────────────────────────
# Limiter is built in api.middleware.rate_limit and imported by route modules.
# Here we attach it to the app state and register the 429 handler.
try:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from api.middleware.rate_limit import limiter as _limiter
    if _limiter is not None:
        _RATE_LIMIT_ENABLED = True
    else:
        _RATE_LIMIT_ENABLED = False
except ImportError:
    _limiter = None
    _RATE_LIMIT_ENABLED = False
    logger.warning("slowapi not installed — rate limiting disabled. Run: pip install slowapi")

from fastapi.staticfiles import StaticFiles
from pathlib import Path
from api.routes import telemetry as telemetry_router
from api.routes import ui as ui_router
from api.routes import websocket as ws_router
from api.middleware.auth import AuthMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.runtime_contract import HOST_ID_HEADER, MACHINE_KEY_ENV, MACHINE_KEY_HEADER


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler — startup and shutdown."""
    import json
    from pathlib import Path

    # Start the native gRPC server for Envoy ext_authz
    try:
        from api.grpc_server import start_grpc_background
        start_grpc_background(app)
    except Exception as e:
        logger.warning(f"Could not start gRPC background server: {e}")

    # Load API registry into app state
    registry_path = Path(__file__).resolve().parent.parent / "sentinel" / "api_registry.json"
    if registry_path.exists():
        with registry_path.open("r") as fh:
            app.state.api_registry = json.load(fh)
    else:
        app.state.api_registry = {"apis": {}}

    # Initialize PostgreSQL audit ledger
    try:
        import asyncpg
        import asyncio
        db_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL", "")
        if not db_url:
            raise RuntimeError("DATABASE_URL or POSTGRES_URL must be set")
        pool = await asyncio.wait_for(asyncpg.create_pool(dsn=db_url, min_size=2, max_size=10), timeout=3.0)
        app.state.db_pool = pool

        from srp.sdk.impl.postgres_audit_ledger import PostgresAuditLedgerClient
        app.state.audit_ledger = PostgresAuditLedgerClient(pool=pool)
        logger.info("PostgresAuditLedgerClient initialized")
    except Exception as e:
        app.state.db_pool = None
        logger.warning("Postgres unavailable: %s. Audit ledger not available.", e)
        app.state.audit_ledger = None

    # Wire up the YamlPolicyLoader with default policy
    try:
        from srp.sdk.impl.yaml_policy_loader import YamlPolicyLoader
        policy_path = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"
        loader = YamlPolicyLoader()
        if policy_path.exists():
            loader.load(str(policy_path))
            loader.watch(str(policy_path), callback=lambda p: logger.info("Policy hot-reloaded: %s", p.name))
        app.state.policy_loader = loader
        logger.info("YamlPolicyLoader initialized with %s", policy_path)
    except Exception as e:
        app.state.policy_loader = None
        logger.warning("PolicyLoader unavailable: %s", e)

    # Wire up VerdictEngine
    try:
        from srp.verdict_engine import VerdictEngine
        app.state.verdict_engine = VerdictEngine()
        logger.info("VerdictEngine initialized")
    except Exception as e:
        app.state.verdict_engine = None
        logger.warning("VerdictEngine unavailable: %s", e)

    logger.info("Gavel control plane started")
    yield

    # Shutdown
    if hasattr(app.state, "policy_loader") and app.state.policy_loader:
        try:
            app.state.policy_loader.stop_watching()
        except Exception:
            pass

    if hasattr(app.state, "db_pool") and app.state.db_pool:
        await app.state.db_pool.close()

    logger.info("Gavel control plane shutting down")


app = FastAPI(
    title="Gavel OS Control Plane",
    description=(
        "Gavel — OS-level enforcement runtime for AI agents. "
        "Deterministic policy enforcement with cryptographically chained audit ledger."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Attach rate limiter to app state
if _RATE_LIMIT_ENABLED and _limiter is not None:
    app.state.limiter = _limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── Telemetry ────────────────────────────────────────────────────────────────
try:
    from telemetry.setup import setup_telemetry
    setup_telemetry(app, service_name="gavel-control-plane")
except ImportError as e:
    logger.warning(f"Telemetry setup unavailable: {e}")

# ─── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuthMiddleware)

_allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
if os.getenv("ENV", "development") == "development":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in _allowed_origins],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Request-ID",
            MACHINE_KEY_HEADER,
            HOST_ID_HEADER,
        ],
    )
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ─── Core Routes ──────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health_check():
    """API health check endpoint."""
    try:
        from api.grpc_server import get_grpc_authz_status
        grpc_authz_status = get_grpc_authz_status()
    except Exception:
        grpc_authz_status = "unavailable"

    try:
        from api.routes import query as query_route
        opa_status = "ready" if query_route.opa_engine.is_available() else "unavailable"
    except Exception:
        opa_status = "unavailable"

    db_status = "unavailable"
    if getattr(app.state, "db_pool", None):
        try:
            async with app.state.db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            db_status = "connected"
        except Exception:
            db_status = "error"

    redis_status = "unavailable"
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url(redis_url, socket_connect_timeout=2)
            await r.ping()
            await r.aclose()
            redis_status = "connected"
        except Exception:
            redis_status = "error"

    components = {
        "audit_ledger": "connected" if getattr(app.state, "audit_ledger", None) else "unavailable",
        "policy_loader": "loaded" if getattr(app.state, "policy_loader", None) else "unavailable",
        "verdict_engine": "ready" if getattr(app.state, "verdict_engine", None) else "unavailable",
        "machine_auth": "configured" if os.getenv(MACHINE_KEY_ENV) else "missing",
        "grpc_authz": grpc_authz_status,
        "opa_policy_engine": opa_status,
        "database": db_status,
        "redis": redis_status,
    }
    status = "healthy" if all(
        components[key] in {"connected", "loaded", "ready", "configured"}
        for key in ("audit_ledger", "policy_loader", "verdict_engine", "machine_auth")
    ) and grpc_authz_status == "ready" and opa_status == "ready" else "degraded"
    body = {
        "status": status,
        "service": "gavel-control-plane",
        "version": "1.0.0",
        "components": components,
    }
    if status == "degraded":
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=body)
    return body


@app.get("/readyz", tags=["Health"])
async def readiness_check():
    """Kubernetes readiness probe."""
    ready = all([
        getattr(app.state, "audit_ledger", None) is not None,
        getattr(app.state, "policy_loader", None) is not None,
        getattr(app.state, "verdict_engine", None) is not None,
    ])
    if not ready:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"ready": False, "reason": "One or more critical components not yet initialized"},
        )
    return {"ready": True}


# ─── Feature Routes ───────────────────────────────────────────────────────────

app.include_router(telemetry_router.router, tags=["Telemetry"])

from api.routes import external as external_router
app.include_router(external_router.router, prefix="/external", tags=["External Bridge"])

try:
    from api.routes import audit as audit_router
    app.include_router(audit_router.router, prefix="/audit", tags=["Audit"])
except ImportError:
    logger.warning("Audit routes not available")

# ─── UI Routes ────────────────────────────────────────────────────────────────
app.include_router(ui_router.router)
app.include_router(ws_router.router)

# ─── Static Files ──────────────────────────────────────────────────────────────
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
else:
    logger.warning(f"Static directory not found at {static_dir}")

# ─── Auth Token Endpoint ─────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    """Request body for generating a signed JWT token."""
    role: str = "customer"
    customer_id: Optional[str] = None
    tenant_id: str = "default"
    clearance_level: int = 1
    department: str = "external"


class TokenResponse(BaseModel):
    """Response body containing the signed JWT."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
async def generate_token(
    request: Request,
    payload: TokenRequest,
    x_admin_secret: Optional[str] = __import__("fastapi").Header(None, alias="X-Admin-Secret")
):
    """Generate a signed JWT token for API authentication."""
    from auth.jwt_handler import create_token, _JWT_EXPIRY_SECONDS
    from fastapi import HTTPException

    if payload.role == "admin":
        expected_secret = os.getenv("ADMIN_SECRET_KEY")
        if not expected_secret or x_admin_secret != expected_secret:
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing X-Admin-Secret header for admin role minting."
            )

    token = create_token(
        role=payload.role,
        customer_id=payload.customer_id,
        tenant_id=payload.tenant_id,
        clearance_level=payload.clearance_level,
        department=payload.department,
    )
    return TokenResponse(
        access_token=token,
        expires_in=_JWT_EXPIRY_SECONDS,
    )


@app.get("/auth/jwks", tags=["Auth"])
@app.get("/.well-known/jwks.json", tags=["Auth"], include_in_schema=False)
async def jwks_endpoint():
    """
    Return the public key set (JWKS) for this control plane.

    Downstream services can fetch this endpoint to verify JWTs without
    calling back to the control plane on every request. Cache the response
    for JWKS_CACHE_TTL_SECONDS (default 300s).
    """
    from auth.jwt_handler import get_jwks
    from fastapi.responses import JSONResponse
    ttl = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
    return JSONResponse(
        content=get_jwks(),
        headers={"Cache-Control": f"public, max-age={ttl}"},
    )


# Prometheus Metrics Scrape Endpoint
try:
    import hmac as _hmac
    from prometheus_client import make_asgi_app as _make_metrics_app
    from fastapi.responses import JSONResponse as _JSONResponse

    _raw_metrics = _make_metrics_app()
    _metrics_token = os.getenv("METRICS_SECRET_KEY", "")

    async def _metrics_with_auth(scope, receive, send):
        if scope.get("type") == "http":
            headers = {
                k.decode("utf-8").lower(): v.decode("utf-8")
                for k, v in scope.get("headers", [])
            }
            token = (
                headers.get("x-api-key", "")
                or headers.get("authorization", "").removeprefix("Bearer ")
            )
            if _metrics_token and not _hmac.compare_digest(token, _metrics_token):
                resp = _JSONResponse(
                    status_code=401,
                    content={"detail": "Metrics scrape requires X-API-Key"},
                )
                await resp(scope, receive, send)
                return
        await _raw_metrics(scope, receive, send)

    app.mount("/metrics", _metrics_with_auth)
except ImportError:
    pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
