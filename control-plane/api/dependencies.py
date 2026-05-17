"""FastAPI dependency injection utilities."""

from fastapi import HTTPException, Request

from models.tenant import TenantContext


async def get_tenant_context(request: Request) -> TenantContext:
    """Dependency to inject TenantContext into endpoints."""
    tenant_context = getattr(request.state, "tenant_context", None)
    if not tenant_context:
        # Fallback: unauthenticated request with default tenant
        tenant_context = TenantContext(
            tenant_id="default",
            is_authenticated=False,
        )
    return tenant_context


async def require_authentication(
    tenant_context: TenantContext = None,
) -> TenantContext:
    """Dependency to require authenticated requests."""
    if not tenant_context or not tenant_context.is_authenticated:
        raise HTTPException(status_code=401, detail="Authentication required")
    return tenant_context


async def require_admin(
    tenant_context: TenantContext = None,
) -> TenantContext:
    """Dependency to require admin role."""
    if not tenant_context or tenant_context.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return tenant_context
