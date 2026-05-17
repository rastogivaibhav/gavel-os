"""Multi-tenant context models."""

from pydantic import BaseModel, Field


class TenantContext(BaseModel):
    """Tenant and user context extracted from request."""

    tenant_id: str = Field(..., description="Tenant identifier")
    user_id: str | None = Field(None, description="User identifier within tenant")
    role: str = Field(default="guest", description="User role within tenant")
    clearance_level: int = Field(default=0, description="Security clearance level")
    is_authenticated: bool = Field(default=False, description="Whether request is authenticated")
    request_id: str | None = Field(None, description="Request correlation ID")

    def __hash__(self):
        return hash((self.tenant_id, self.user_id))
