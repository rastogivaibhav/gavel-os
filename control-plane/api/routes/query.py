"""
query.py — OPA engine singleton for the control plane.

Imported by control_plane.py and external.py as:
    from api.routes import query as query_route
    query_route.opa_engine.check_routing_allowance(...)

The OPA engine is a module-level singleton so it is constructed once at
import time and shared across all requests. Configuration is read from
environment variables (OPA_URL, OPA_PACKAGE_PATH, OPA_TIMEOUT_SECONDS).
"""

from __future__ import annotations

from sentinel.opa_engine import OPAValidationEngine

# Module-level singleton — shared across all requests.
opa_engine: OPAValidationEngine = OPAValidationEngine()
