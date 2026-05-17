"""
OPA client wrapper that talks directly to the OPA HTTP API.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from sentinel.circuit_breaker import CircuitBreaker

logger = logging.getLogger("sentinel.opa")


class OPAValidationEngine:
    def __init__(self, host: str = "localhost", port: int = 8181):
        """Initializes the OPA endpoint configuration."""
        self.host = host
        self.port = port
        env_base_url = os.getenv("OPA_URL", "").strip()
        explicit_endpoint = host != "localhost" or port != 8181
        self.base_url = (
            f"http://{host}:{port}" if explicit_endpoint or not env_base_url else env_base_url
        ).rstrip("/")
        self.package_path = os.getenv("OPA_PACKAGE_PATH", "sentinel/api/authz").strip("/")
        self.timeout_seconds = float(os.getenv("OPA_TIMEOUT_SECONDS", "2.0"))

        # Circuit breaker for OPA service
        self.circuit_breaker = CircuitBreaker(
            name="opa_service",
            failure_threshold=int(os.getenv("OPA_CB_FAILURE_THRESHOLD", "5")),
            recovery_timeout_seconds=int(os.getenv("OPA_CB_RECOVERY_TIMEOUT", "60")),
            expected_exception=Exception,
        )

    def _request_json(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Make HTTP request to OPA with circuit breaker protection."""

        def _make_request():
            target_url = urljoin(f"{self.base_url}/", path.lstrip("/"))
            body = None
            headers = {"Accept": "application/json"}
            if payload is not None:
                body = json.dumps(payload).encode("utf-8")
                headers["Content-Type"] = "application/json"

            request = Request(
                target_url,
                data=body,
                headers=headers,
                method="POST" if payload is not None else "GET",
            )
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}

        try:
            return self.circuit_breaker.call(_make_request)
        except Exception as e:
            logger.error(f"Circuit breaker open or request failed: {e}")
            raise

    def is_available(self) -> bool:
        try:
            self._request_json("/health")
            return True
        except (URLError, HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            logger.warning("OPA health check failed: %s", exc)
            return False

    def check_routing_allowance(
        self,
        identity_context: dict[str, Any],
        target_endpoint: dict[str, Any],
        tenant_id: str | None = None,
    ) -> tuple[bool, str]:
        """
        Evaluate if the current identity is authorized to invoke the target endpoint.

        Args:
            identity_context: Identity attributes (user, roles, etc.)
            target_endpoint: Target resource (path, method)
            tenant_id: Optional tenant ID for multi-tenant policy evaluation
        """
        input_data = {
            "identity": identity_context,
            "resource": target_endpoint,
        }

        # Include tenant_id in policy input if provided
        if tenant_id:
            input_data["tenant_id"] = tenant_id

        if not self.is_available():
            return False, "Internal Security Error: Policy Engine Unavailable"

        try:
            response = self._request_json(
                f"/v1/data/{self.package_path}/allow",
                payload={"input": input_data},
            )
        except Exception as exc:
            logger.error("OPA evaluation failed: %s", exc)
            return False, "Internal Security Error: Policy Engine Unavailable"

        is_allowed = bool(response.get("result", False))
        if is_allowed:
            return True, "Authorized by OPA"
        return False, "Access Denied by PBAC Rego Rules"

    def evaluate_runtime_policy(
        self,
        action: str,
        method: str,
        host_id: str,
        runtime_os: str,
        agent_id: str,
        tenant_id: str | None = None,
    ) -> tuple[bool, str]:
        """
        Evaluate network-level runtime policy (sentinel.runtime.policy).

        Used for enforcer-level network action decisions.
        Input shape:
            action: target hostname or IP
            method: CONNECT | GET | POST | EXECUTE
            host_id: enforcer host identifier
            runtime_os: linux | windows | macos
            agent_id: agent process name
            tenant_id: optional tenant ID for multi-tenant policies
        """
        input_data = {
            "action": action,
            "method": method,
            "host_id": host_id,
            "runtime_os": runtime_os,
            "agent_id": agent_id,
        }

        # Include tenant_id in policy input if provided
        if tenant_id:
            input_data["tenant_id"] = tenant_id

        if not self.is_available():
            return False, "Policy Engine Unavailable (fail-closed)"

        try:
            response = self._request_json(
                "/v1/data/sentinel/runtime/policy/allow",
                payload={"input": input_data},
            )
        except Exception as exc:
            logger.error("Runtime policy evaluation failed: %s", exc)
            return False, "Policy Engine Error (fail-closed)"

        is_allowed = bool(response.get("result", False))
        verdict = response.get("verdict", "DENY")

        if is_allowed:
            return True, f"Authorized by Runtime Policy ({verdict})"
        return False, f"Denied by Runtime Policy ({verdict})"

    def get_circuit_breaker_status(self) -> dict:
        """Get circuit breaker status for monitoring."""
        return self.circuit_breaker.get_status()
