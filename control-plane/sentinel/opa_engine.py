"""
OPA client wrapper that talks directly to the OPA HTTP API.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

logger = logging.getLogger("sentinel.opa")


class OPAValidationEngine:
    def __init__(self, host: str = "localhost", port: int = 8181):
        """Initializes the OPA endpoint configuration."""
        self.host = host
        self.port = port
        self.base_url = os.getenv("OPA_URL", f"http://{host}:{port}").rstrip("/")
        self.package_path = os.getenv("OPA_PACKAGE_PATH", "sentinel/api/authz").strip("/")
        self.timeout_seconds = float(os.getenv("OPA_TIMEOUT_SECONDS", "2.0"))

    def _request_json(self, path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        target_url = urljoin(f"{self.base_url}/", path.lstrip("/"))
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(target_url, data=body, headers=headers, method="POST" if payload is not None else "GET")
        with urlopen(request, timeout=self.timeout_seconds) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}

    def is_available(self) -> bool:
        try:
            self._request_json("/health")
            return True
        except (URLError, HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            logger.warning("OPA health check failed: %s", exc)
            return False

    def check_routing_allowance(
        self, identity_context: Dict[str, Any], target_endpoint: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Evaluate if the current identity is authorized to invoke the target endpoint.
        """
        input_data = {
            "identity": identity_context,
            "resource": target_endpoint,
        }

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
