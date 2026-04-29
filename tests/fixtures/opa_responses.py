"""Sample OPA response templates for testing."""

import json


class OPAResponseTemplates:
    """Pre-built OPA response templates."""

    @staticmethod
    def authorization_allow(reason: str = "Policy allows operation") -> dict:
        """Template: Authorization policy ALLOW."""
        return {
            "result": True,
            "reason": reason,
        }

    @staticmethod
    def authorization_deny(reason: str = "Policy denies operation") -> dict:
        """Template: Authorization policy DENY."""
        return {
            "result": False,
            "reason": reason,
        }

    @staticmethod
    def runtime_policy_allow(verdict: str = "ALLOW") -> dict:
        """Template: Runtime policy ALLOW."""
        return {
            "result": True,
            "verdict": verdict,
        }

    @staticmethod
    def runtime_policy_deny(verdict: str = "DENY") -> dict:
        """Template: Runtime policy DENY."""
        return {
            "result": False,
            "verdict": verdict,
        }

    @staticmethod
    def runtime_policy_escalate() -> dict:
        """Template: Runtime policy ESCALATE."""
        return {
            "result": None,
            "verdict": "ESCALATE",
        }

    @staticmethod
    def opa_health() -> dict:
        """Template: OPA health check response."""
        return {
            "version": "0.68.0",
            "capabilities": ["feature1", "feature2"],
        }

    @staticmethod
    def opa_error(message: str = "OPA evaluation error") -> dict:
        """Template: OPA error response."""
        return {
            "error": message,
        }
