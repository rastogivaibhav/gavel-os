"""Unit tests for OPA validation engine."""

import pytest
from unittest.mock import patch, MagicMock
import json
import sys
sys.path.insert(0, 'control-plane')
from sentinel.opa_engine import OPAValidationEngine


@pytest.mark.unit
class TestOPAEngine:
    """Tests for OPAValidationEngine."""

    def test_initialization(self):
        """Test OPA engine initialization."""
        engine = OPAValidationEngine(host="opa.local", port=9999)
        assert engine.host == "opa.local"
        assert engine.port == 9999
        assert "opa.local:9999" in engine.base_url

    def test_initialization_with_env(self, monkeypatch):
        """Test OPA engine initialization with environment variables."""
        monkeypatch.setenv("OPA_URL", "http://opa-custom:8181")
        monkeypatch.setenv("OPA_PACKAGE_PATH", "custom/policy")
        monkeypatch.setenv("OPA_TIMEOUT_SECONDS", "5.0")

        engine = OPAValidationEngine()
        assert engine.base_url == "http://opa-custom:8181"
        assert engine.package_path == "custom/policy"
        assert engine.timeout_seconds == 5.0

    @patch("sentinel.opa_engine.urlopen")
    def test_is_available_success(self, mock_urlopen):
        """Test health check when OPA is available."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"version": "0.68.0"}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        engine = OPAValidationEngine()
        assert engine.is_available() is True

    @patch("sentinel.opa_engine.urlopen")
    def test_is_available_failure(self, mock_urlopen):
        """Test health check when OPA is unavailable."""
        # Make urlopen raise an exception when called
        mock_urlopen.side_effect = TimeoutError("Connection timeout")

        engine = OPAValidationEngine()
        assert engine.is_available() is False

    @patch("sentinel.opa_engine.urlopen")
    def test_check_routing_allowance_allow(self, mock_urlopen):
        """Test routing allowance returns ALLOW."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"result": true}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        engine = OPAValidationEngine()
        allowed, reason = engine.check_routing_allowance(
            identity_context={"user_id": "user-001", "roles": ["admin"]},
            target_endpoint={"path": "/external/validate", "method": "POST"},
        )

        assert allowed is True
        assert "Authorized" in reason

    @patch("sentinel.opa_engine.urlopen")
    def test_check_routing_allowance_deny(self, mock_urlopen):
        """Test routing allowance returns DENY."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"result": false}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        engine = OPAValidationEngine()
        allowed, reason = engine.check_routing_allowance(
            identity_context={"user_id": "user-001", "roles": []},
            target_endpoint={"path": "/admin", "method": "DELETE"},
        )

        assert allowed is False
        assert "Denied" in reason

    @patch("sentinel.opa_engine.urlopen")
    def test_evaluate_runtime_policy_allow(self, mock_urlopen):
        """Test runtime policy evaluation returns ALLOW."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"result": true, "verdict": "ALLOW"}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        engine = OPAValidationEngine()
        allowed, reason = engine.evaluate_runtime_policy(
            action="93.184.216.34",
            method="CONNECT",
            host_id="host-001",
            runtime_os="linux",
            agent_id="claude-code-1",
        )

        assert allowed is True
        assert "Authorized" in reason
        assert "ALLOW" in reason

    @patch("sentinel.opa_engine.urlopen")
    def test_evaluate_runtime_policy_deny(self, mock_urlopen):
        """Test runtime policy evaluation returns DENY."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"result": false, "verdict": "DENY"}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        engine = OPAValidationEngine()
        allowed, reason = engine.evaluate_runtime_policy(
            action="192.168.1.1",
            method="EXECUTE",
            host_id="host-001",
            runtime_os="windows",
            agent_id="unknown-agent",
        )

        assert allowed is False
        assert "Denied" in reason
        assert "DENY" in reason
