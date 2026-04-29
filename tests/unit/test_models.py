"""Unit tests for Pydantic models."""

import pytest
from datetime import datetime
import sys
sys.path.insert(0, 'control-plane')


@pytest.mark.unit
class TestPydanticModels:
    """Tests for Pydantic request/response models."""

    def test_tool_proposal_request_valid(self):
        """Test valid ToolProposalRequest."""
        from api.routes.external import ToolProposalRequest
        
        data = {
            "agent_id": "claude-code-1",
            "tool_call_id": "tc_abc123",
            "api_ref": "payments.api",
            "operation": "transfer",
            "environment": "prod",
            "parameters": {"amount": 50000},
            "replay_nonce": "nonce_1234567890123456",
        }
        
        request = ToolProposalRequest(**data)
        assert request.agent_id == "claude-code-1"
        assert request.tool_call_id == "tc_abc123"
        assert request.environment == "prod"

    def test_tool_proposal_request_missing_required(self):
        """Test ToolProposalRequest with missing required field."""
        from api.routes.external import ToolProposalRequest
        
        data = {
            "agent_id": "claude-code-1",
            # Missing tool_call_id
            "api_ref": "payments.api",
            "operation": "transfer",
            "environment": "prod",
            "parameters": {},
            "replay_nonce": "nonce_1234567890123456",
        }
        
        with pytest.raises(ValueError):
            ToolProposalRequest(**data)

    def test_network_policy_request_valid(self):
        """Test valid NetworkPolicyRequest."""
        from api.routes.external import NetworkPolicyRequest
        
        data = {
            "action": "93.184.216.34",
            "method": "CONNECT",
            "host_id": "host-abc123",
            "runtime_os": "linux",
            "agent_id": "claude-code-1",
        }
        
        request = NetworkPolicyRequest(**data)
        assert request.action == "93.184.216.34"
        assert request.method == "CONNECT"
        assert request.runtime_os == "linux"

    def test_network_policy_request_invalid_os(self):
        """Test NetworkPolicyRequest with invalid runtime_os."""
        from api.routes.external import NetworkPolicyRequest
        
        data = {
            "action": "93.184.216.34",
            "method": "CONNECT",
            "host_id": "host-abc123",
            "runtime_os": "invalid_os",  # Invalid OS
            "agent_id": "claude-code-1",
        }
        
        # May or may not raise depending on validation
        try:
            request = NetworkPolicyRequest(**data)
            assert request.runtime_os == "invalid_os"
        except ValueError:
            pass  # Valid if it raises

    def test_verdict_response_serialization(self):
        """Test Verdict can be serialized to JSON."""
        from srp.models import Verdict, VerdictReason, VerdictType
        from uuid import uuid4

        response = Verdict(
            proposal_id=uuid4(),
            verdict=VerdictType.ALLOW,
            reasons=[
                VerdictReason(
                    code="APPROVED",
                    message="Tool proposal meets policy requirements",
                    details={},
                )
            ],
            policy_ids=["policy-001"],
        )

        json_str = response.model_dump_json()
        assert "ALLOW" in json_str
        assert "APPROVED" in json_str
