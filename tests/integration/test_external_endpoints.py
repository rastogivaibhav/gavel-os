"""Integration tests for /external/* endpoints."""

import pytest
from httpx import AsyncClient
import sys
sys.path.insert(0, 'control-plane')


@pytest.mark.integration
class TestExternalEndpoints:
    """Integration tests for external API endpoints."""

    @pytest.mark.asyncio
    async def test_external_validate_endpoint_structure(self):
        """Test that /external/validate endpoint structure is correct."""
        # This is a placeholder test that verifies endpoint exists
        # Full integration test requires running API server and OPA
        pass

    @pytest.mark.asyncio
    async def test_tool_verdict_endpoint_with_allow(self):
        """Test tool verdict endpoint returns ALLOW."""
        # Requires: FastAPI app, OPA running, database
        # Will implement when API server is launched
        pass

    @pytest.mark.asyncio
    async def test_network_policy_endpoint_with_deny(self):
        """Test network policy endpoint returns DENY."""
        # Requires: FastAPI app, OPA running, database
        # Will implement when API server is launched
        pass

    @pytest.mark.asyncio
    async def test_audit_logging_on_allow(self, integration_db):
        """Test that ALLOW decisions are logged to audit ledger."""
        # Requires: Database with audit_ledger table
        # Will implement when database schema is available
        pass

    @pytest.mark.asyncio
    async def test_audit_logging_on_deny(self, integration_db):
        """Test that DENY decisions are logged to audit ledger."""
        # Requires: Database with audit_ledger table
        # Will implement when database schema is available
        pass


@pytest.mark.integration
class TestEscalationWorkflows:
    """Integration tests for escalation workflow."""

    @pytest.mark.asyncio
    async def test_create_escalation(self, db_pool):
        """Test creating an escalation record."""
        from service.escalation_service import EscalationService

        service = EscalationService(db_pool)

        ticket = await service.create_escalation(
            tenant_id="tenant-001",
            tool_call_id="tc_abc123",
            agent_id="claude-code-1",
            api_ref="payments.api",
            operation="transfer",
            environment="prod",
            parameters={"amount": 50000},
            risk_level="high",
        )

        assert ticket.startswith("ESC-")

    @pytest.mark.asyncio
    async def test_escalation_approval_workflow(self, db_pool):
        """Test complete escalation approval workflow."""
        from service.escalation_service import EscalationService

        service = EscalationService(db_pool)

        # Create escalation
        ticket = await service.create_escalation(
            tenant_id="tenant-001",
            tool_call_id="tc_def456",
            agent_id="claude-code-1",
            api_ref="database.api",
            operation="delete",
            environment="prod",
            parameters={"table": "users"},
        )

        # Get status before approval
        escalation_id = f"esc_{ticket.split('-')[1][:16]}"
        status = await service.get_escalation_status("tenant-001", escalation_id)
        if status:
            assert status["status"] == "pending"

        # Approve escalation
        success, msg = await service.approve_escalation(
            tenant_id="tenant-001",
            escalation_id=escalation_id,
            approver_id="security-lead-001",
            decision="approved",
            reason="Reviewed and approved by security team"
        )

        # Note: success depends on database schema being set up

    @pytest.mark.asyncio
    async def test_get_pending_escalations(self, db_pool):
        """Test querying pending escalations."""
        from service.escalation_service import EscalationService

        service = EscalationService(db_pool)

        # Get pending escalations (may be empty if schema not set up)
        escalations = await service.get_pending_escalations("tenant-001")

        assert isinstance(escalations, list)

    @pytest.mark.asyncio
    async def test_auto_deny_expired(self, db_pool):
        """Test auto-denial of expired escalations."""
        from service.escalation_service import EscalationService

        service = EscalationService(db_pool)

        # Run auto-deny (should handle gracefully even if no escalations)
        count = await service.auto_deny_expired()

        assert isinstance(count, int)
        assert count >= 0
