"""Phase 2 Integration Tests - Escalation Workflow End-to-End."""

import asyncio
import json
import pytest
import sys

sys.path.insert(0, 'control-plane')


@pytest.mark.integration
class TestEscalationWorkflow:
    """Test complete escalation workflow."""

    def test_escalation_service_available(self):
        """Test that escalation service can be imported."""
        from service.escalation_service import EscalationService

        assert EscalationService is not None

    @pytest.mark.asyncio
    async def test_escalation_creation(self, integration_db_pool):
        """Test creating an escalation record."""
        from service.escalation_service import EscalationService

        service = EscalationService(integration_db_pool)

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
        assert "tc_abc123" in ticket

    @pytest.mark.asyncio
    async def test_escalation_status_query(self, integration_db_pool):
        """Test querying escalation status."""
        from service.escalation_service import EscalationService

        service = EscalationService(integration_db_pool)

        # Create escalation
        ticket = await service.create_escalation(
            tenant_id="tenant-002",
            tool_call_id="tc_def456",
            agent_id="claude-code-1",
            api_ref="database.api",
            operation="delete",
            environment="prod",
            parameters={"table": "users"},
            risk_level="high",
        )

        # Extract escalation ID from ticket
        escalation_id = f"esc_{ticket.split('-')[1][:16]}"

        # Query status
        status = await service.get_escalation_status("tenant-002", escalation_id)

        assert status is not None
        assert status["status"] == "pending"
        assert status["ticket_number"] == ticket

    @pytest.mark.asyncio
    async def test_escalation_approval_workflow(self, integration_db_pool):
        """Test complete escalation approval workflow."""
        from service.escalation_service import EscalationService

        service = EscalationService(integration_db_pool)

        # Create escalation
        ticket = await service.create_escalation(
            tenant_id="tenant-003",
            tool_call_id="tc_ghi789",
            agent_id="claude-code-1",
            api_ref="payments.api",
            operation="transfer",
            environment="prod",
            parameters={"amount": 100000},
            risk_level="high",
        )

        escalation_id = f"esc_{ticket.split('-')[1][:16]}"

        # Get initial status
        status = await service.get_escalation_status("tenant-003", escalation_id)
        assert status["status"] == "pending"

        # Approve escalation
        success, message = await service.approve_escalation(
            tenant_id="tenant-003",
            escalation_id=escalation_id,
            approver_id="security-lead-001",
            decision="approved",
            reason="Reviewed and approved by security team"
        )

        assert success is True

        # Get updated status
        status = await service.get_escalation_status("tenant-003", escalation_id)
        assert status["status"] == "approved"
        assert len(status["approvals"]) >= 1

    @pytest.mark.asyncio
    async def test_pending_escalations_query(self, integration_db_pool):
        """Test querying pending escalations."""
        from service.escalation_service import EscalationService

        service = EscalationService(integration_db_pool)

        # Create multiple escalations
        for i in range(3):
            await service.create_escalation(
                tenant_id="tenant-004",
                tool_call_id=f"tc_pending_{i}",
                agent_id="claude-code-1",
                api_ref="api.service",
                operation="update",
                environment="prod",
                parameters={"id": i},
                risk_level="medium",
            )

        # Get pending escalations
        escalations = await service.get_pending_escalations("tenant-004")

        assert len(escalations) >= 3
        assert all(e["status"] == "pending" for e in escalations)

    @pytest.mark.asyncio
    async def test_auto_deny_expired(self, integration_db_pool):
        """Test auto-denial of expired escalations."""
        from service.escalation_service import EscalationService

        service = EscalationService(integration_db_pool)

        # Run auto-deny (should handle gracefully even if no escalations)
        count = await service.auto_deny_expired()

        assert isinstance(count, int)
        assert count >= 0


@pytest.mark.integration
class TestNotificationIntegration:
    """Test notification service integration."""

    def test_notification_service_available(self):
        """Test that notification service can be imported."""
        from service.notification_service import NotificationService

        assert NotificationService is not None

    @pytest.mark.asyncio
    async def test_notification_service_sends_all_backends(self):
        """Test that notifications are sent to all configured backends."""
        from service.notification_service import (
            NotificationService,
            NotificationPayload,
            NotificationType,
        )
        from datetime import datetime, timezone

        service = NotificationService(
            enable_logging=True,
            enable_slack=False,
            enable_email=False,
        )

        payload = NotificationPayload(
            notification_type=NotificationType.APPROVAL_REQUIRED,
            tenant_id="tenant-test",
            escalation_id="esc_test",
            ticket_number="ESC-tc_test",
            tool_call_id="tc_test",
            operation="test_op",
            agent_id="test-agent",
            deadline=datetime.now(timezone.utc),
            parameters={"test": True},
        )

        result = await service.send(payload)
        assert result is True

    @pytest.mark.asyncio
    async def test_approval_required_notification(self):
        """Test sending approval required notification."""
        from service.notification_service import NotificationService
        from datetime import datetime, timezone, timedelta

        service = NotificationService(
            enable_logging=True,
            enable_slack=False,
            enable_email=False,
        )

        deadline = datetime.now(timezone.utc) + timedelta(hours=24)
        result = await service.send_approval_required(
            tenant_id="tenant-test",
            escalation_id="esc_test",
            ticket_number="ESC-tc_test",
            tool_call_id="tc_test",
            operation="transfer",
            agent_id="agent-1",
            deadline=deadline,
            parameters={"amount": 50000},
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_approval_granted_notification(self):
        """Test sending approval granted notification."""
        from service.notification_service import NotificationService

        service = NotificationService(
            enable_logging=True,
            enable_slack=False,
            enable_email=False,
        )

        result = await service.send_approval_granted(
            tenant_id="tenant-test",
            escalation_id="esc_test",
            ticket_number="ESC-tc_test",
            tool_call_id="tc_test",
            operation="transfer",
            agent_id="agent-1",
            approver_id="approver-1",
            reason="Approved by security lead",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_approval_denied_notification(self):
        """Test sending approval denied notification."""
        from service.notification_service import NotificationService

        service = NotificationService(
            enable_logging=True,
            enable_slack=False,
            enable_email=False,
        )

        result = await service.send_approval_denied(
            tenant_id="tenant-test",
            escalation_id="esc_test",
            ticket_number="ESC-tc_test",
            tool_call_id="tc_test",
            operation="transfer",
            agent_id="agent-1",
            approver_id="approver-1",
            reason="Insufficient justification",
        )

        assert result is True


@pytest.mark.integration
class TestExternalEndpointIntegration:
    """Test external API endpoints integration."""

    def test_external_routes_available(self):
        """Test that external routes can be imported."""
        from api.routes import external

        assert external.router is not None
        assert hasattr(external, 'evaluate_tool_proposal')

    def test_tool_proposal_request_model(self):
        """Test ToolProposalRequest model."""
        from api.routes.external import ToolProposalRequest

        request = ToolProposalRequest(
            agent_id="claude-code-1",
            tool_call_id="tc_test",
            api_ref="payments.api",
            operation="transfer",
            environment="prod",
            parameters={"amount": 50000},
            tenant_id="tenant-001",
        )

        assert request.agent_id == "claude-code-1"
        assert request.operation == "transfer"
        assert request.tenant_id == "tenant-001"

    def test_network_policy_request_model(self):
        """Test NetworkPolicyRequest model."""
        from api.routes.external import NetworkPolicyRequest

        request = NetworkPolicyRequest(
            action="93.184.216.34",
            method="CONNECT",
            host_id="host-001",
            runtime_os="linux",
            agent_id="claude-code-1",
        )

        assert request.action == "93.184.216.34"
        assert request.method == "CONNECT"
        assert request.runtime_os == "linux"


@pytest.mark.integration
class TestEscalationRoutesIntegration:
    """Test escalation routes integration."""

    def test_escalation_routes_available(self):
        """Test that escalation routes can be imported."""
        from api.routes import escalations

        assert escalations.router is not None
        assert hasattr(escalations, 'approve_escalation')
        assert hasattr(escalations, 'get_escalation_status')
        assert hasattr(escalations, 'list_pending_escalations')

    def test_escalation_approve_model(self):
        """Test EscalationApprove model."""
        from models.escalation import EscalationApprove

        approval = EscalationApprove(
            decision="approved",
            reason="Reviewed and approved"
        )

        assert approval.decision == "approved"
        assert approval.reason == "Reviewed and approved"
