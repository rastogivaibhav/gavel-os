"""Notification service for escalation workflows."""

import json
import logging
import os
import smtplib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

import httpx

logger = logging.getLogger("sentinel.notification")


class NotificationType(str, Enum):
    """Types of notifications."""

    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    DENIED = "denied"
    REMINDER = "reminder"
    ESCALATION_EXPIRED = "escalation_expired"


@dataclass
class NotificationPayload:
    """Notification payload."""

    notification_type: NotificationType
    tenant_id: str
    escalation_id: str
    ticket_number: str
    tool_call_id: str
    operation: str
    agent_id: str
    approver_id: Optional[str] = None
    approval_reason: Optional[str] = None
    deadline: Optional[datetime] = None
    parameters: Optional[dict] = None


class NotificationBackend(ABC):
    """Abstract base for notification backends."""

    @abstractmethod
    async def send(self, payload: NotificationPayload) -> bool:
        """Send notification.

        Args:
            payload: Notification payload

        Returns:
            True if successful, False otherwise
        """
        pass


class LoggingBackend(NotificationBackend):
    """Backend that logs notifications to structured logs."""

    async def send(self, payload: NotificationPayload) -> bool:
        """Log notification to structured logs."""
        try:
            log_data = {
                "notification_type": payload.notification_type.value,
                "tenant_id": payload.tenant_id,
                "escalation_id": payload.escalation_id,
                "ticket_number": payload.ticket_number,
                "tool_call_id": payload.tool_call_id,
                "operation": payload.operation,
                "agent_id": payload.agent_id,
                "approver_id": payload.approver_id,
            }

            if payload.notification_type == NotificationType.APPROVAL_REQUIRED:
                logger.info(
                    f"NOTIFICATION: Approval required for {payload.ticket_number}",
                    extra={
                        "notification": log_data,
                        "deadline": payload.deadline.isoformat() if payload.deadline else None,
                    },
                )

            elif payload.notification_type == NotificationType.APPROVED:
                logger.info(
                    f"NOTIFICATION: Escalation {payload.ticket_number} approved",
                    extra={
                        "notification": log_data,
                        "reason": payload.approval_reason,
                    },
                )

            elif payload.notification_type == NotificationType.DENIED:
                logger.info(
                    f"NOTIFICATION: Escalation {payload.ticket_number} denied",
                    extra={
                        "notification": log_data,
                        "reason": payload.approval_reason,
                    },
                )

            elif payload.notification_type == NotificationType.ESCALATION_EXPIRED:
                logger.warning(
                    f"NOTIFICATION: Escalation {payload.ticket_number} expired",
                    extra={"notification": log_data},
                )

            return True

        except Exception as e:
            logger.error(f"Failed to log notification: {e}")
            return False


class SlackBackend(NotificationBackend):
    """Backend that sends notifications via Slack webhook."""

    def __init__(self, webhook_url: Optional[str] = None):
        """Initialize Slack backend.

        Args:
            webhook_url: Slack webhook URL (defaults to env SLACK_WEBHOOK_URL)
        """
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")

    async def send(self, payload: NotificationPayload) -> bool:
        """Send notification to Slack."""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        try:
            message = self._format_message(payload)

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=message,
                    timeout=10,
                )
                response.raise_for_status()

            logger.info(f"Sent Slack notification for {payload.ticket_number}")
            return True

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    def _format_message(self, payload: NotificationPayload) -> dict:
        """Format notification as Slack message."""
        if payload.notification_type == NotificationType.APPROVAL_REQUIRED:
            return {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🔔 Escalation Approval Required",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Ticket:*\n{payload.ticket_number}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Agent:*\n{payload.agent_id}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Operation:*\n{payload.operation}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Tenant:*\n{payload.tenant_id}",
                            },
                        ],
                    },
                    {
                        "type": "divider",
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Parameters:*\n```{json.dumps(payload.parameters, indent=2)}```",
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Deadline:*\n{payload.deadline.isoformat() if payload.deadline else 'N/A'}",
                        },
                    },
                ]
            }

        elif payload.notification_type == NotificationType.APPROVED:
            return {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ Escalation Approved",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Ticket:*\n{payload.ticket_number}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Approver:*\n{payload.approver_id}",
                            },
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Reason:*\n{payload.approval_reason or 'No reason provided'}",
                        },
                    },
                ]
            }

        elif payload.notification_type == NotificationType.DENIED:
            return {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "❌ Escalation Denied",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Ticket:*\n{payload.ticket_number}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Approver:*\n{payload.approver_id}",
                            },
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Reason:*\n{payload.approval_reason or 'No reason provided'}",
                        },
                    },
                ]
            }

        else:
            return {
                "text": f"{payload.notification_type.value}: {payload.ticket_number}"
            }


class EmailBackend(NotificationBackend):
    """Backend that sends notifications via email."""

    def __init__(self, smtp_server: Optional[str] = None):
        """Initialize email backend.

        Args:
            smtp_server: SMTP server address (defaults to env SMTP_SERVER)
        """
        self.smtp_server = smtp_server or os.getenv("SMTP_SERVER")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.from_email = os.getenv("NOTIFICATION_FROM_EMAIL", "noreply@gavel.io")
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")

    async def send(self, payload: NotificationPayload) -> bool:
        """Send notification via email."""
        if not self.smtp_server:
            logger.warning("SMTP server not configured")
            return False

        try:
            # Get recipient email (would come from approver lookup in real system)
            recipient_email = os.getenv("NOTIFICATION_TO_EMAIL", "ops@gavel.io")

            subject, body = self._format_email(payload)

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = recipient_email

            msg.attach(MIMEText(body, "plain"))

            # Send email synchronously (simplified for now)
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(f"Sent email notification for {payload.ticket_number}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False

    def _format_email(self, payload: NotificationPayload) -> tuple[str, str]:
        """Format notification as email subject and body."""
        if payload.notification_type == NotificationType.APPROVAL_REQUIRED:
            subject = f"Escalation Approval Required: {payload.ticket_number}"
            body = f"""
Escalation Approval Required

Ticket: {payload.ticket_number}
Agent: {payload.agent_id}
Operation: {payload.operation}
Tenant: {payload.tenant_id}
Tool Call: {payload.tool_call_id}

Parameters:
{json.dumps(payload.parameters, indent=2)}

Deadline: {payload.deadline.isoformat() if payload.deadline else 'N/A'}

Please review and approve or deny this escalation.
"""

        elif payload.notification_type == NotificationType.APPROVED:
            subject = f"Escalation Approved: {payload.ticket_number}"
            body = f"""
Escalation Approved

Ticket: {payload.ticket_number}
Approved by: {payload.approver_id}
Reason: {payload.approval_reason or 'No reason provided'}

The escalation has been approved and the operation will proceed.
"""

        elif payload.notification_type == NotificationType.DENIED:
            subject = f"Escalation Denied: {payload.ticket_number}"
            body = f"""
Escalation Denied

Ticket: {payload.ticket_number}
Denied by: {payload.approver_id}
Reason: {payload.approval_reason or 'No reason provided'}

The escalation has been denied and the operation will not proceed.
"""

        else:
            subject = f"Notification: {payload.ticket_number}"
            body = f"Notification type: {payload.notification_type.value}"

        return subject, body


class NotificationService:
    """Manages notification backends and dispatch."""

    def __init__(
        self,
        enable_logging: bool = True,
        enable_slack: bool = True,
        enable_email: bool = True,
    ):
        """Initialize notification service.

        Args:
            enable_logging: Enable logging backend
            enable_slack: Enable Slack backend
            enable_email: Enable email backend
        """
        self.backends: list[NotificationBackend] = []

        if enable_logging:
            self.backends.append(LoggingBackend())

        if enable_slack and os.getenv("SLACK_WEBHOOK_URL"):
            self.backends.append(SlackBackend())

        if enable_email and os.getenv("SMTP_SERVER"):
            self.backends.append(EmailBackend())

        logger.info(f"Notification service initialized with {len(self.backends)} backends")

    async def send(self, payload: NotificationPayload) -> bool:
        """Send notification to all configured backends.

        Args:
            payload: Notification payload

        Returns:
            True if at least one backend succeeded
        """
        results = []
        for backend in self.backends:
            try:
                result = await backend.send(payload)
                results.append(result)
            except Exception as e:
                logger.error(f"Notification backend error: {e}")
                results.append(False)

        return any(results) if results else False

    async def send_approval_required(
        self,
        tenant_id: str,
        escalation_id: str,
        ticket_number: str,
        tool_call_id: str,
        operation: str,
        agent_id: str,
        deadline: datetime,
        parameters: Optional[dict] = None,
    ) -> bool:
        """Send approval required notification."""
        payload = NotificationPayload(
            notification_type=NotificationType.APPROVAL_REQUIRED,
            tenant_id=tenant_id,
            escalation_id=escalation_id,
            ticket_number=ticket_number,
            tool_call_id=tool_call_id,
            operation=operation,
            agent_id=agent_id,
            deadline=deadline,
            parameters=parameters,
        )
        return await self.send(payload)

    async def send_approval_granted(
        self,
        tenant_id: str,
        escalation_id: str,
        ticket_number: str,
        tool_call_id: str,
        operation: str,
        agent_id: str,
        approver_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """Send approval granted notification."""
        payload = NotificationPayload(
            notification_type=NotificationType.APPROVED,
            tenant_id=tenant_id,
            escalation_id=escalation_id,
            ticket_number=ticket_number,
            tool_call_id=tool_call_id,
            operation=operation,
            agent_id=agent_id,
            approver_id=approver_id,
            approval_reason=reason,
        )
        return await self.send(payload)

    async def send_approval_denied(
        self,
        tenant_id: str,
        escalation_id: str,
        ticket_number: str,
        tool_call_id: str,
        operation: str,
        agent_id: str,
        approver_id: str,
        reason: Optional[str] = None,
    ) -> bool:
        """Send approval denied notification."""
        payload = NotificationPayload(
            notification_type=NotificationType.DENIED,
            tenant_id=tenant_id,
            escalation_id=escalation_id,
            ticket_number=ticket_number,
            tool_call_id=tool_call_id,
            operation=operation,
            agent_id=agent_id,
            approver_id=approver_id,
            approval_reason=reason,
        )
        return await self.send(payload)
