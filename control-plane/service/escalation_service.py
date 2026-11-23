"""Service for managing tool proposal escalations."""

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

logger = logging.getLogger("sentinel.escalation")


class EscalationService:
    """Manages escalation workflow for tool proposals."""

    def __init__(self, db_pool):
        """Initialize with database pool."""
        self.db_pool = db_pool

    async def create_escalation(
        self,
        tenant_id: str,
        tool_call_id: str,
        agent_id: str,
        api_ref: str,
        operation: str,
        environment: str,
        parameters: dict,
        risk_level: str = "medium",
    ) -> str:
        """Create new escalation record.

        Returns:
            ticket_number: Unique escalation ticket identifier
        """
        escalation_id = f"esc_{uuid.uuid4().hex[:16]}"
        ticket_number = f"ESC-{tool_call_id[:20]}"
        now = datetime.now(UTC)
        deadline = now + timedelta(hours=24)

        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO escalations
                    (id, tenant_id, tool_call_id, agent_id, api_ref, operation,
                     environment, status, ticket_number, created_at, updated_at,
                     deadline, parameters, risk_level)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    """,
                    escalation_id,
                    tenant_id,
                    tool_call_id,
                    agent_id,
                    api_ref,
                    operation,
                    environment,
                    "pending",
                    ticket_number,
                    now,
                    now,
                    deadline,
                    json.dumps(parameters),
                    risk_level,
                )
            logger.info(f"Created escalation {ticket_number} for {tool_call_id}")
        except Exception as e:
            logger.error(f"Failed to create escalation: {e}")
            raise

        return ticket_number

    async def approve_escalation(
        self,
        tenant_id: str,
        escalation_id: str,
        approver_id: str,
        decision: str,
        reason: str | None = None,
    ) -> tuple[bool, str]:
        """Atomically record an approval on an existing pending escalation.

        Do not change status if the approval evidence cannot be persisted.
        """
        if decision not in ("approved", "denied"):
            return (False, "Invalid decision. Must be 'approved' or 'denied'")

        try:
            async with self.db_pool.acquire() as conn:
                async with conn.transaction():
                    changed = await conn.fetchrow(
                        """
                        UPDATE escalations
                        SET status = $1, updated_at = NOW()
                        WHERE id = $2 AND tenant_id = $3 AND status = 'pending'
                        RETURNING id
                        """,
                        decision,
                        escalation_id,
                        tenant_id,
                    )
                    if changed is None:
                        return (False, "Escalation not found or no longer pending")

                    approval_id = f"appr_{uuid.uuid4().hex[:16]}"
                    await conn.execute(
                        """
                        INSERT INTO escalation_approvals
                        (id, escalation_id, tenant_id, approver_id, decision, reason, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6, NOW())
                        """,
                        approval_id,
                        escalation_id,
                        tenant_id,
                        approver_id,
                        decision,
                        reason,
                    )
            logger.info(f"Escalation {escalation_id} {decision} by {approver_id}")
            return (True, f"Escalation marked as {decision}")
        except Exception as e:
            logger.error(f"Failed to approve escalation: {e}")
            return (False, str(e))

    async def get_escalation_status(
        self,
        tenant_id: str,
        escalation_id: str,
    ) -> dict | None:
        """Get current status of escalation."""
        try:
            async with self.db_pool.acquire() as conn:
                esc = await conn.fetchrow(
                    "SELECT * FROM escalations WHERE id = $1 AND tenant_id = $2",
                    escalation_id,
                    tenant_id,
                )

                if not esc:
                    return None

                # Get approvals
                approvals = await conn.fetch(
                    """
                    SELECT approver_id, decision, reason, created_at
                    FROM escalation_approvals
                    WHERE escalation_id = $1
                    """,
                    escalation_id,
                )

                return {
                    "id": esc["id"],
                    "ticket_number": esc["ticket_number"],
                    "status": esc["status"],
                    "created_at": esc["created_at"].isoformat(),
                    "deadline": esc["deadline"].isoformat(),
                    "approvals": [dict(a) for a in approvals],
                }
        except Exception as e:
            logger.error(f"Failed to get escalation status: {e}")
            return None

    async def get_pending_escalations(self, tenant_id: str) -> list[dict]:
        """Get all pending escalations for a tenant."""
        try:
            async with self.db_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT id, ticket_number, tool_call_id, agent_id, deadline, status
                    FROM escalations
                    WHERE tenant_id = $1 AND status = $2
                    ORDER BY created_at DESC
                    """,
                    tenant_id,
                    "pending",
                )
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to get pending escalations: {e}")
            return []

    async def auto_deny_expired(self) -> int:
        """Auto-deny escalations past deadline. Returns count of denied escalations."""
        try:
            async with self.db_pool.acquire() as conn:
                result = await conn.execute(
                    """
                    UPDATE escalations
                    SET status = $1, updated_at = NOW()
                    WHERE status = $2 AND deadline < NOW()
                    """,
                    "expired",
                    "pending",
                )
                count = int(result.split()[-1]) if result else 0
                if count > 0:
                    logger.info(f"Auto-denied {count} expired escalations")
                return count
        except Exception as e:
            logger.error(f"Failed to auto-deny expired escalations: {e}")
            return 0
