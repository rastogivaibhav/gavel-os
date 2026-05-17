"""
audit_tools.py — Immutable Audit Ledger

Provides tools to cryptographically chain and store governance
decisions and interaction logs, ensuring Zero Trust auditability.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import UTC, datetime

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sentinel.audit")
_POSTGRES_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL", "")
if not _POSTGRES_URL and os.getenv("ENV", "development") != "development":
    raise RuntimeError("POSTGRES_URL environment variable is required but not set.")
elif not _POSTGRES_URL:
    _POSTGRES_URL = "postgresql://sentinel:changeme@localhost:5432/sentinel_recipes"
_ENV = os.getenv("ENV", "development")

# Mock ledger for development mode
_MOCK_LEDGER: list[dict] = []
_GENESIS_HASH = "genesis"


def _canonical_event_json(event_type: str, event_data: dict) -> str:
    return json.dumps(
        {
            "recipe_id": event_type,
            "step_id": event_data.get("step_id", event_type),
            "actor": event_data.get("actor", event_data.get("customer_id", "system")),
            "action": event_data.get("action", event_type),
            "target_system": event_data.get("target_system", "audit-tools"),
            "outcome": event_data.get("outcome", "SUCCESS"),
            "payload_hash": event_data.get("payload_hash", "n/a"),
            "timestamp": event_data.get("timestamp", datetime.now(UTC).isoformat()),
            "metadata": event_data,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _compute_hash(event_json: str, previous_hash: str) -> str:
    """Compute the SHA-256 hash of the event and the previous hash."""
    return hashlib.sha256((previous_hash + event_json).encode("utf-8")).hexdigest()


async def _get_last_hash() -> str:
    """Retrieve the hash of the most recent entry in the ledger."""
    if _ENV == "development":
        if not _MOCK_LEDGER:
            return _GENESIS_HASH
        return _MOCK_LEDGER[-1]["current_hash"]

    try:
        import asyncpg

        conn = await asyncpg.connect(_POSTGRES_URL)
        try:
            row = await conn.fetchrow(
                "SELECT current_hash FROM audit_ledger ORDER BY created_at DESC LIMIT 1"
            )
            if row:
                return row["current_hash"]
            return _GENESIS_HASH
        finally:
            await conn.close()
    except Exception:
        # Fallback to genesis hash on DB connection failure
        return _GENESIS_HASH


async def log_audit_event(event_type: str, event_data: dict) -> dict:
    """Securely log an event into the immutable audit ledger.

    Computes a cryptographic hash chaining this event to the previous
    one, ensuring tamper-evidence.

    Args:
        event_type: String identifier for the type of event (e.g., 'interaction', 'status_change').
        event_data: JSON-serializable dictionary containing the event details.

    Returns:
        The ledger entry dictionary including the assigned hash.
    """
    previous_hash = await _get_last_hash()
    event_json = _canonical_event_json(event_type, event_data)
    current_hash = _compute_hash(event_json, previous_hash)

    entry = {
        "event_json": json.loads(event_json),
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "created_at": datetime.now(UTC).isoformat(),
    }

    if _ENV == "development":
        _MOCK_LEDGER.append(entry)
        return entry

    try:
        import asyncpg

        conn = await asyncpg.connect(_POSTGRES_URL)
        try:
            await conn.execute(
                """
                INSERT INTO audit_ledger (tenant_id, previous_hash, current_hash, event_json)
                VALUES ($1, $2, $3, $4::jsonb)
                """,
                event_data.get("tenant_id", "default"),
                previous_hash,
                current_hash,
                event_json,
            )
        finally:
            await conn.close()
        return entry
    except Exception as e:
        logger.error("Failed to write to audit ledger: %s", e)
        return entry


async def log_interaction(
    session_id: str, customer_id: str, query: str, intent: str, recipe_id: str, response: str
) -> dict:
    """Log a customer query interaction to the audit ledger."""
    event_data = {
        "session_id": session_id,
        "customer_id": customer_id,
        "query": query,
        "intent": intent,
        "recipe_id": recipe_id,
        "response_summary": response[:100] + "..." if len(response) > 100 else response,
    }
    return await log_audit_event("customer_interaction", event_data)


async def log_recipe_status_change(
    recipe_id: str, old_status: str, new_status: str, reason: str = ""
) -> dict:
    """Log a recipe status transition to the audit ledger."""
    event_data = {
        "recipe_id": recipe_id,
        "old_status": old_status,
        "new_status": new_status,
        "reason": reason,
    }
    return await log_audit_event("recipe_status_change", event_data)


def verify_ledger_integrity() -> bool:
    """Verify the cryptographic integrity of the entire audit ledger."""
    if _ENV == "development":
        ledger = _MOCK_LEDGER
    else:
        try:
            import asyncio

            import asyncpg

            async def _fetch_all():
                conn = await asyncpg.connect(_POSTGRES_URL)
                try:
                    rows = await conn.fetch("SELECT * FROM audit_ledger ORDER BY created_at ASC")
                    return [dict(row) for row in rows]
                finally:
                    await conn.close()

            ledger = asyncio.run(_fetch_all())
        except Exception:
            return False

    if not ledger:
        return True

    expected_previous = _GENESIS_HASH
    for entry in ledger:
        # Check chain link
        if entry["previous_hash"] != expected_previous:
            return False

        # Check payload integrity
        data = entry["event_json"]
        if isinstance(data, str):
            data = json.loads(data)

        event_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        computed_hash = _compute_hash(event_json, entry["previous_hash"])
        if computed_hash != entry["current_hash"]:
            return False

        expected_previous = computed_hash

    return True
