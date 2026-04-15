"""
audit_tools.py — Immutable Audit Ledger

Provides tools to cryptographically chain and store governance
decisions and interaction logs, ensuring Zero Trust auditability.
"""

from __future__ import annotations

import json
import hashlib
import os
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv

load_dotenv()

import logging

logger = logging.getLogger("sentinel.audit")
_POSTGRES_URL = os.getenv("POSTGRES_URL", "")
if not _POSTGRES_URL and os.getenv("ENV", "development") != "development":
    raise RuntimeError("POSTGRES_URL environment variable is required but not set.")
elif not _POSTGRES_URL:
    _POSTGRES_URL = "postgresql://sentinel:changeme@localhost:5432/sentinel_recipes"
_ENV = os.getenv("ENV", "development")

# Mock ledger for development mode
_MOCK_LEDGER: list[dict] = []
_GENESIS_HASH = "0" * 64


def _compute_hash(event_type: str, event_data: dict, previous_hash: str) -> str:
    """Compute the SHA-256 hash of the event and the previous hash."""
    payload = {
        "event_type": event_type,
        "event_data": event_data,
        "previous_hash": previous_hash,
    }
    # Sort keys for deterministic JSON serialization
    serialized = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


async def _get_last_hash() -> str:
    """Retrieve the hash of the most recent entry in the ledger."""
    if _ENV == "development":
        if not _MOCK_LEDGER:
            return _GENESIS_HASH
        return _MOCK_LEDGER[-1]["hash"]

    try:
        import asyncpg
        conn = await asyncpg.connect(_POSTGRES_URL)
        try:
            row = await conn.fetchrow(
                "SELECT hash FROM audit_ledger ORDER BY created_at DESC LIMIT 1"
            )
            if row:
                return row["hash"]
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
    current_hash = _compute_hash(event_type, event_data, previous_hash)

    entry = {
        "event_type": event_type,
        "event_data": event_data,
        "previous_hash": previous_hash,
        "hash": current_hash,
        "created_at": datetime.now(timezone.utc).isoformat()
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
                INSERT INTO audit_ledger (event_type, event_data, previous_hash, hash)
                VALUES ($1, $2, $3, $4)
                """,
                event_type,
                json.dumps(event_data),
                previous_hash,
                current_hash
            )
        finally:
            await conn.close()
        return entry
    except Exception as e:
        logger.error("Failed to write to audit ledger: %s", e)
        return entry


async def log_interaction(session_id: str, customer_id: str, query: str, intent: str, recipe_id: str, response: str) -> dict:
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


async def log_recipe_status_change(recipe_id: str, old_status: str, new_status: str, reason: str = "") -> dict:
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
            import asyncpg
            import asyncio

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
        data = entry["event_data"] 
        if isinstance(data, str):
            data = json.loads(data)
            
        computed_hash = _compute_hash(entry["event_type"], data, entry["previous_hash"])
        if computed_hash != entry["hash"]:
            return False
            
        expected_previous = computed_hash

    return True
