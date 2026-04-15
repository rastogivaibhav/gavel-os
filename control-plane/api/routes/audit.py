"""
audit.py — Audit Ledger API Routes

Provides endpoints to query the cryptographically chained audit ledger
and verify chain integrity. Backed by PostgresAuditLedgerClient.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()
logger = logging.getLogger("sentinel-recipe-engine")


class LedgerQueryParams(BaseModel):
    """Query parameters for audit ledger search."""
    start_date: datetime
    end_date: datetime
    actor: Optional[str] = None
    tenant_id: str = "default"


class VerifyRequest(BaseModel):
    """Request body for chain integrity verification."""
    start_date: datetime = datetime(2020, 1, 1, tzinfo=timezone.utc)
    end_date: datetime = datetime(2030, 12, 31, tzinfo=timezone.utc)


@router.post("/ledger")
async def query_audit_ledger(request: Request, params: LedgerQueryParams):
    """Query the immutable audit ledger for entries within a date range.

    Returns ledger entries in ascending chronological order.
    Each entry includes its SHA-256 hash and the previous entry's hash,
    forming a verifiable chain.
    """
    ledger = getattr(request.app.state, "audit_ledger", None)
    if ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Audit ledger is not available. Ensure PostgreSQL is running.",
        )

    from srp.sdk.models import LedgerQuery

    try:
        query = LedgerQuery(
            tenant_id=params.tenant_id,
            start_date=params.start_date,
            end_date=params.end_date,
            actor=params.actor,
        )
        entries = await ledger.query(query)
        return {
            "count": len(entries),
            "entries": [
                {
                    "id": e.id,
                    "previous_hash": e.previous_hash,
                    "current_hash": e.current_hash,
                    "event": {
                        "recipe_id": e.event.recipe_id,
                        "step_id": e.event.step_id,
                        "actor": e.event.actor,
                        "action": e.event.action,
                        "target_system": e.event.target_system,
                        "outcome": e.event.outcome,
                        "timestamp": e.event.timestamp.isoformat(),
                    },
                }
                for e in entries
            ],
        }
    except Exception as e:
        logger.exception("Audit ledger query failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify")
async def verify_chain_integrity(request: Request, params: VerifyRequest):
    """Verify the cryptographic chain integrity of the audit ledger.

    Walks the ledger in chronological order and verifies that each entry's
    SHA-256 hash correctly references the previous entry's hash.
    Returns a ChainIntegrityReport indicating whether the chain is valid
    and listing any corrupted entries.
    """
    ledger = getattr(request.app.state, "audit_ledger", None)
    if ledger is None:
        raise HTTPException(
            status_code=503,
            detail="Audit ledger is not available. Ensure PostgreSQL is running.",
        )

    try:
        report = await ledger.verify_chain(params.start_date, params.end_date)
        return {
            "is_valid": report.is_valid,
            "corrupted_entries": report.corrupted_entries,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.exception("Chain verification failed")
        raise HTTPException(status_code=500, detail=str(e))
