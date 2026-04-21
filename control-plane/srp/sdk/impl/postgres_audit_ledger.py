"""
postgres_audit_ledger.py — PostgreSQL-backed cryptographic audit ledger.

Each appended event is SHA-256 hashed together with the previous entry's
hash, forming a tamper-evident chain. The genesis entry uses "genesis" as
its previous_hash.

The underlying table is append-only (enforced by PostgreSQL NO UPDATE /
NO DELETE rules — see database/migrations/001_initial_audit_ledger.sql).

Thread safety: asyncpg connection pools are safe for concurrent use.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from srp.sdk.models import AuditEvent, ChainIntegrityReport, LedgerEntry, LedgerQuery

logger = logging.getLogger("srp.audit_ledger")


def _compute_hash(previous_hash: str, event_json: str) -> str:
    """Compute SHA-256(previous_hash + event_json)."""
    raw = (previous_hash + event_json).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class PostgresAuditLedgerClient:
    """
    Append-only audit ledger backed by PostgreSQL.

    Usage:
        pool = await asyncpg.create_pool(dsn=DATABASE_URL)
        ledger = PostgresAuditLedgerClient(pool=pool)

        entry = await ledger.append(AuditEvent(...))
        entries = await ledger.query(LedgerQuery(...))
        report = await ledger.verify_chain(start, end)
    """

    def __init__(self, pool) -> None:
        self._pool = pool

    async def append(self, event: AuditEvent) -> LedgerEntry:
        """
        Append an event to the ledger.

        Fetches the current chain tip inside a serialisable transaction,
        computes the new hash, and inserts the row atomically.
        """
        event_json = event.to_json()

        async with self._pool.acquire() as conn:
            async with conn.transaction(isolation="serializable"):
                # Fetch the most recent hash for this tenant
                row = await conn.fetchrow(
                    """
                    SELECT current_hash
                    FROM audit_ledger
                    WHERE tenant_id = $1
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    "default",
                )
                previous_hash = row["current_hash"] if row else "genesis"
                current_hash = _compute_hash(previous_hash, event_json)

                new_id = await conn.fetchval(
                    """
                    INSERT INTO audit_ledger
                        (tenant_id, previous_hash, current_hash, event_json)
                    VALUES ($1, $2, $3, $4::jsonb)
                    RETURNING id
                    """,
                    "default",
                    previous_hash,
                    current_hash,
                    event_json,
                )

        logger.debug(
            "Audit ledger append: id=%s actor=%s action=%s hash=%s",
            new_id,
            event.actor,
            event.action,
            current_hash[:12],
        )
        return LedgerEntry(
            id=new_id,
            previous_hash=previous_hash,
            current_hash=current_hash,
            event=event,
        )

    async def query(self, query: LedgerQuery) -> List[LedgerEntry]:
        """
        Query ledger entries within a date range, optionally filtered by actor.
        """
        async with self._pool.acquire() as conn:
            if query.actor:
                rows = await conn.fetch(
                    """
                    SELECT id, previous_hash, current_hash, event_json, created_at
                    FROM audit_ledger
                    WHERE tenant_id = $1
                      AND created_at >= $2
                      AND created_at <= $3
                      AND event_json->>'actor' = $4
                    ORDER BY id ASC
                    LIMIT $5
                    """,
                    query.tenant_id,
                    query.start_date,
                    query.end_date,
                    query.actor,
                    query.limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT id, previous_hash, current_hash, event_json, created_at
                    FROM audit_ledger
                    WHERE tenant_id = $1
                      AND created_at >= $2
                      AND created_at <= $3
                    ORDER BY id ASC
                    LIMIT $4
                    """,
                    query.tenant_id,
                    query.start_date,
                    query.end_date,
                    query.limit,
                )

        entries: List[LedgerEntry] = []
        for row in rows:
            raw = row["event_json"]
            event_data = raw if isinstance(raw, dict) else json.loads(raw)
            ts_raw = event_data.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_raw)
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc)

            event = AuditEvent(
                recipe_id=event_data.get("recipe_id", ""),
                step_id=event_data.get("step_id", ""),
                actor=event_data.get("actor", ""),
                action=event_data.get("action", ""),
                target_system=event_data.get("target_system", ""),
                outcome=event_data.get("outcome", ""),
                payload_hash=event_data.get("payload_hash", "n/a"),
                timestamp=ts,
                metadata=event_data.get("metadata", {}),
            )
            entries.append(
                LedgerEntry(
                    id=row["id"],
                    previous_hash=row["previous_hash"],
                    current_hash=row["current_hash"],
                    event=event,
                    created_at=row["created_at"],
                )
            )
        return entries

    async def verify_chain(
        self,
        start_date: datetime,
        end_date: datetime,
        tenant_id: str = "default",
    ) -> ChainIntegrityReport:
        """
        Walk the ledger in chronological order and verify the hash chain.

        For each entry, recomputes SHA-256(previous_hash + event_json) and
        compares it to the stored current_hash. Any mismatch is recorded as
        a corrupted entry.
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, previous_hash, current_hash, event_json
                FROM audit_ledger
                WHERE tenant_id = $1
                  AND created_at >= $2
                  AND created_at <= $3
                ORDER BY id ASC
                """,
                tenant_id,
                start_date,
                end_date,
            )

        corrupted: List[int] = []
        for row in rows:
            raw = row["event_json"]
            event_json = raw if isinstance(raw, str) else json.dumps(
                raw if isinstance(raw, dict) else json.loads(raw),
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = _compute_hash(row["previous_hash"], event_json)
            if expected != row["current_hash"]:
                corrupted.append(row["id"])
                logger.warning(
                    "Chain integrity violation at id=%s expected=%s stored=%s",
                    row["id"],
                    expected[:12],
                    row["current_hash"][:12],
                )

        return ChainIntegrityReport(
            is_valid=len(corrupted) == 0,
            corrupted_entries=corrupted,
            verified_count=len(rows),
        )
