"""
srp.sdk.models — Shared data models for the audit ledger SDK.

AuditEvent:   A single immutable event to be appended to the ledger.
LedgerEntry:  A persisted ledger row with hash chain fields.
LedgerQuery:  Query parameters for ledger retrieval.
ChainIntegrityReport: Result of a chain verification pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class AuditEvent:
    """A single immutable event to be appended to the audit ledger."""

    recipe_id: str
    step_id: str
    actor: str
    action: str
    target_system: str
    outcome: str
    payload_hash: str = "n/a"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialise the event to a canonical JSON string for hashing."""
        return json.dumps(
            {
                "recipe_id": self.recipe_id,
                "step_id": self.step_id,
                "actor": self.actor,
                "action": self.action,
                "target_system": self.target_system,
                "outcome": self.outcome,
                "payload_hash": self.payload_hash,
                "timestamp": self.timestamp.isoformat(),
                "metadata": self.metadata,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass
class LedgerEntry:
    """A persisted ledger row with cryptographic chain fields."""

    id: int
    previous_hash: str
    current_hash: str
    event: AuditEvent
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class LedgerQuery:
    """Query parameters for audit ledger retrieval."""

    tenant_id: str = "default"
    start_date: datetime = field(default_factory=lambda: datetime(2020, 1, 1, tzinfo=UTC))
    end_date: datetime = field(default_factory=lambda: datetime(2030, 12, 31, tzinfo=UTC))
    actor: str | None = None
    limit: int = 500


@dataclass
class ChainIntegrityReport:
    """Result of a ledger chain integrity verification pass."""

    is_valid: bool
    corrupted_entries: list[int] = field(default_factory=list)
    verified_count: int = 0
    verified_at: datetime = field(default_factory=lambda: datetime.now(UTC))
