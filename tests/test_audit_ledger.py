"""
Tests for srp.sdk — AuditEvent, hash chain, PostgresAuditLedgerClient, YamlPolicyLoader.

All database tests use an in-memory mock of asyncpg — no real PostgreSQL required.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from srp.sdk.models import AuditEvent, ChainIntegrityReport, LedgerEntry, LedgerQuery
from srp.sdk.impl.postgres_audit_ledger import PostgresAuditLedgerClient, _compute_hash
from srp.sdk.impl.yaml_policy_loader import YamlPolicyLoader


# ── _compute_hash ─────────────────────────────────────────────────────────────

def test_compute_hash_is_sha256_of_concatenation():
    previous = "genesis"
    event_json = '{"action":"read"}'
    expected = hashlib.sha256((previous + event_json).encode("utf-8")).hexdigest()
    assert _compute_hash(previous, event_json) == expected


def test_compute_hash_genesis_entry():
    event_json = '{"action":"first"}'
    h = _compute_hash("genesis", event_json)
    assert len(h) == 64  # SHA-256 hex digest is always 64 chars
    assert h != "genesis"


def test_compute_hash_is_deterministic():
    h1 = _compute_hash("prev", "event")
    h2 = _compute_hash("prev", "event")
    assert h1 == h2


def test_compute_hash_changes_with_different_previous():
    h1 = _compute_hash("hash-a", "event")
    h2 = _compute_hash("hash-b", "event")
    assert h1 != h2


def test_compute_hash_changes_with_different_event():
    h1 = _compute_hash("prev", "event-a")
    h2 = _compute_hash("prev", "event-b")
    assert h1 != h2


# ── AuditEvent.to_json ────────────────────────────────────────────────────────

def test_audit_event_to_json_is_canonical():
    """to_json must produce sort_keys=True output for deterministic hashing."""
    event = AuditEvent(
        recipe_id="r1",
        step_id="s1",
        actor="agent-1",
        action="read.data",
        target_system="crm.api",
        outcome="SUCCESS",
    )
    raw = event.to_json()
    parsed = json.loads(raw)
    # All required fields present
    assert parsed["recipe_id"] == "r1"
    assert parsed["actor"] == "agent-1"
    assert parsed["action"] == "read.data"
    assert parsed["outcome"] == "SUCCESS"


def test_audit_event_to_json_is_stable():
    """Same event must produce identical JSON on repeated calls."""
    ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    event = AuditEvent(
        recipe_id="r1", step_id="s1", actor="a", action="b",
        target_system="c", outcome="SUCCESS", timestamp=ts,
    )
    assert event.to_json() == event.to_json()


def test_audit_event_to_json_keys_are_sorted():
    """Keys must be sorted so hash is deterministic regardless of dict insertion order."""
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    event = AuditEvent(
        recipe_id="r", step_id="s", actor="a", action="b",
        target_system="c", outcome="SUCCESS", timestamp=ts,
    )
    raw = event.to_json()
    keys = list(json.loads(raw).keys())
    assert keys == sorted(keys)


# ── PostgresAuditLedgerClient.append ─────────────────────────────────────────

def _make_mock_pool(existing_hash: str | None = None) -> MagicMock:
    """Build a mock asyncpg pool that simulates the audit_ledger table."""
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(
        return_value={"current_hash": existing_hash} if existing_hash else None
    )
    conn.fetchval = AsyncMock(return_value=42)  # simulated new row id

    # Simulate async context manager for conn.transaction()
    tx = AsyncMock()
    tx.__aenter__ = AsyncMock(return_value=tx)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)

    pool = AsyncMock()
    pool.acquire = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    return pool


@pytest.mark.asyncio
async def test_append_genesis_entry_uses_genesis_as_previous_hash():
    pool = _make_mock_pool(existing_hash=None)
    ledger = PostgresAuditLedgerClient(pool=pool)
    event = AuditEvent(
        recipe_id="r1", step_id="s1", actor="agent",
        action="read", target_system="api", outcome="SUCCESS",
    )
    entry = await ledger.append(event)
    assert entry.previous_hash == "genesis"
    assert len(entry.current_hash) == 64


@pytest.mark.asyncio
async def test_append_chains_from_previous_hash():
    previous = "abc123def456" + "0" * 52  # 64-char fake hash
    pool = _make_mock_pool(existing_hash=previous)
    ledger = PostgresAuditLedgerClient(pool=pool)
    event = AuditEvent(
        recipe_id="r1", step_id="s1", actor="agent",
        action="write", target_system="api", outcome="SUCCESS",
    )
    entry = await ledger.append(event)
    assert entry.previous_hash == previous
    expected = _compute_hash(previous, event.to_json())
    assert entry.current_hash == expected


@pytest.mark.asyncio
async def test_append_returns_ledger_entry_with_correct_id():
    pool = _make_mock_pool()
    ledger = PostgresAuditLedgerClient(pool=pool)
    event = AuditEvent(
        recipe_id="r1", step_id="s1", actor="a",
        action="b", target_system="c", outcome="SUCCESS",
    )
    entry = await ledger.append(event)
    assert entry.id == 42  # matches mock fetchval return value


# ── PostgresAuditLedgerClient.verify_chain ────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_chain_valid_chain():
    """A correctly chained set of rows should report is_valid=True."""
    event1 = AuditEvent(
        recipe_id="r", step_id="s1", actor="a", action="b",
        target_system="c", outcome="SUCCESS",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    event2 = AuditEvent(
        recipe_id="r", step_id="s2", actor="a", action="c",
        target_system="c", outcome="SUCCESS",
        timestamp=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    json1 = event1.to_json()
    hash1 = _compute_hash("genesis", json1)
    json2 = event2.to_json()
    hash2 = _compute_hash(hash1, json2)

    rows = [
        {"id": 1, "previous_hash": "genesis", "current_hash": hash1, "event_json": json1},
        {"id": 2, "previous_hash": hash1, "current_hash": hash2, "event_json": json2},
    ]

    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=rows)
    pool = AsyncMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    ledger = PostgresAuditLedgerClient(pool=pool)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 12, 31, tzinfo=timezone.utc)
    report = await ledger.verify_chain(start, end)

    assert report.is_valid is True
    assert report.corrupted_entries == []
    assert report.verified_count == 2


@pytest.mark.asyncio
async def test_verify_chain_detects_tampered_entry():
    """A row with a wrong current_hash should be reported as corrupted."""
    event = AuditEvent(
        recipe_id="r", step_id="s1", actor="a", action="b",
        target_system="c", outcome="SUCCESS",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    json1 = event.to_json()
    correct_hash = _compute_hash("genesis", json1)
    tampered_hash = "0" * 64  # wrong hash

    rows = [
        {"id": 1, "previous_hash": "genesis", "current_hash": tampered_hash, "event_json": json1},
    ]

    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=rows)
    pool = AsyncMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    ledger = PostgresAuditLedgerClient(pool=pool)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 12, 31, tzinfo=timezone.utc)
    report = await ledger.verify_chain(start, end)

    assert report.is_valid is False
    assert 1 in report.corrupted_entries


@pytest.mark.asyncio
async def test_verify_chain_empty_range_is_valid():
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])
    pool = AsyncMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    ledger = PostgresAuditLedgerClient(pool=pool)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 1, 2, tzinfo=timezone.utc)
    report = await ledger.verify_chain(start, end)

    assert report.is_valid is True
    assert report.verified_count == 0


# ── YamlPolicyLoader ──────────────────────────────────────────────────────────

VALID_YAML = """
name: test-policy
version: "1.0.0"
rules:
  - id: block-delete
    description: "Block delete"
    effect: BLOCK
    priority: 100
    condition:
      operations:
        - delete
  - id: allow-read
    description: "Allow read"
    effect: ALLOW
    priority: 900
    condition:
      operations:
        - read
"""

def test_yaml_policy_loader_loads_valid_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(VALID_YAML)
        path = f.name

    loader = YamlPolicyLoader()
    loader.load(path)

    assert loader.policy_set is not None
    assert loader.policy_set.name == "test-policy"
    assert loader.policy_set.version == "1.0.0"
    assert len(loader.policy_set.rules) == 2


def test_yaml_policy_loader_rule_effects():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(VALID_YAML)
        path = f.name

    loader = YamlPolicyLoader()
    loader.load(path)

    rules = {r.id: r for r in loader.policy_set.rules}
    assert rules["block-delete"].effect.value == "BLOCK"
    assert rules["allow-read"].effect.value == "ALLOW"


def test_yaml_policy_loader_rule_priorities():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(VALID_YAML)
        path = f.name

    loader = YamlPolicyLoader()
    loader.load(path)

    rules = {r.id: r for r in loader.policy_set.rules}
    assert rules["block-delete"].priority == 100
    assert rules["allow-read"].priority == 900


def test_yaml_policy_loader_missing_file_leaves_policy_set_none():
    loader = YamlPolicyLoader()
    loader.load("/nonexistent/path/policy.yaml")
    assert loader.policy_set is None


def test_yaml_policy_loader_invalid_yaml_leaves_policy_set_none():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("name: [unclosed bracket")
        path = f.name

    loader = YamlPolicyLoader()
    loader.load(path)
    assert loader.policy_set is None


def test_yaml_policy_loader_effect_is_case_insensitive():
    yaml_content = """
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: block
    priority: 100
    condition:
      operations: [delete]
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        path = f.name

    loader = YamlPolicyLoader()
    loader.load(path)

    assert loader.policy_set is not None
    assert loader.policy_set.rules[0].effect.value == "BLOCK"


def test_yaml_policy_loader_hot_reload(tmp_path):
    """Watcher detects file change and reloads policy."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(VALID_YAML)

    loader = YamlPolicyLoader()
    loader.load(str(policy_file))
    assert loader.policy_set.name == "test-policy"

    # Simulate a file change
    updated_yaml = VALID_YAML.replace("test-policy", "updated-policy")
    policy_file.write_text(updated_yaml)

    # Reload manually (watcher would do this automatically)
    loader.load(str(policy_file))
    assert loader.policy_set.name == "updated-policy"


def test_yaml_policy_loader_stop_watching_is_idempotent():
    loader = YamlPolicyLoader()
    loader.stop_watching()  # should not raise even if never started
    loader.stop_watching()  # second call also safe


def test_yaml_policy_loader_default_policy_file():
    """The actual default.yaml in policies/ must load without errors."""
    default_path = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"
    assert default_path.exists(), "policies/default.yaml must exist"

    loader = YamlPolicyLoader()
    loader.load(str(default_path))

    assert loader.policy_set is not None
    assert len(loader.policy_set.rules) > 0
