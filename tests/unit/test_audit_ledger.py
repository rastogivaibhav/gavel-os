"""Unit tests for audit ledger and SHA-256 chain verification."""

import pytest
import hashlib
import json
from datetime import datetime
import sys
sys.path.insert(0, 'control-plane')


@pytest.mark.unit
class TestAuditChainVerification:
    """Tests for audit ledger SHA-256 chaining."""

    @staticmethod
    def compute_entry_hash(event_json: dict, previous_hash: str) -> str:
        """Compute SHA-256 hash for an audit entry."""
        content = json.dumps(event_json, sort_keys=True) + previous_hash
        return hashlib.sha256(content.encode()).hexdigest()

    def test_chain_hash_computation(self):
        """Test that entry hash is computed correctly."""
        event_json = {
            "action": "tool_proposal_verdict",
            "verdict": "ALLOW",
            "agent_id": "claude-code-1",
        }
        previous_hash = "abc123def456"

        computed_hash = self.compute_entry_hash(event_json, previous_hash)

        # Verify it's a valid SHA-256 hash (64 hex chars)
        assert len(computed_hash) == 64
        assert all(c in "0123456789abcdef" for c in computed_hash)

    def test_chain_hash_deterministic(self):
        """Test that same input produces same hash."""
        event_json = {"action": "allow", "verdict": "ALLOW"}
        previous_hash = "prev_hash_001"

        hash1 = self.compute_entry_hash(event_json, previous_hash)
        hash2 = self.compute_entry_hash(event_json, previous_hash)

        assert hash1 == hash2

    def test_chain_hash_different_on_change(self):
        """Test that hash changes when event changes."""
        event_json1 = {"action": "allow", "verdict": "ALLOW"}
        event_json2 = {"action": "deny", "verdict": "DENY"}
        previous_hash = "prev_hash_001"

        hash1 = self.compute_entry_hash(event_json1, previous_hash)
        hash2 = self.compute_entry_hash(event_json2, previous_hash)

        assert hash1 != hash2

    def test_chain_hash_includes_previous(self):
        """Test that hash depends on previous hash."""
        event_json = {"action": "allow"}
        prev1 = "prev_hash_001"
        prev2 = "prev_hash_002"

        hash1 = self.compute_entry_hash(event_json, prev1)
        hash2 = self.compute_entry_hash(event_json, prev2)

        assert hash1 != hash2

    def test_chain_integrity_multiple_entries(self):
        """Test chain integrity with multiple entries."""
        entries = [
            {"action": "allow", "verdict": "ALLOW", "timestamp": "2026-04-29T10:00:00Z"},
            {"action": "deny", "verdict": "DENY", "timestamp": "2026-04-29T10:01:00Z"},
            {"action": "escalate", "verdict": "ESCALATE", "timestamp": "2026-04-29T10:02:00Z"},
        ]

        # Build chain
        previous_hash = "genesis_hash"
        chain = []

        for entry in entries:
            entry_hash = self.compute_entry_hash(entry, previous_hash)
            chain.append({
                "event_json": entry,
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
            })
            previous_hash = entry_hash

        # Verify chain is intact
        assert len(chain) == 3
        assert chain[0]["previous_hash"] == "genesis_hash"
        assert chain[1]["previous_hash"] == chain[0]["entry_hash"]
        assert chain[2]["previous_hash"] == chain[1]["entry_hash"]

    def test_chain_tampering_detected(self):
        """Test that tampering with an entry breaks the chain."""
        entries = [
            {"action": "allow"},
            {"action": "deny"},
            {"action": "escalate"},
        ]

        # Build original chain
        previous_hash = "genesis"
        original_chain = []
        for entry in entries:
            entry_hash = self.compute_entry_hash(entry, previous_hash)
            original_chain.append({
                "event_json": entry,
                "entry_hash": entry_hash,
                "previous_hash": previous_hash,
            })
            previous_hash = entry_hash

        # Tamper with middle entry
        tampered_chain = original_chain.copy()
        tampered_chain[1]["event_json"]["action"] = "modified"

        # Recompute hash with tampered entry
        tampered_chain[1]["new_hash"] = self.compute_entry_hash(
            tampered_chain[1]["event_json"],
            tampered_chain[1]["previous_hash"]
        )

        # Verify the recomputed hash differs from original
        assert tampered_chain[1]["new_hash"] != original_chain[1]["entry_hash"]

        # Verify third entry would now have mismatched previous hash
        assert tampered_chain[2]["previous_hash"] == original_chain[1]["entry_hash"]
        # But we'd need to recompute entry 2 with tampered hash
        recomputed_entry3 = self.compute_entry_hash(
            tampered_chain[2]["event_json"],
            tampered_chain[1]["new_hash"]  # This would be the tampered hash
        )
        assert recomputed_entry3 != original_chain[2]["entry_hash"]

    @staticmethod
    def verify_chain(entries: list) -> tuple[bool, str]:
        """Verify an audit chain is unbroken."""
        if not entries:
            return True, "Empty chain"

        previous_hash = "genesis_hash"

        for i, entry in enumerate(entries):
            event_json = entry["event_json"]
            stored_hash = entry["entry_hash"]
            stored_previous = entry["previous_hash"]

            # Check previous hash matches
            if stored_previous != previous_hash:
                return False, f"Entry {i}: previous hash mismatch"

            # Recompute hash and verify
            computed_hash = hashlib.sha256(
                (json.dumps(event_json, sort_keys=True) + previous_hash).encode()
            ).hexdigest()

            if computed_hash != stored_hash:
                return False, f"Entry {i}: hash mismatch (tampered)"

            previous_hash = stored_hash

        return True, "Chain verified"

    def test_chain_verification_valid(self):
        """Test chain verification on valid chain."""
        # Build valid chain
        entries = []
        previous_hash = "genesis_hash"

        for i in range(3):
            event = {"action": f"action_{i}", "index": i}
            entry_hash = hashlib.sha256(
                (json.dumps(event, sort_keys=True) + previous_hash).encode()
            ).hexdigest()
            entries.append({
                "event_json": event,
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
            })
            previous_hash = entry_hash

        # Verify chain
        is_valid, reason = self.verify_chain(entries)
        assert is_valid is True
        assert "verified" in reason.lower()

    def test_chain_verification_tampered(self):
        """Test chain verification detects tampering."""
        # Build valid chain
        entries = []
        previous_hash = "genesis_hash"

        for i in range(3):
            event = {"action": f"action_{i}"}
            entry_hash = hashlib.sha256(
                (json.dumps(event, sort_keys=True) + previous_hash).encode()
            ).hexdigest()
            entries.append({
                "event_json": event,
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
            })
            previous_hash = entry_hash

        # Tamper with middle entry
        entries[1]["event_json"]["action"] = "TAMPERED"

        # Verify chain detects tampering
        is_valid, reason = self.verify_chain(entries)
        assert is_valid is False
        assert "mismatch" in reason.lower()
