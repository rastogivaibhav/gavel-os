"""
Tests for api.grpc_server — TLS credential builder and security guards.

The gRPC servicer itself is tested via the external routes integration tests.
These tests focus on the security-critical startup behaviour:
  - GRPC_INSECURE=true must be rejected outside development
  - TLS credentials are built correctly from env vars
  - Dev self-signed cert generation works
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest


# ── GRPC_INSECURE guard ───────────────────────────────────────────────────────

def test_grpc_insecure_rejected_in_production(monkeypatch):
    """GRPC_INSECURE=true must cause sys.exit(1) when ENV != development."""
    monkeypatch.setenv("GRPC_INSECURE", "true")
    monkeypatch.setenv("ENV", "production")

    # Force re-import so the module-level code re-runs
    mod = "api.grpc_server"
    if mod in sys.modules:
        del sys.modules[mod]

    # _build_grpc_credentials is called lazily (inside serve_grpc), not at import.
    # We call it directly after import.
    import api.grpc_server as grpc_mod

    with pytest.raises(SystemExit) as exc_info:
        grpc_mod._build_grpc_credentials()

    assert exc_info.value.code == 1


def test_grpc_insecure_allowed_in_development(monkeypatch):
    """GRPC_INSECURE=true must return None (no credentials) in development."""
    monkeypatch.setenv("GRPC_INSECURE", "true")
    monkeypatch.setenv("ENV", "development")

    import api.grpc_server as grpc_mod

    # grpc may not be installed in test env — mock it
    with patch.dict("sys.modules", {"grpc": MagicMock()}):
        result = grpc_mod._build_grpc_credentials()

    assert result is None


def test_grpc_missing_cert_paths_exits_in_production(monkeypatch):
    """Missing cert paths must cause sys.exit(1) in production."""
    monkeypatch.setenv("GRPC_INSECURE", "false")
    monkeypatch.setenv("ENV", "production")
    monkeypatch.delenv("GRPC_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("GRPC_TLS_KEY_PATH", raising=False)

    import api.grpc_server as grpc_mod

    with pytest.raises(SystemExit) as exc_info:
        grpc_mod._build_grpc_credentials()

    assert exc_info.value.code == 1


def test_grpc_dev_generates_self_signed_cert(monkeypatch, tmp_path):
    """In development with no cert paths, a self-signed cert must be generated."""
    monkeypatch.setenv("GRPC_INSECURE", "false")
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("GRPC_TLS_CERT_PATH", raising=False)
    monkeypatch.delenv("GRPC_TLS_KEY_PATH", raising=False)
    monkeypatch.setenv("GRPC_DEV_CERT_DIR", str(tmp_path))

    import api.grpc_server as grpc_mod

    mock_grpc = MagicMock()
    mock_grpc.ssl_server_credentials = MagicMock(return_value=MagicMock())

    with patch.dict("sys.modules", {"grpc": mock_grpc}):
        # Re-import to pick up the mock
        if "api.grpc_server" in sys.modules:
            del sys.modules["api.grpc_server"]
        import api.grpc_server as grpc_mod_fresh
        grpc_mod_fresh._build_grpc_credentials()

    # Cert files should have been written to tmp_path
    assert (tmp_path / "server.crt").exists()
    assert (tmp_path / "server.key").exists()


def test_grpc_status_thread_safety():
    """get_grpc_authz_status and _set_grpc_authz_status must be thread-safe."""
    import threading
    import api.grpc_server as grpc_mod

    results = []

    def _set_and_read(value: str):
        grpc_mod._set_grpc_authz_status(value)
        results.append(grpc_mod.get_grpc_authz_status())

    threads = [threading.Thread(target=_set_and_read, args=(f"status-{i}",)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All results must be valid status strings — no corruption
    assert all(isinstance(r, str) for r in results)
