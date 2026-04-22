"""
Tests for api.middleware.rate_limit — key function and limiter construction.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ── _enforcer_key ─────────────────────────────────────────────────────────────

def test_enforcer_key_uses_host_id_header():
    from api.middleware.rate_limit import _enforcer_key

    request = MagicMock()
    request.headers.get = lambda k, d="": "my-host-id" if k == "x-gavel-host-id" else d
    request.client = None

    key = _enforcer_key(request)
    assert key == "enforcer:my-host-id"


def test_enforcer_key_falls_back_to_forwarded_for():
    from api.middleware.rate_limit import _enforcer_key

    request = MagicMock()
    request.headers.get = lambda k, d="": (
        "" if k == "x-gavel-host-id"
        else "10.0.0.1, 10.0.0.2" if k == "x-forwarded-for"
        else d
    )
    request.client = None

    key = _enforcer_key(request)
    assert key == "ip:10.0.0.1"


def test_enforcer_key_falls_back_to_remote_ip():
    from api.middleware.rate_limit import _enforcer_key

    request = MagicMock()
    request.headers.get = lambda k, d="": d  # all headers empty
    request.client = MagicMock()
    request.client.host = "192.168.1.100"

    key = _enforcer_key(request)
    assert key == "ip:192.168.1.100"


def test_enforcer_key_unknown_when_no_client():
    from api.middleware.rate_limit import _enforcer_key

    request = MagicMock()
    request.headers.get = lambda k, d="": d
    request.client = None

    key = _enforcer_key(request)
    assert key == "ip:unknown"


def test_enforcer_key_prefers_host_id_over_forwarded_for():
    from api.middleware.rate_limit import _enforcer_key

    request = MagicMock()
    request.headers.get = lambda k, d="": (
        "my-enforcer" if k == "x-gavel-host-id"
        else "10.0.0.1" if k == "x-forwarded-for"
        else d
    )
    request.client = None

    key = _enforcer_key(request)
    assert key == "enforcer:my-enforcer"


# ── Limit strings from env ────────────────────────────────────────────────────

def test_limit_strings_have_defaults(monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_VALIDATE", raising=False)
    monkeypatch.delenv("RATE_LIMIT_HEARTBEAT", raising=False)
    monkeypatch.delenv("RATE_LIMIT_TELEMETRY", raising=False)
    monkeypatch.delenv("RATE_LIMIT_POLICY", raising=False)

    # Re-import to pick up env changes
    import importlib
    import api.middleware.rate_limit as rl
    importlib.reload(rl)

    assert rl.LIMIT_VALIDATE == "200/minute"
    assert rl.LIMIT_HEARTBEAT == "4/minute"
    assert rl.LIMIT_TELEMETRY == "300/minute"
    assert rl.LIMIT_POLICY == "30/minute"


def test_limit_strings_read_from_env(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_VALIDATE", "500/minute")
    monkeypatch.setenv("RATE_LIMIT_HEARTBEAT", "10/minute")

    import importlib
    import api.middleware.rate_limit as rl
    importlib.reload(rl)

    assert rl.LIMIT_VALIDATE == "500/minute"
    assert rl.LIMIT_HEARTBEAT == "10/minute"
