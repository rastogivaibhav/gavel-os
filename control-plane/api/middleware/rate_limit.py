"""
rate_limit.py — Per-host-id rate limiting for enforcer-facing endpoints.

Uses slowapi backed by Redis when REDIS_URL is set, falling back to an
in-process memory store for development.

Limits (all configurable via env vars):
  RATE_LIMIT_VALIDATE   — /external/runtime/validate   default: 200/minute
  RATE_LIMIT_HEARTBEAT  — /external/heartbeat           default: 4/minute
  RATE_LIMIT_TELEMETRY  — /internal/telemetry/push      default: 300/minute
  RATE_LIMIT_POLICY     — /external/runtime/policy      default: 30/minute

Key function: X-Gavel-Host-Id header, falling back to remote IP.
This ensures limits are per-enforcer-host, not per-IP (which would
incorrectly aggregate all enforcers behind a NAT).
"""

from __future__ import annotations

import logging
import os
from typing import Callable

from fastapi import Request

logger = logging.getLogger("gavel.rate_limit")

# ── Key function: identify callers by host-id, fall back to IP ───────────────

def _enforcer_key(request: Request) -> str:
    host_id = request.headers.get("x-gavel-host-id", "").strip()
    if host_id:
        return f"enforcer:{host_id}"
    # Fallback: use remote IP (handles direct API callers)
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return f"ip:{forwarded_for.split(',')[0].strip()}"
    client = request.client
    return f"ip:{client.host}" if client else "ip:unknown"


# ── Limit strings from env ────────────────────────────────────────────────────

LIMIT_VALIDATE  = os.getenv("RATE_LIMIT_VALIDATE",  "200/minute")
LIMIT_HEARTBEAT = os.getenv("RATE_LIMIT_HEARTBEAT", "4/minute")
LIMIT_TELEMETRY = os.getenv("RATE_LIMIT_TELEMETRY", "300/minute")
LIMIT_POLICY    = os.getenv("RATE_LIMIT_POLICY",    "30/minute")


# ── Limiter factory ───────────────────────────────────────────────────────────

def build_limiter():
    """
    Build a slowapi Limiter.

    Uses Redis storage when REDIS_URL is configured so limits are shared
    across multiple control-plane replicas. Falls back to in-memory storage
    for single-instance / development deployments.
    """
    try:
        from slowapi import Limiter
    except ImportError:
        logger.warning("slowapi not installed — rate limiting disabled")
        return None

    redis_url = os.getenv("REDIS_URL", "").strip()
    if redis_url:
        try:
            # slowapi accepts a storage_uri directly; the limits library handles redis://
            limiter = Limiter(key_func=_enforcer_key, storage_uri=redis_url)
            logger.info("Rate limiter using Redis storage (%s)", redis_url.split("@")[-1])
            return limiter
        except Exception as exc:
            logger.warning("Redis rate limit storage unavailable (%s) — falling back to memory", exc)

    limiter = Limiter(key_func=_enforcer_key)
    logger.info("Rate limiter using in-memory storage (single-instance only)")
    return limiter


# Singleton — imported by route modules
limiter = build_limiter()
