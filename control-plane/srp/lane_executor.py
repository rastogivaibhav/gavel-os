"""
lane_executor.py — Phase 7: Deterministic Lane-Serialized Execution

Implements a per-session asyncio Lock queue model so that only one
tool call is active in a session's "Lane" at any given time.
Prevents state corruption from concurrent recipe executions.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Awaitable

logger = logging.getLogger("srp.lane_executor")


class LaneExecutor:
    """
    A per-session Lane executor that guarantees serialized execution.

    A "Lane" is identified by a session_id. Each Lane holds an asyncio.Lock.
    Only one coroutine can hold a Lane lock at a time — all others queue up.

    Usage:
        executor = LaneExecutor()
        result = await executor.run("session-123", my_coroutine_fn, arg1, arg2)
    """

    def __init__(self) -> None:
        self._lanes: dict[str, asyncio.Lock] = {}
        self._lane_lock = asyncio.Lock()  # Protects the _lanes registry itself

    async def _get_lane(self, session_id: str) -> asyncio.Lock:
        """Get or create a Lane (Lock) for the given session_id."""
        async with self._lane_lock:
            if session_id not in self._lanes:
                self._lanes[session_id] = asyncio.Lock()
                logger.debug("LaneExecutor: created new Lane for session=%s", session_id)
            return self._lanes[session_id]

    async def run(
        self,
        session_id: str,
        fn: Callable[..., Awaitable[Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Run `fn(*args, **kwargs)` inside the session's exclusive Lane.

        Args:
            session_id: Uniquely identifies the execution Lane.
            fn: The async callable to execute.
            *args / **kwargs: Forwarded to `fn`.

        Returns:
            The return value of `fn`.

        Raises:
            Re-raises any exception from `fn` after releasing the Lane lock.
        """
        lane = await self._get_lane(session_id)
        logger.info("LaneExecutor: acquiring Lane for session=%s", session_id)

        async with lane:
            logger.info("LaneExecutor: Lane acquired for session=%s", session_id)
            try:
                return await fn(*args, **kwargs)
            except Exception as exc:
                logger.error(
                    "LaneExecutor: execution failed in Lane session=%s: %s",
                    session_id,
                    exc,
                )
                raise
            finally:
                logger.info("LaneExecutor: releasing Lane for session=%s", session_id)

    async def release_lane(self, session_id: str) -> None:
        """
        Explicitly remove a Lane from the registry once a session ends.
        Prevents unbounded memory growth on long-running deployments.
        """
        async with self._lane_lock:
            if session_id in self._lanes:
                del self._lanes[session_id]
                logger.debug("LaneExecutor: evicted Lane for session=%s", session_id)

    def active_lanes(self) -> list[str]:
        """Return list of active session IDs with registered lanes."""
        return list(self._lanes.keys())
