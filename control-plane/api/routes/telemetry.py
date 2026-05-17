from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
from dataclasses import dataclass, field

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from api.control_plane import require_machine_auth
from api.middleware.rate_limit import LIMIT_TELEMETRY, limiter
from api.runtime_contract import RuntimeEventEnvelope

router = APIRouter()
logger = logging.getLogger("sentinel.telemetry")


# Decorator helper: no-op when limiter is unavailable
def _rate_limit(limit_string: str):
    if limiter is None:

        def _noop(fn):
            return fn

        return _noop
    return limiter.limit(limit_string)


@dataclass
class TelemetrySubscriber:
    websocket: WebSocket
    queue: queue.Queue[str] = field(default_factory=queue.Queue)


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[TelemetrySubscriber] = []

    async def connect(self, websocket: WebSocket) -> TelemetrySubscriber:
        await websocket.accept()
        subscriber = TelemetrySubscriber(websocket=websocket)
        self.active_connections.append(subscriber)
        logger.info("Telemetry subscriber connected. Total=%s", len(self.active_connections))
        return subscriber

    def disconnect(self, websocket: WebSocket):
        subscriber = next(
            (
                candidate
                for candidate in self.active_connections
                if candidate.websocket == websocket
            ),
            None,
        )
        if subscriber is not None:
            self.active_connections.remove(subscriber)
        logger.info("Telemetry subscriber disconnected. Total=%s", len(self.active_connections))

    async def broadcast(self, message: dict):
        encoded = json.dumps(message)
        dead_connections: list[WebSocket] = []
        for subscriber in self.active_connections:
            try:
                subscriber.queue.put_nowait(encoded)
            except Exception as exc:
                logger.error("Failed to broadcast telemetry: %s", exc)
                dead_connections.append(subscriber.websocket)

        for websocket in dead_connections:
            self.disconnect(websocket)


manager = ConnectionManager()


def _telemetry_websocket_authenticated(websocket: WebSocket) -> bool:
    # Dev mode: allow all WebSocket connections without credentials so the
    # dashboard UI works out of the box during local development.
    if (
        os.getenv("ENV") == "development"
        and os.getenv("ALLOW_INSECURE_DEV_AUTH", "false").lower() == "true"
    ):
        return True

    headers = {key.lower(): value for key, value in websocket.headers.items()}

    configured_machine_key = os.getenv("GAVEL_MACHINE_KEY", "").strip()
    machine_key = headers.get("x-gavel-machine-key", "").strip()
    if configured_machine_key and machine_key and machine_key == configured_machine_key:
        return True

    configured_api_key = os.getenv("API_SECRET_KEY", "").strip()
    api_key = headers.get("x-api-key", "").strip()
    if configured_api_key and api_key and api_key == configured_api_key:
        return True

    auth_header = headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            from auth.jwt_handler import verify_token

            verify_token(token)
            return True
        except Exception:
            return False

    return False


@router.websocket("/ws/telemetry")
async def telemetry_endpoint(websocket: WebSocket):
    logger.info("WebSocket telemetry connection from %s", websocket.client)
    if not _telemetry_websocket_authenticated(websocket):
        await websocket.close(code=4401)
        return
    subscriber = await manager.connect(websocket)
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.25)
            except TimeoutError:
                pass

            while True:
                try:
                    message = subscriber.queue.get_nowait()
                except queue.Empty:
                    break
                await websocket.send_text(message)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except asyncio.CancelledError:
        manager.disconnect(websocket)
        raise


@router.post("/internal/telemetry/push", tags=["Telemetry"])
@_rate_limit(LIMIT_TELEMETRY)
async def push_telemetry_event(request: Request, event: RuntimeEventEnvelope):
    require_machine_auth(request)
    logger.info(
        "Telemetry push received: event_type=%s target=%s verdict=%s",
        event.event_type.value,
        event.target,
        event.verdict.value,
    )
    payload = event.model_dump(mode="json")
    await manager.broadcast({"type": event.event_type.value, "payload": payload})
    return JSONResponse(
        {
            "ok": True,
            "subscribers": len(manager.active_connections),
            "event_type": event.event_type.value,
        }
    )
