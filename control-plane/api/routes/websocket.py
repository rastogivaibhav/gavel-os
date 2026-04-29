"""WebSocket endpoint for real-time event streaming."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json
from typing import Set

router = APIRouter(tags=["WebSocket"])

active_connections: Set[WebSocket] = set()

@router.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for streaming real-time events."""
    await websocket.accept()
    active_connections.add(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(json.dumps({"status": "received", "message": data}))
    except WebSocketDisconnect:
        active_connections.discard(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        active_connections.discard(websocket)


async def broadcast_event(event: dict):
    """Broadcast event to all connected WebSocket clients."""
    disconnected = set()
    for connection in active_connections:
        try:
            await connection.send_json(event)
        except Exception as e:
            print(f"Broadcast error: {e}")
            disconnected.add(connection)

    for conn in disconnected:
        active_connections.discard(conn)
