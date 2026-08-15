"""WebSocket connection manager.

Connections are authenticated at the route level; this manager handles
fan-out of real-time updates to connected SOC clients.
"""
import asyncio
import json
import logging
from typing import Any, Dict, List, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info("websocket connected (total=%d)", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)
        logger.info("websocket disconnected (total=%d)", len(self._connections))

    async def broadcast(self, event: str, payload: Dict[str, Any]) -> None:
        """Send an event to all connected clients."""
        message = json.dumps({"event": event, "data": payload}, default=str)
        async with self._lock:
            targets = list(self._connections)
        dead: List[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    async def send_to(self, websocket: WebSocket, event: str, payload: Dict[str, Any]) -> None:
        await websocket.send_text(json.dumps({"event": event, "data": payload}, default=str))


ws_manager = WebSocketManager()
