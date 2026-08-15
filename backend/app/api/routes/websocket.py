"""Real-time WebSocket endpoint."""
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.security import decode_token
from app.core.websocket_manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Authenticated real-time feed.

    Auth: pass ?token=<access_jwt> in the query string, or send a first
    message {"type": "auth", "token": "..."}.
    """
    token = websocket.query_params.get("token")
    if token:
        payload = decode_token(token)
        if payload is None:
            await websocket.close(code=4401, reason="Invalid token")
            return
        await ws_manager.connect(websocket)
        await _serve(websocket)
        return

    # Fallback: wait briefly for an auth message
    await websocket.accept()
    try:
        first = await websocket.receive_json()
        if first.get("type") != "auth" or decode_token(first.get("token", "")) is None:
            await websocket.close(code=4401, reason="Authentication required")
            return
    except Exception:
        await websocket.close(code=4401, reason="Authentication required")
        return
    await _serve(websocket)


async def _serve(websocket: WebSocket) -> None:
    try:
        while True:
            msg = await websocket.receive_json()
            # Currently a broadcast-only feed; client messages are acknowledged.
            if msg.get("type") == "ping":
                await websocket.send_json({"event": "pong", "data": {}})
    except WebSocketDisconnect:
        pass
    except Exception as exc:  # pragma: no cover
        logger.debug("websocket error: %s", exc)
    finally:
        await ws_manager.disconnect(websocket)
