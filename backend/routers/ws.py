from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from loguru import logger

from agentshield.events.models import BaseEvent
from backend.dependencies import get_event_store
from backend.event_store import EventStore
from backend.routers.schemas import EventResponse, event_to_response

router = APIRouter(tags=["websocket"])

HISTORY_BURST_SIZE: int = 50


async def _safe_send_json(websocket: WebSocket, payload: dict[str, object]) -> bool:
    """Send a JSON payload and convert transport failures to a boolean.

    Args:
        websocket: Active websocket connection.
        payload: JSON-serializable dictionary payload.

    Returns:
        True if send succeeded, otherwise False.
    """

    try:
        await websocket.send_json(payload)
    except (RuntimeError, OSError, ValueError, TypeError) as exc:
        logger.warning("WebSocket send failed | error={}", exc)
        return False
    return True


@router.websocket("/ws/events")
async def stream_events(
    websocket: WebSocket,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> None:
    """Stream all new AgentShield events to connected clients.

    On connect, sends a confirmation message followed by a 50-event
    history burst. Then it waits for store updates and pushes each
    newly observed event as a live message.

    Args:
        websocket: FastAPI websocket connection.
        store: Event storage dependency.
    """

    try:
        await websocket.accept()
        connected_payload: dict[str, object] = {
            "type": "connected",
            "message": "AgentShield live feed",
        }
        if not await _safe_send_json(websocket, connected_payload):
            return

        history_events: list[BaseEvent] = await store.get_recent(HISTORY_BURST_SIZE)
        history_responses: list[EventResponse] = [
            event_to_response(event) for event in history_events
        ]
        history_payload: dict[str, object] = {
            "type": "history",
            "events": [response.model_dump() for response in history_responses],
        }
        if not await _safe_send_json(websocket, history_payload):
            return

        last_sent_id: str | None = (
            history_responses[-1].id if history_responses else None
        )
        while True:
            store._updated.clear()
            snapshot: list[BaseEvent] = await store.get_recent(1)
            if snapshot:
                response: EventResponse = event_to_response(snapshot[0])
                if response.id != last_sent_id:
                    event_payload: dict[str, object] = {
                        "type": "event",
                        "data": response.model_dump(),
                    }
                    if not await _safe_send_json(websocket, event_payload):
                        break
                    last_sent_id = response.id
            await store._updated.wait()
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected | endpoint=/ws/events")
        return
    except (RuntimeError, OSError, ValueError, TypeError) as exc:
        logger.warning("WebSocket handler stopped | endpoint=/ws/events error={}", exc)
        error_payload: dict[str, object] = {
            "type": "error",
            "message": "WebSocket stream terminated",
        }
        await _safe_send_json(websocket, error_payload)
        return
