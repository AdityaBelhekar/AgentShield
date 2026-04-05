from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from loguru import logger

from agentshield.events.models import BaseEvent
from backend.config import BackendConfig
from backend.dependencies import get_config, get_event_store
from backend.event_store import EventStore
from backend.routers.schemas import (
    EventResponse,
    StoreStatsResponse,
    event_to_response,
)

router = APIRouter(tags=["events"])

DEFAULT_LIST_LIMIT: int = 100
MAX_LIST_LIMIT: int = 1000
DEFAULT_RECENT_LIMIT: int = 50
MAX_RECENT_LIMIT: int = 500
HISTORY_BURST_SIZE: int = 50


def _cap_limit(limit: int, cap: int) -> int:
    """Clamp a positive query limit to server-side bounds.

    Args:
        limit: User-provided limit value.
        cap: Maximum allowed value.

    Returns:
        Sanitized integer in [0, cap].
    """
    return max(0, min(limit, cap))


async def _safe_send_json(websocket: WebSocket, payload: dict[str, object]) -> bool:
    """Send JSON payload and convert transport failures to bool.

    Args:
        websocket: Active websocket.
        payload: JSON payload.

    Returns:
        True when send succeeds, otherwise False.
    """
    try:
        await websocket.send_json(payload)
    except (RuntimeError, OSError, ValueError, TypeError) as exc:
        logger.warning("WebSocket send failed | error={}", exc)
        return False
    return True


@router.get("/api/events", response_model=list[EventResponse])
async def list_events(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
    limit: Annotated[int, Query(ge=0)] = DEFAULT_LIST_LIMIT,
    session_id: str | None = None,
) -> list[EventResponse]:
    """Return all events in the store.

    Args:
        store: Event storage dependency.
        config: Backend configuration dependency.
        limit: Maximum number of events to return.
        session_id: Optional session filter.

    Returns:
        Serialized events list.
    """
    del config
    safe_limit = _cap_limit(limit, MAX_LIST_LIMIT)

    events: list[BaseEvent]
    if session_id is None:
        events = await store.get_all()
    else:
        events = await store.get_by_session(session_id)

    trimmed = events[:safe_limit]
    return [event_to_response(event) for event in trimmed]


@router.get("/api/events/recent", response_model=list[EventResponse])
async def list_recent_events(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
    n: Annotated[int, Query(ge=0)] = DEFAULT_RECENT_LIMIT,
) -> list[EventResponse]:
    """Return the n most recent events.

    Args:
        store: Event storage dependency.
        config: Backend configuration dependency.
        n: Count of newest events to return.

    Returns:
        Serialized recent events list.
    """
    del config
    safe_n = _cap_limit(n, MAX_RECENT_LIMIT)
    events = await store.get_recent(safe_n)
    return [event_to_response(event) for event in events]


@router.get("/api/events/stats", response_model=StoreStatsResponse)
async def get_event_store_stats(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
) -> StoreStatsResponse:
    """Return current EventStore statistics.

    Args:
        store: Event storage dependency.
        config: Backend configuration dependency.

    Returns:
        Event store metrics.
    """
    events = await store.get_all()
    total_events = len(events)
    total_threats = len([event for event in events if event.event_type.value == "THREAT_DETECTED"])
    total_sessions = len({str(event.session_id) for event in events})

    return StoreStatsResponse(
        total_events=total_events,
        total_threats=total_threats,
        total_sessions=total_sessions,
        store_capacity=config.event_store_max_size,
    )


@router.delete("/api/events", response_model=dict[str, bool])
async def clear_events(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
) -> dict[str, bool]:
    """Clear all events from the store.

    Args:
        store: Event storage dependency.
        config: Backend configuration dependency.

    Returns:
        Confirmation payload.
    """
    del config
    await store.clear()
    return {"cleared": True}


@router.websocket("/ws/events")
async def stream_events(
    websocket: WebSocket,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> None:
    """Stream all new AgentShield events to connected clients.

    Args:
        websocket: Websocket connection.
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
        history_payload: dict[str, object] = {
            "type": "history",
            "events": [event_to_response(event).model_dump() for event in history_events],
        }
        if not await _safe_send_json(websocket, history_payload):
            return

        last_sent_id = str(history_events[-1].id) if history_events else None
        while True:
            store._updated.clear()
            snapshot = await store.get_recent(1)
            if snapshot:
                response = event_to_response(snapshot[0])
                if response.id != last_sent_id:
                    payload: dict[str, object] = {
                        "type": "event",
                        "data": response.model_dump(),
                    }
                    if not await _safe_send_json(websocket, payload):
                        break
                    last_sent_id = response.id
            await store._updated.wait()
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected | endpoint=/ws/events")
    except (RuntimeError, OSError, ValueError, TypeError) as exc:
        logger.warning("WebSocket handler stopped | endpoint=/ws/events error={}", exc)
        error_payload: dict[str, object] = {
            "type": "error",
            "message": "WebSocket stream terminated",
        }
        await _safe_send_json(websocket, error_payload)
