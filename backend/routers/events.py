from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from loguru import logger

from agentshield.events.models import BaseEvent
from backend.config import BackendConfig
from backend.dependencies import get_config, get_event_store
from backend.event_store import EventStore
from backend.routers.schemas import (
    EventResponse,
    StoreStatsResponse,
    ThreatResponse,
    event_to_response,
    threat_to_response,
)

router = APIRouter(prefix="/api/events", tags=["events"])

DEFAULT_LIST_LIMIT: int = 100
MAX_LIST_LIMIT: int = 1000
DEFAULT_RECENT_LIMIT: int = 50
MAX_RECENT_LIMIT: int = 500


def _cap_limit(limit: int, cap: int) -> int:
    """Clamp a positive query limit to server-side bounds.

    Args:
        limit: User-provided limit value.
        cap: Maximum allowed value.

    Returns:
        Sanitized integer in [0, cap].
    """

    return max(0, min(limit, cap))


@router.get("", response_model=list[EventResponse])
async def list_events(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
    limit: Annotated[int, Query(ge=0)] = DEFAULT_LIST_LIMIT,
    session_id: str | None = None,
) -> list[EventResponse]:
    """Return all events in the store.

    Args:
        limit: Maximum number of events to return.
        session_id: Optional session filter.
        store: Event storage dependency.
        config: Backend configuration dependency.

    Returns:
        Serialized events list.
    """

    del config
    safe_limit: int = _cap_limit(limit, MAX_LIST_LIMIT)
    events: list[BaseEvent]
    if session_id is None:
        events = await store.get_all()
    else:
        events = await store.get_by_session(session_id)
    trimmed: list[BaseEvent] = events[:safe_limit]
    responses: list[EventResponse] = [event_to_response(event) for event in trimmed]
    logger.debug(
        "GET /api/events | session_id={} requested_limit={} returned={}",
        session_id,
        limit,
        len(responses),
    )
    return responses


@router.get("/threats", response_model=list[ThreatResponse])
async def list_threat_events(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
    limit: Annotated[int, Query(ge=0)] = DEFAULT_LIST_LIMIT,
) -> list[ThreatResponse]:
    """Return all ThreatEvents in the store.

    Args:
        limit: Maximum number of threat events to return.
        store: Event storage dependency.
        config: Backend configuration dependency.

    Returns:
        Serialized threat events list.
    """

    del config
    safe_limit: int = _cap_limit(limit, MAX_LIST_LIMIT)
    threats = await store.get_threats()
    trimmed = threats[:safe_limit]
    responses: list[ThreatResponse] = [threat_to_response(event) for event in trimmed]
    logger.debug(
        "GET /api/events/threats | requested_limit={} returned={}",
        limit,
        len(responses),
    )
    return responses


@router.get("/recent", response_model=list[EventResponse])
async def list_recent_events(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
    n: Annotated[int, Query(ge=0)] = DEFAULT_RECENT_LIMIT,
) -> list[EventResponse]:
    """Return the n most recent events.

    Args:
        n: Count of newest events to return.
        store: Event storage dependency.
        config: Backend configuration dependency.

    Returns:
        Serialized recent events list.
    """

    del config
    safe_n: int = _cap_limit(n, MAX_RECENT_LIMIT)
    events = await store.get_recent(safe_n)
    responses: list[EventResponse] = [event_to_response(event) for event in events]
    logger.debug(
        "GET /api/events/recent | requested_n={} returned={}",
        n,
        len(responses),
    )
    return responses


@router.get("/stats", response_model=StoreStatsResponse)
async def get_event_store_stats(
    store: Annotated[EventStore, Depends(get_event_store)],
    config: Annotated[BackendConfig, Depends(get_config)],
) -> StoreStatsResponse:
    """Return current EventStore statistics.

    Args:
        store: Event storage dependency.
        config: Backend configuration dependency.

    Returns:
        Aggregated store statistics.
    """

    events: list[BaseEvent] = await store.get_all()
    total_events: int = len(events)
    total_threats: int = len(
        [event for event in events if event.event_type.value == "THREAT_DETECTED"]
    )
    total_sessions: int = len({str(event.session_id) for event in events})

    response = StoreStatsResponse(
        total_events=total_events,
        total_threats=total_threats,
        total_sessions=total_sessions,
        store_capacity=config.event_store_max_size,
    )
    logger.debug(
        "GET /api/events/stats | total_events={} total_threats={} total_sessions={}",
        total_events,
        total_threats,
        total_sessions,
    )
    return response


@router.delete("", response_model=dict[str, bool])
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
    payload: dict[str, bool] = {"cleared": True}
    logger.debug("DELETE /api/events | cleared={}", payload["cleared"])
    return payload
