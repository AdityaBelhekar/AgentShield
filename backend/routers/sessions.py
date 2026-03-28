from __future__ import annotations

from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger

from agentshield.events.models import BaseEvent, ThreatEvent
from backend.dependencies import get_event_store
from backend.event_store import EventStore
from backend.routers.schemas import (
    EventResponse,
    SessionSummary,
    ThreatResponse,
    event_to_response,
    threat_to_response,
)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _build_summary(session_id: str, events: list[BaseEvent]) -> SessionSummary:
    """Build a SessionSummary from a list of session events.

    Args:
        session_id: Session identifier key.
        events: All events for one session.

    Returns:
        Aggregated session summary.
    """

    threat_events: list[ThreatEvent] = [
        event for event in events if isinstance(event, ThreatEvent)
    ]
    blocked_count: int = len([event for event in threat_events if event.mitigated])
    first_seen: str = min(event.timestamp for event in events).isoformat()
    last_seen: str = max(event.timestamp for event in events).isoformat()
    return SessionSummary(
        session_id=session_id,
        agent_id=events[0].agent_id,
        event_count=len(events),
        threat_count=len(threat_events),
        blocked_count=blocked_count,
        first_seen=first_seen,
        last_seen=last_seen,
    )


def _session_not_found(session_id: str) -> HTTPException:
    """Create standardized not-found error for session endpoints.

    Args:
        session_id: Missing session identifier.

    Returns:
        HTTP 404 exception with required detail message.
    """

    return HTTPException(status_code=404, detail=f"Session {session_id} not found")


@router.get("", response_model=list[SessionSummary])
async def list_sessions(
    store: Annotated[EventStore, Depends(get_event_store)],
) -> list[SessionSummary]:
    """Return a summary for every distinct session in the store.

    Args:
        store: Event storage dependency.

    Returns:
        List of aggregated summaries, one per session.
    """

    events = await store.get_all()
    grouped: dict[str, list[BaseEvent]] = defaultdict(list)
    for event in events:
        grouped[str(event.session_id)].append(event)

    summaries: list[SessionSummary] = [
        _build_summary(session_id, session_events)
        for session_id, session_events in grouped.items()
    ]
    logger.debug("GET /api/sessions | returned={}", len(summaries))
    return summaries


@router.get("/{session_id}", response_model=SessionSummary)
async def get_session_summary(
    session_id: str,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> SessionSummary:
    """Return the summary for a single session.

    Args:
        session_id: Session identifier.
        store: Event storage dependency.

    Returns:
        Aggregated summary for the requested session.

    Raises:
        HTTPException: If the session does not exist.
    """

    events = await store.get_by_session(session_id)
    if not events:
        raise _session_not_found(session_id)
    summary: SessionSummary = _build_summary(session_id, events)
    logger.debug("GET /api/sessions/{} | found=true", session_id)
    return summary


@router.get("/{session_id}/events", response_model=list[EventResponse])
async def get_session_events(
    session_id: str,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> list[EventResponse]:
    """Return all events for a single session.

    Args:
        session_id: Session identifier.
        store: Event storage dependency.

    Returns:
        Serialized event list for the session.

    Raises:
        HTTPException: If the session does not exist.
    """

    events = await store.get_by_session(session_id)
    if not events:
        raise _session_not_found(session_id)
    responses: list[EventResponse] = [event_to_response(event) for event in events]
    logger.debug(
        "GET /api/sessions/{}/events | returned={}", session_id, len(responses)
    )
    return responses


@router.get("/{session_id}/threats", response_model=list[ThreatResponse])
async def get_session_threats(
    session_id: str,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> list[ThreatResponse]:
    """Return all ThreatEvents for a single session.

    Args:
        session_id: Session identifier.
        store: Event storage dependency.

    Returns:
        Serialized threat list for the session.

    Raises:
        HTTPException: If the session does not exist.
    """

    events = await store.get_by_session(session_id)
    if not events:
        raise _session_not_found(session_id)
    threats: list[ThreatEvent] = [
        event for event in events if isinstance(event, ThreatEvent)
    ]
    responses: list[ThreatResponse] = [threat_to_response(event) for event in threats]
    logger.debug(
        "GET /api/sessions/{}/threats | returned={}", session_id, len(responses)
    )
    return responses
