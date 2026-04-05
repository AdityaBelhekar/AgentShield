from __future__ import annotations

from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

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

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _build_summary(session_id: str, events: list[BaseEvent]) -> SessionSummary:
    """Build session summary from raw events.

    Args:
        session_id: Session identifier.
        events: Session event list.

    Returns:
        Aggregated summary model.
    """
    threat_events: list[ThreatEvent] = [event for event in events if isinstance(event, ThreatEvent)]
    blocked_count = len([event for event in threat_events if event.mitigated])
    first_seen = min(event.timestamp for event in events).isoformat()
    last_seen = max(event.timestamp for event in events).isoformat()

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
    """Build 404 error for missing session.

    Args:
        session_id: Missing session id.

    Returns:
        FastAPI HTTPException.
    """
    return HTTPException(status_code=404, detail=f"Session {session_id} not found")


@router.get("/sessions", response_model=list[SessionSummary])
async def list_sessions(
    store: Annotated[EventStore, Depends(get_event_store)],
) -> list[SessionSummary]:
    """Return summaries for all sessions.

    Args:
        store: Event store dependency.

    Returns:
        Session summaries.
    """
    events = await store.get_all()
    grouped: dict[str, list[BaseEvent]] = defaultdict(list)
    for event in events:
        grouped[str(event.session_id)].append(event)

    return [
        _build_summary(session_id, session_events) for session_id, session_events in grouped.items()
    ]


@router.get("/sessions/{session_id}", response_model=SessionSummary)
async def get_session_summary(
    session_id: str,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> SessionSummary:
    """Return a summary for one session.

    Args:
        session_id: Session id.
        store: Event store dependency.

    Returns:
        Session summary.

    Raises:
        HTTPException: If session does not exist.
    """
    events = await store.get_by_session(session_id)
    if not events:
        raise _session_not_found(session_id)
    return _build_summary(session_id, events)


@router.get("/sessions/{session_id}/events", response_model=list[EventResponse])
async def get_session_events(
    session_id: str,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> list[EventResponse]:
    """Return all events for one session.

    Args:
        session_id: Session id.
        store: Event store dependency.

    Returns:
        Serialized events.

    Raises:
        HTTPException: If session does not exist.
    """
    events = await store.get_by_session(session_id)
    if not events:
        raise _session_not_found(session_id)
    return [event_to_response(event) for event in events]


@router.get("/sessions/{session_id}/threats", response_model=list[ThreatResponse])
async def get_session_threats(
    session_id: str,
    store: Annotated[EventStore, Depends(get_event_store)],
) -> list[ThreatResponse]:
    """Return all threat events for one session.

    Args:
        session_id: Session id.
        store: Event store dependency.

    Returns:
        Serialized threats.

    Raises:
        HTTPException: If session does not exist.
    """
    events = await store.get_by_session(session_id)
    if not events:
        raise _session_not_found(session_id)

    threats: list[ThreatEvent] = [event for event in events if isinstance(event, ThreatEvent)]
    return [threat_to_response(event) for event in threats]
