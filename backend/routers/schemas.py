from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from agentshield.events.models import BaseEvent, ThreatEvent


class EventResponse(BaseModel):
    """Single event in API response format."""

    id: str
    session_id: str
    agent_id: str
    timestamp: str
    event_type: str
    severity: str
    metadata: dict[str, Any]


class ThreatResponse(BaseModel):
    """Threat event in API response format."""

    id: str
    session_id: str
    agent_id: str
    timestamp: str
    event_type: str
    severity: str
    threat_type: str
    confidence: float
    explanation: str
    recommended_action: str
    mitigated: bool
    evidence: dict[str, Any]


class SessionSummary(BaseModel):
    """Aggregated summary of a single agent session."""

    session_id: str
    agent_id: str
    event_count: int
    threat_count: int
    blocked_count: int
    first_seen: str
    last_seen: str


class StoreStatsResponse(BaseModel):
    """Current EventStore statistics."""

    total_events: int
    total_threats: int
    total_sessions: int
    store_capacity: int


def event_to_response(event: BaseEvent) -> EventResponse:
    """Convert any BaseEvent to EventResponse.

    Args:
        event: Source event model.

    Returns:
        Serialized API response model.
    """

    return EventResponse(
        id=str(event.id),
        session_id=str(event.session_id),
        agent_id=event.agent_id,
        timestamp=event.timestamp.isoformat(),
        event_type=event.event_type.value,
        severity=event.severity.value,
        metadata=event.metadata,
    )


def threat_to_response(event: ThreatEvent) -> ThreatResponse:
    """Convert a ThreatEvent to ThreatResponse.

    Args:
        event: Source threat event model.

    Returns:
        Serialized threat API response model.
    """

    return ThreatResponse(
        id=str(event.id),
        session_id=str(event.session_id),
        agent_id=event.agent_id,
        timestamp=event.timestamp.isoformat(),
        event_type=event.event_type.value,
        severity=event.severity.value,
        threat_type=event.threat_type.value,
        confidence=event.confidence,
        explanation=event.explanation,
        recommended_action=event.recommended_action.value,
        mitigated=event.mitigated,
        evidence=event.evidence,
    )
