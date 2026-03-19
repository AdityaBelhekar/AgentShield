"""AgentShield event system - models, emitter, and utilities.

Public API:
    Emitter   : EventEmitter
    Models    : BaseEvent, ToolCallEvent, LLMEvent, MemoryEvent,
                            ThreatEvent, SessionEvent, CanaryEvent,
                            ProvenanceEvent, AuditLog
    Enums     : EventType, SeverityLevel, ThreatType,
                            RecommendedAction, TrustLevel
    Utilities : deserialize_event, EVENT_TYPE_MAP
"""

from agentshield.events.emitter import EventEmitter
from agentshield.events.models import (
    EVENT_TYPE_MAP,
    AuditLog,
    BaseEvent,
    CanaryEvent,
    EventType,
    LLMEvent,
    MemoryEvent,
    ProvenanceEvent,
    RecommendedAction,
    SessionEvent,
    SeverityLevel,
    ThreatEvent,
    ThreatType,
    ToolCallEvent,
    TrustLevel,
    deserialize_event,
)

__all__ = [
    # Emitter
    "EventEmitter",
    # Models
    "AuditLog",
    "BaseEvent",
    "CanaryEvent",
    "LLMEvent",
    "MemoryEvent",
    "ProvenanceEvent",
    "SessionEvent",
    "ThreatEvent",
    "ToolCallEvent",
    # Enums
    "EventType",
    "RecommendedAction",
    "SeverityLevel",
    "ThreatType",
    "TrustLevel",
    # Utilities
    "EVENT_TYPE_MAP",
    "deserialize_event",
]
