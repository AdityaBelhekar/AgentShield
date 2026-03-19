from __future__ import annotations

# ruff: noqa: UP017, UP042, UP045
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import UUID4, BaseModel, ConfigDict, Field, field_validator


class EventType(str, Enum):
    """Categorizes every event emitted during agent execution.

    Used as the discriminator field for deserializing raw
    event dictionaries into the correct Pydantic model subclass.
    """

    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    TOOL_CALL_START = "TOOL_CALL_START"
    TOOL_CALL_COMPLETE = "TOOL_CALL_COMPLETE"
    TOOL_CALL_BLOCKED = "TOOL_CALL_BLOCKED"
    LLM_PROMPT = "LLM_PROMPT"
    LLM_RESPONSE = "LLM_RESPONSE"
    CHAIN_START = "CHAIN_START"
    CHAIN_END = "CHAIN_END"
    MEMORY_READ = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    THREAT_DETECTED = "THREAT_DETECTED"
    THREAT_CLEARED = "THREAT_CLEARED"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class SeverityLevel(str, Enum):
    """Severity of a security event from informational to critical.

    Used to drive alerting thresholds and policy responses.
    Higher severity events trigger more aggressive responses.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Classifies the specific attack vector that was detected.

    Each value maps to a specific detector in the detection
    engine. Used for routing, reporting, and policy evaluation.
    """

    PROMPT_INJECTION = "PROMPT_INJECTION"
    GOAL_DRIFT = "GOAL_DRIFT"
    TOOL_POISONING = "TOOL_POISONING"
    TOOL_CHAIN_ESCALATION = "TOOL_CHAIN_ESCALATION"
    MEMORY_POISONING = "MEMORY_POISONING"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    INTER_AGENT_INJECTION = "INTER_AGENT_INJECTION"


class RecommendedAction(str, Enum):
    """Action AgentShield recommends or takes upon threat detection.

    The detection engine sets this. The policy compiler decides
    whether to enforce it based on the active policy config.
    """

    BLOCK = "BLOCK"
    FLAG = "FLAG"
    ALERT = "ALERT"
    LOG_ONLY = "LOG_ONLY"


class TrustLevel(str, Enum):
    """Trust level assigned to content by the provenance tracker.

    Every piece of text entering the LLM context is tagged
    with one of these levels. Used by the detection engine
    to apply extra scrutiny to untrusted content.

    TRUSTED   - came directly from the user
    INTERNAL  - came from agent memory or internal state
    EXTERNAL  - came from a tool call to a known source
    UNTRUSTED - came from an unknown or unverified source
    """

    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    UNTRUSTED = "UNTRUSTED"


class BaseEvent(BaseModel):
    """Base class for all AgentShield security events.

    All events share a common identity and context envelope.
    Subclasses add domain-specific fields for each category.

    The event_type field is the discriminator used by
    deserialize_event() to route to the correct subclass.

    Attributes:
        id: Auto-generated UUID4 uniquely identifying this event.
        session_id: UUID of the agent session this belongs to.
        agent_id: Human-readable identifier for the agent instance.
        timestamp: UTC timestamp of event creation. Auto-set.
        event_type: Discriminator field for deserialization routing.
        severity: Severity level. Defaults to INFO.
        metadata: Arbitrary key-value pairs for extensibility.
    """

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat(),
            uuid.UUID: lambda v: str(v),
        },
        populate_by_name=True,
    )

    id: UUID4 = Field(default_factory=uuid.uuid4, description="Unique event identifier")
    session_id: UUID4 = Field(..., description="Session this event belongs to")
    agent_id: str = Field(..., description="Human-readable agent identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of event creation",
    )
    event_type: EventType = Field(..., description="Event category discriminator")
    severity: SeverityLevel = Field(
        default=SeverityLevel.INFO, description="Event severity level"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary extensibility metadata",
    )


class ToolCallEvent(BaseEvent):
    """Records a single tool invocation during agent execution.

    Emitted up to three times per tool call:
      TOOL_CALL_START    - before execution (tool_output=None)
      TOOL_CALL_COMPLETE - after execution (tool_output set)
      TOOL_CALL_BLOCKED  - if a policy rule blocked the call

    The tool_input field stores the raw arguments dict.
    The tool_output field stores the string return value.
    execution_time_ms is only set on TOOL_CALL_COMPLETE events.

    Attributes:
        tool_name: Name of the LangChain tool being invoked.
        tool_input: Arguments dict passed to the tool.
        tool_output: Return value. None before execution.
        execution_time_ms: Wall-clock execution time in ms.
        blocked: True if this call was blocked by policy.
        block_reason: Human-readable reason for block.
        trust_level: Trust level of the tool's output source.
    """

    tool_name: str = Field(..., description="Name of the tool being invoked")
    tool_input: dict[str, Any] = Field(
        default_factory=dict, description="Arguments passed to the tool"
    )
    tool_output: Optional[str] = Field(
        default=None, description="Tool return value. None before execution."
    )
    execution_time_ms: Optional[float] = Field(
        default=None,
        description="Execution duration in milliseconds",
        ge=0.0,
    )
    blocked: bool = Field(
        default=False, description="Whether this call was blocked by policy"
    )
    block_reason: Optional[str] = Field(
        default=None, description="Reason for blocking if blocked=True"
    )
    trust_level: TrustLevel = Field(
        default=TrustLevel.EXTERNAL,
        description="Trust level of the tool output source",
    )


class LLMEvent(BaseEvent):
    """Records an LLM prompt or response during agent execution.

    Emitted twice per LLM call:
      LLM_PROMPT   - when prompt is sent (response=None)
      LLM_RESPONSE - when response arrives (response set)

    The prompt field is analyzed by PromptInjectionDetector
    and GoalDriftDetector on every LLM_PROMPT event.

    Attributes:
        prompt: Full prompt text sent to the LLM.
        response: LLM response text. None on PROMPT events.
        model: Model identifier string (e.g. "gpt-4o").
        token_count: Total tokens used (prompt + completion).
        prompt_tokens: Tokens in the prompt only.
        completion_tokens: Tokens in the completion only.
        prompt_trust_levels: Trust tags per content segment.
            Maps segment identifier to TrustLevel. Used by
            the provenance tracker to label prompt sections.
    """

    prompt: str = Field(..., description="Full prompt text sent to the LLM")
    response: Optional[str] = Field(
        default=None, description="LLM response. None on PROMPT events."
    )
    model: str = Field(..., description="Model identifier string")
    token_count: Optional[int] = Field(
        default=None, description="Total tokens consumed", ge=0
    )
    prompt_tokens: Optional[int] = Field(
        default=None, description="Prompt token count", ge=0
    )
    completion_tokens: Optional[int] = Field(
        default=None, description="Completion token count", ge=0
    )
    prompt_trust_levels: dict[str, str] = Field(
        default_factory=dict,
        description="Trust level tags per prompt segment",
    )


class MemoryEvent(BaseEvent):
    """Records a read or write operation on agent memory.

    Memory write events are analyzed by MemoryPoisonDetector
    to identify anomalous content being injected into memory.

    content_preview is intentionally capped at 200 characters
    to avoid storing sensitive full content in event logs
    while still providing enough context for detection.

    Attributes:
        operation: Either 'read' or 'write'.
        memory_key: The key used to access memory.
        content_preview: First 200 chars of memory content.
        content_length: Full content length in characters.
    """

    operation: str = Field(..., description="Memory operation: 'read' or 'write'")
    memory_key: str = Field(..., description="Memory key being accessed")
    content_preview: str = Field(..., description="First 200 characters of content")
    content_length: int = Field(
        default=0,
        description="Full content length in characters",
        ge=0,
    )

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, v: str) -> str:
        """Validate that operation is either 'read' or 'write'.

        Args:
            v: Operation string to validate.

        Returns:
            Validated operation string.

        Raises:
            ValueError: If operation is not 'read' or 'write'.
        """

        if v not in ("read", "write"):
            raise ValueError(f"operation must be 'read' or 'write', got {v!r}")
        return v

    @field_validator("content_preview")
    @classmethod
    def truncate_to_200(cls, v: str) -> str:
        """Enforce the 200-character preview limit.

        Args:
            v: Content string to truncate.

        Returns:
            String truncated to 200 characters.
        """

        return v[:200]


class ThreatEvent(BaseEvent):
    """Records a detected security threat during agent execution.

    Emitted by the DetectionEngine when any detector fires
    above its configured threshold.

    The confidence score drives severity and action:
      >= 0.80 -> CRITICAL, BLOCK
      >= 0.50 -> HIGH, ALERT
      >= 0.25 -> MEDIUM, FLAG
      <  0.25 -> not emitted (below threshold)

    The evidence dict stores raw detector output for forensic
    analysis and is included in the cryptographic audit chain.

    Attributes:
        threat_type: Which attack vector was detected.
        confidence: Detection confidence from 0.0 to 1.0.
        affected_event_id: UUID of the triggering event.
        explanation: Human-readable description of threat.
        recommended_action: What AgentShield should do.
        evidence: Raw supporting data for the detection.
        mitigated: True if AgentShield blocked the threat.
        detector_name: Name of the detector that fired.
        canary_triggered: True if a canary token was echoed.
    """

    threat_type: ThreatType = Field(..., description="Attack vector classification")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Detection confidence score 0.0 to 1.0",
    )
    affected_event_id: Optional[UUID4] = Field(
        default=None,
        description="UUID of the event that triggered detection",
    )
    explanation: str = Field(
        ..., description="Human-readable description of the threat"
    )
    recommended_action: RecommendedAction = Field(
        ...,
        description="Action AgentShield recommends or takes",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Raw detection evidence for forensics"
    )
    mitigated: bool = Field(
        default=False, description="Whether the threat was successfully blocked"
    )
    detector_name: str = Field(
        default="", description="Name of the detector that fired"
    )
    canary_triggered: bool = Field(
        default=False,
        description="Whether a canary token triggered this event",
    )


class SessionEvent(BaseEvent):
    """Records the start or end of an agent session.

    SESSION_START is emitted by AgentShieldRuntime.wrap()
    at context entry. Captures original task and policy state.

    SESSION_END is emitted at context exit. Captures final
    session metrics: total events, threats, tool calls blocked.

    Attributes:
        original_task: The user's original task string.
        policy_snapshot: Serialized policy config for session.
        framework: Agent framework in use.
        total_events: Total events emitted (SESSION_END only).
        threats_detected: Threat count (SESSION_END only).
        threats_blocked: Blocked threat count (SESSION_END only).
        tool_calls_total: Total tool calls (SESSION_END only).
        tool_calls_blocked: Blocked tool calls (SESSION_END only).
    """

    original_task: str = Field(..., description="Original task the agent was given")
    policy_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Policy config snapshot for this session",
    )
    framework: str = Field(
        default="langchain", description="Agent framework: langchain/autogen/crewai"
    )
    total_events: int = Field(
        default=0, description="Total events emitted. Set on SESSION_END.", ge=0
    )
    threats_detected: int = Field(
        default=0, description="Threats detected. Set on SESSION_END.", ge=0
    )
    threats_blocked: int = Field(
        default=0, description="Threats blocked. Set on SESSION_END.", ge=0
    )
    tool_calls_total: int = Field(
        default=0, description="Total tool calls. Set on SESSION_END.", ge=0
    )
    tool_calls_blocked: int = Field(
        default=0, description="Blocked tool calls. Set on SESSION_END.", ge=0
    )


class CanaryEvent(BaseEvent):
    """Records a canary token injection or detection event.

    Emitted by the CanarySystem (Phase 4B) in two scenarios:
      CANARY_INJECTED - when a canary token is planted
      CANARY_TRIGGERED - when the LLM echoes a canary token

    A triggered canary means active manipulation is occurring
    with near-zero false positive rate.

    Attributes:
        canary_id: Unique identifier for this canary token.
        canary_hash: Cryptographic hash of the canary value.
            The actual canary string is NEVER stored in events
            to prevent attackers from learning canary patterns.
        triggered: True if this is a trigger event.
        trigger_context: Snippet showing where canary appeared.
    """

    canary_id: str = Field(..., description="Unique canary token identifier")
    canary_hash: str = Field(
        ..., description="Hash of canary value. Never the value itself."
    )
    triggered: bool = Field(
        default=False, description="True if canary was echoed by LLM"
    )
    trigger_context: Optional[str] = Field(
        default=None,
        description="Context snippet where canary appeared",
    )


class ProvenanceEvent(BaseEvent):
    """Records a provenance tag assigned to prompt content.

    Emitted by the ProvenanceTracker (Phase 4A) whenever
    content from a new source enters the agent's context.

    Attributes:
        content_hash: Hash of the content being tagged.
            Never the content itself.
        trust_level: Trust level assigned to this content.
        source_tool: Tool that produced the content, if any.
        source_url: URL of content origin, if applicable.
        content_length: Length of the tagged content.
    """

    content_hash: str = Field(
        ..., description="Hash of tagged content. Never raw content."
    )
    trust_level: TrustLevel = Field(
        ..., description="Trust level assigned to this content"
    )
    source_tool: Optional[str] = Field(
        default=None, description="Tool that produced this content"
    )
    source_url: Optional[str] = Field(
        default=None, description="URL origin of content if applicable"
    )
    content_length: int = Field(
        default=0, description="Length of the tagged content in chars", ge=0
    )


class AuditLog(BaseModel):
    """Complete audit record for a single agent session.

    Aggregates all events and metrics for one session.
    Exported as JSON by the ForensicTracePanel in the frontend.
    Used as input for the cryptographic audit chain (Phase 8).

    Attributes:
        session_id: UUID of the session.
        agent_id: Agent identifier string.
        framework: Agent framework used.
        session_start: UTC timestamp of session start.
        session_end: UTC timestamp of session end.
        original_task: The user's original task.
        total_events: Count of all events.
        threats_detected: Count of ThreatEvents emitted.
        threats_blocked: Count of mitigated threats.
        clean_tool_calls: Count of unblocked tool calls.
        blocked_tool_calls: Count of blocked tool calls.
        canaries_triggered: Count of canary triggers.
        events: Ordered list of all events in the session.
        policy_snapshot: Policy config active during session.
        chain_hash: Hash of the cryptographic audit chain.
            Empty string until Phase 8 is implemented.
    """

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat(),
            uuid.UUID: lambda v: str(v),
        }
    )

    session_id: UUID4
    agent_id: str
    framework: str = "langchain"
    session_start: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_end: Optional[datetime] = None
    original_task: str = ""
    total_events: int = 0
    threats_detected: int = 0
    threats_blocked: int = 0
    clean_tool_calls: int = 0
    blocked_tool_calls: int = 0
    canaries_triggered: int = 0
    events: list[BaseEvent] = Field(default_factory=list)
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    chain_hash: str = Field(
        default="", description="Cryptographic audit chain hash. Phase 8."
    )


EVENT_TYPE_MAP: dict[str, type[BaseEvent]] = {
    EventType.SESSION_START: SessionEvent,
    EventType.SESSION_END: SessionEvent,
    EventType.TOOL_CALL_START: ToolCallEvent,
    EventType.TOOL_CALL_COMPLETE: ToolCallEvent,
    EventType.TOOL_CALL_BLOCKED: ToolCallEvent,
    EventType.LLM_PROMPT: LLMEvent,
    EventType.LLM_RESPONSE: LLMEvent,
    EventType.CHAIN_START: BaseEvent,
    EventType.CHAIN_END: BaseEvent,
    EventType.MEMORY_READ: MemoryEvent,
    EventType.MEMORY_WRITE: MemoryEvent,
    EventType.THREAT_DETECTED: ThreatEvent,
    EventType.THREAT_CLEARED: ThreatEvent,
    EventType.POLICY_VIOLATION: ThreatEvent,
}


def deserialize_event(data: dict[str, Any]) -> BaseEvent:
    """Deserialize a raw dictionary into the correct BaseEvent subclass.

    Routes deserialization based on the event_type field.
    Used by the backend to reconstruct typed events from
    Redis pub/sub messages.

    Args:
        data: Raw dictionary from JSON deserialization.

    Returns:
        Correctly typed BaseEvent subclass instance.

    Raises:
        ValueError: If event_type is missing or unrecognized.

    Example:
        >>> raw = {
        ...     "event_type": "TOOL_CALL_START",
        ...     "session_id": "...",
        ...     "agent_id": "my-agent",
        ...     "tool_name": "search",
        ...     "tool_input": {},
        ... }
        >>> event = deserialize_event(raw)
        >>> isinstance(event, ToolCallEvent)
        True
    """

    raw_type = data.get("event_type")
    if not raw_type:
        raise ValueError("event_type field is required for deserialization")

    try:
        event_type = EventType(raw_type)
    except ValueError as exc:
        raise ValueError(
            f"Unknown event_type: {raw_type!r}. "
            f"Valid types: {[e.value for e in EventType]}"
        ) from exc

    model_class = EVENT_TYPE_MAP.get(event_type, BaseEvent)
    return model_class.model_validate(data)
