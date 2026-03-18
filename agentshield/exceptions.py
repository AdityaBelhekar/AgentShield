"""
AgentShield exception hierarchy.

All exceptions raised by AgentShield are subclasses of
AgentShieldError. This allows callers to catch all SDK
exceptions with a single except clause if needed.

Hierarchy:
    AgentShieldError
    ├── ConfigurationError
    ├── InterceptorError
    ├── DetectionError
    ├── EventEmissionError
    ├── RedisConnectionError
    ├── ProvenanceError
    ├── CanaryError
    ├── DNAError
    ├── AuditChainError
    └── PolicyViolationError
        ├── ToolCallBlockedError
        │   └── PrivilegeEscalationError
        ├── GoalDriftError
        ├── PromptInjectionError
        ├── MemoryPoisonError
        ├── BehavioralAnomalyError
        └── InterAgentInjectionError
"""

from __future__ import annotations

from typing import Any


class AgentShieldError(Exception):
    """
    Base exception for all AgentShield errors.

    All exceptions raised by the AgentShield SDK are subclasses
    of this class, allowing callers to catch all SDK errors with
    a single except clause.

    Attributes:
        message: Human-readable description of the error.
        threat_type: The attack vector classification, if applicable.
        confidence: Detection confidence score (0.0 to 1.0), if applicable.
        evidence: Supporting data for the error, as a dictionary.
        session_id: The session ID where the error occurred, if applicable.
    """

    def __init__(
        self,
        message: str,
        threat_type: str | None = None,
        confidence: float | None = None,
        evidence: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> None:
        """
        Initialize AgentShieldError.

        Args:
            message: Human-readable description of the error.
            threat_type: Attack vector classification string.
            confidence: Detection confidence from 0.0 to 1.0.
            evidence: Supporting data dictionary for forensic analysis.
            session_id: Session ID where the error occurred.
        """
        self.message = message
        self.threat_type = threat_type
        self.confidence = confidence
        self.evidence: dict[str, Any] = evidence or {}
        self.session_id = session_id
        super().__init__(self.message)

    def __str__(self) -> str:
        """Format exception as readable string with all context."""
        parts = [self.message]
        if self.threat_type:
            parts.append(f"threat={self.threat_type}")
        if self.confidence is not None:
            parts.append(f"confidence={self.confidence:.2f}")
        if self.session_id:
            parts.append(f"session={self.session_id}")
        return " | ".join(parts)

    def __repr__(self) -> str:
        """Detailed representation for debugging."""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"threat_type={self.threat_type!r}, "
            f"confidence={self.confidence!r}"
            f")"
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize exception to dictionary for JSON logging.

        Returns:
            Dictionary with all exception fields.
        """
        return {
            "exception_type": self.__class__.__name__,
            "message": self.message,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "session_id": self.session_id,
            "evidence": self.evidence,
        }


# ── Infrastructure Exceptions ─────────────────────────────────


class ConfigurationError(AgentShieldError):
    """Raised when AgentShield configuration is invalid."""


class InterceptorError(AgentShieldError):
    """Raised when an interceptor fails to attach or detach."""


class DetectionError(AgentShieldError):
    """Raised when the detection engine encounters an internal error."""


class EventEmissionError(AgentShieldError):
    """Raised when event emission to Redis or audit log fails critically."""


class RedisConnectionError(AgentShieldError):
    """Raised when AgentShield cannot connect to Redis."""


class ProvenanceError(AgentShieldError):
    """Raised when prompt provenance tracking encounters an error."""


class CanaryError(AgentShieldError):
    """Raised when the canary injection system encounters an error."""


class DNAError(AgentShieldError):
    """Raised when agent DNA fingerprinting encounters an error."""


class AuditChainError(AgentShieldError):
    """Raised when the cryptographic audit chain is broken or invalid."""


# ── Policy Violation Exceptions ───────────────────────────────


class PolicyViolationError(AgentShieldError):
    """
    Raised when an agent action violates the active security policy.

    This is the base class for all threat-based exceptions.
    When AgentShield is in blocking mode and detects a threat
    that exceeds the block threshold, it raises a subclass of
    this exception to halt execution.

    Catching PolicyViolationError catches all security violations.
    """


class ToolCallBlockedError(PolicyViolationError):
    """Raised when a tool call is blocked by AgentShield policy."""


class PrivilegeEscalationError(ToolCallBlockedError):
    """
    Raised when a tool chain escalation attack is detected.

    This is a subclass of ToolCallBlockedError because the
    mitigation is the same — block the tool call — but the
    threat type is specifically a privilege escalation pattern.
    """


class GoalDriftError(PolicyViolationError):
    """
    Raised when the agent has drifted too far from its original task.

    Indicates the agent's current behavior is semantically
    divergent from what the user originally requested.
    """


class PromptInjectionError(PolicyViolationError):
    """
    Raised when a prompt injection attack is detected.

    Indicates that external content (tool output, memory,
    user input) contains instructions attempting to hijack
    the agent's behavior.
    """


class MemoryPoisonError(PolicyViolationError):
    """
    Raised when anomalous content is detected being written
    to agent memory.

    Indicates a potential memory poisoning attack where an
    attacker attempts to corrupt the agent's context window
    across sessions.
    """


class BehavioralAnomalyError(PolicyViolationError):
    """
    Raised when the agent's behavior deviates significantly
    from its learned DNA baseline.

    This is the exception raised by the Agent DNA system (Phase 4)
    when behavioral fingerprinting detects abnormal patterns
    not covered by rule-based detectors.
    """


class InterAgentInjectionError(PolicyViolationError):
    """
    Raised when an inter-agent injection attack is detected.

    Indicates that one agent in a multi-agent system is
    attempting to manipulate another agent through shared
    memory, tool outputs, or message passing.
    """
