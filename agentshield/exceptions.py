"""AgentShield — Real-time security runtime for AI agents.

Provides exception classes for error handling across the SDK.
All exceptions carry optional threat metadata for security context.
"""

from __future__ import annotations

from typing import Any


class AgentShieldError(Exception):
    """Base exception for all AgentShield errors.

    Attributes:
        message: Human-readable error description.
        threat_type: Optional threat classification string.
        confidence: Optional detection confidence score (0.0–1.0).
        evidence: Optional dictionary of supporting evidence.
    """

    def __init__(
        self,
        message: str,
        threat_type: str | None = None,
        confidence: float | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.threat_type = threat_type
        self.confidence = confidence
        self.evidence = evidence or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        """Format error with threat metadata when available."""
        parts = [self.message]
        if self.threat_type:
            parts.append(f"threat={self.threat_type}")
        if self.confidence is not None:
            parts.append(f"confidence={self.confidence:.2f}")
        return " | ".join(parts)


class ConfigurationError(AgentShieldError):
    """Raised when SDK configuration is invalid or missing."""


class InterceptorError(AgentShieldError):
    """Raised when an interceptor fails to attach, detach, or operate."""


class DetectionError(AgentShieldError):
    """Raised when the detection engine encounters an internal error."""


class EventEmissionError(AgentShieldError):
    """Raised when event emission to Redis or audit log fails."""


class RedisConnectionError(AgentShieldError):
    """Raised when a connection to Redis cannot be established."""


class PolicyViolationError(AgentShieldError):
    """Raised when an agent action violates a security policy."""


class ToolCallBlockedError(PolicyViolationError):
    """Raised when a tool call is blocked by policy or detection."""


class PrivilegeEscalationError(ToolCallBlockedError):
    """Raised when a tool call attempts unauthorized privilege escalation."""


class GoalDriftError(PolicyViolationError):
    """Raised when agent behavior drifts from the original task goal."""


class PromptInjectionError(PolicyViolationError):
    """Raised when a prompt injection attack is detected and blocked."""


class MemoryPoisonError(PolicyViolationError):
    """Raised when memory poisoning is detected and blocked."""
