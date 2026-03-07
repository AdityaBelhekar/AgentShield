"""AgentShield exception hierarchy.

Provides a structured exception tree for all error conditions
in the AgentShield runtime. Each exception carries optional
threat metadata for forensic context.
"""

from __future__ import annotations

from typing import Any


class AgentShieldError(Exception):
    """Base exception for all AgentShield errors.

    Attributes:
        message: Human-readable error description.
        threat_type: Optional threat classification string.
        confidence: Optional detection confidence score (0.0–1.0).
        evidence: Optional dict of forensic evidence.
    """

    def __init__(
        self,
        message: str,
        *,
        threat_type: str | None = None,
        confidence: float | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.threat_type = threat_type
        self.confidence = confidence
        self.evidence = evidence or {}
        super().__init__(message)

    def __str__(self) -> str:
        parts = [self.message]
        if self.threat_type:
            parts.append(f"threat_type={self.threat_type}")
        if self.confidence is not None:
            parts.append(f"confidence={self.confidence:.2f}")
        if self.evidence:
            parts.append(f"evidence={self.evidence}")
        return " | ".join(parts)


# ── Configuration ──────────────────────────────────────────


class ConfigurationError(AgentShieldError):
    """Raised when AgentShield configuration is invalid or missing."""


# ── Interceptor ────────────────────────────────────────────


class InterceptorError(AgentShieldError):
    """Raised when an interceptor fails to attach or detach."""


# ── Detection ──────────────────────────────────────────────


class DetectionError(AgentShieldError):
    """Raised when a detector encounters a runtime error."""


# ── Event System ───────────────────────────────────────────


class EventEmissionError(AgentShieldError):
    """Raised when event emission to Redis or audit log fails."""


class RedisConnectionError(AgentShieldError):
    """Raised when Redis is unavailable or connection fails."""


# ── Policy Violations ─────────────────────────────────────


class PolicyViolationError(AgentShieldError):
    """Raised when a security policy is violated.

    This is the parent class for all threat-specific blocking
    exceptions. Catching this catches all blocked threats.
    """


class ToolCallBlockedError(PolicyViolationError):
    """Raised when a tool call is blocked by a security policy."""


class PrivilegeEscalationError(ToolCallBlockedError):
    """Raised when a tool chain escalation pattern is detected."""


class GoalDriftError(PolicyViolationError):
    """Raised when agent goal drift exceeds the block threshold."""


class PromptInjectionError(PolicyViolationError):
    """Raised when a prompt injection attack is detected and blocked."""


class MemoryPoisonError(PolicyViolationError):
    """Raised when a memory poisoning attempt is detected and blocked."""
