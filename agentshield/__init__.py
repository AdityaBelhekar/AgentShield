"""
AgentShield — Production-grade security runtime for AI agents.

The security primitive the agent ecosystem is missing.

Quick start:
    from agentshield import shield

    agent = shield(your_langchain_agent, policy="no_exfiltration")
    agent.run("Summarize this document")  # Fully protected

GitHub: https://github.com/AdityaBelhekar/AgentShield
Docs:   https://agentshield.dev/docs
"""

from agentshield.config import AgentShieldConfig
from agentshield.events import (
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
from agentshield.exceptions import (
    AgentShieldError,
    AuditChainError,
    BehavioralAnomalyError,
    CanaryError,
    ConfigurationError,
    DetectionError,
    DNAError,
    EventEmissionError,
    GoalDriftError,
    InterAgentInjectionError,
    InterceptorError,
    MemoryPoisonError,
    PolicyViolationError,
    PrivilegeEscalationError,
    PromptInjectionError,
    ProvenanceError,
    RedisConnectionError,
    ToolCallBlockedError,
)

__version__ = "0.1.0"
__author__ = "GroundTruth"
__license__ = "MIT"

__all__ = [
    "__version__",
    # Config
    "AgentShieldConfig",
    # Events
    "AuditLog",
    "BaseEvent",
    "CanaryEvent",
    "EventType",
    "LLMEvent",
    "MemoryEvent",
    "ProvenanceEvent",
    "RecommendedAction",
    "SessionEvent",
    "SeverityLevel",
    "ThreatEvent",
    "ThreatType",
    "ToolCallEvent",
    "TrustLevel",
    "deserialize_event",
    # Base exceptions
    "AgentShieldError",
    "ConfigurationError",
    "InterceptorError",
    "DetectionError",
    "EventEmissionError",
    "RedisConnectionError",
    "ProvenanceError",
    "CanaryError",
    "DNAError",
    "AuditChainError",
    # Policy violations
    "PolicyViolationError",
    "ToolCallBlockedError",
    "PrivilegeEscalationError",
    "GoalDriftError",
    "PromptInjectionError",
    "MemoryPoisonError",
    "BehavioralAnomalyError",
    "InterAgentInjectionError",
]
