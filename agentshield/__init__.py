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

from agentshield.adapters import AdapterRegistry, BaseAdapter
from agentshield.audit import (
    AuditChainExporter,
    AuditChainStore,
    AuditChainVerifier,
    ChainedAuditEntry,
    VerificationResult,
)
from agentshield.canary import CanarySystem
from agentshield.config import AgentShieldConfig
from agentshield.detection import (
    AgentTrustGraph,
    AgentTrustState,
    DetectionEngine,
    InterAgentMonitor,
)
from agentshield.dna import AgentBaseline, AnomalyReport, DNAAnomalyScorer, DNASystem
from agentshield.events import (
    AuditLog,
    BaseEvent,
    CanaryEvent,
    EventEmitter,
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
    AdapterError,
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
from agentshield.notifications import WebhookConfig, WebhookNotifier
from agentshield.observability import OTelConfig, OTelExporter
from agentshield.policy import (
    BUILTIN_POLICIES,
    CompiledPolicy,
    PolicyAction,
    PolicyCompiler,
    PolicyConfig,
    PolicyDecision,
    PolicyEvaluator,
    PolicyRule,
)
from agentshield.provenance import ProvenanceTracker
from agentshield.runtime import AgentShieldRuntime, WrappedAgent, shield
from agentshield.scrubber import EventScrubber

__version__ = "0.1.0"
__author__ = "GroundTruth"
__license__ = "MIT"

__all__ = [
    "__version__",
    # Config
    "AgentShieldConfig",
    "WebhookConfig",
    "WebhookNotifier",
    "OTelConfig",
    "OTelExporter",
    "AuditChainExporter",
    "AuditChainStore",
    "AuditChainVerifier",
    "CanarySystem",
    "DNASystem",
    "AgentBaseline",
    "DNAAnomalyScorer",
    "AnomalyReport",
    # Events
    "AuditLog",
    "BaseEvent",
    "CanaryEvent",
    "EventEmitter",
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
    "ChainedAuditEntry",
    "VerificationResult",
    "deserialize_event",
    # Base exceptions
    "AgentShieldError",
    "AdapterError",
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
    # Policy
    "PolicyCompiler",
    "CompiledPolicy",
    "PolicyConfig",
    "PolicyRule",
    "PolicyAction",
    "PolicyDecision",
    "PolicyEvaluator",
    "BUILTIN_POLICIES",
    # Runtime
    "AgentTrustGraph",
    "AgentTrustState",
    "DetectionEngine",
    "InterAgentMonitor",
    "ProvenanceTracker",
    "AgentShieldRuntime",
    "WrappedAgent",
    "shield",
    "EventScrubber",
    "BaseAdapter",
    "AdapterRegistry",
]
