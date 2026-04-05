__version__ = "0.1.0"
__author__ = "Aditya Belhekar"
__license__ = "MIT"

# Public API — everything a user ever needs to import from agentshield
from agentshield.runtime import shield, WrappedAgent, AgentShieldRuntime
from agentshield.config import AgentShieldConfig
from agentshield.exceptions import (
    AgentShieldError,
    ConfigurationError,
    PolicyViolationError,
    PromptInjectionError,
    GoalDriftError,
    ToolCallBlockedError,
    PrivilegeEscalationError,
    MemoryPoisonError,
    BehavioralAnomalyError,
    InterAgentInjectionError,
)

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "shield",
    "WrappedAgent",
    "AgentShieldRuntime",
    "AgentShieldConfig",
    "AgentShieldError",
    "ConfigurationError",
    "PolicyViolationError",
    "PromptInjectionError",
    "GoalDriftError",
    "ToolCallBlockedError",
    "PrivilegeEscalationError",
    "MemoryPoisonError",
    "BehavioralAnomalyError",
    "InterAgentInjectionError",
]
