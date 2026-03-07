"""AgentShield — Real-time security runtime for AI agents.

Public API surface for the ``agentshield`` package.
"""

from __future__ import annotations

from agentshield.config import AgentShieldConfig
from agentshield.exceptions import (
    AgentShieldError,
    GoalDriftError,
    MemoryPoisonError,
    PolicyViolationError,
    PromptInjectionError,
    ToolCallBlockedError,
)

__version__ = "0.1.0"
__all__ = [
    "AgentShieldConfig",
    "AgentShieldError",
    "GoalDriftError",
    "MemoryPoisonError",
    "PolicyViolationError",
    "PromptInjectionError",
    "ToolCallBlockedError",
]
