"""AgentShield: a policy-enforcing reference monitor for AI agent tool calls."""

from agentshield.exceptions import AgentShieldError
from agentshield.session import (
    Decision,
    Label,
    Session,
    ToolCall,
    Verdict,
    current_session,
)
from agentshield.shield import Shield

__version__ = "0.2.0.dev0"

__all__ = [
    "AgentShieldError",
    "Decision",
    "Label",
    "Session",
    "Shield",
    "ToolCall",
    "Verdict",
    "__version__",
    "current_session",
]
