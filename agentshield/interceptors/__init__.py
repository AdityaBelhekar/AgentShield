"""AgentShield interceptor layer.

Hooks into LangChain and other frameworks to observe every
tool call, LLM prompt, memory operation, and chain event
without modifying the agent's own code.

Public API:
  BaseInterceptor  : abstract base for all interceptors
  LLMInterceptor   : hooks LLM calls and chain lifecycle
  ToolInterceptor  : hooks tool invocations via monkey-patch
  HookResult       : return type for pre-call hooks
  PatchedTool      : internal record for patched tool state
"""

from agentshield.interceptors.base import BaseInterceptor
from agentshield.interceptors.llm_interceptor import LLMInterceptor
from agentshield.interceptors.tool_interceptor import (
    HookResult,
    PatchedTool,
    ToolInterceptor,
)

__all__ = [
    "BaseInterceptor",
    "HookResult",
    "LLMInterceptor",
    "PatchedTool",
    "ToolInterceptor",
]
