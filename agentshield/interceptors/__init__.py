"""AgentShield interceptor layer.

Hooks into LangChain and other frameworks to observe every
tool call, LLM prompt, memory operation, and chain event
without modifying the agent's own code.

Public API:
  BaseInterceptor  : abstract base for all interceptors
  LLMInterceptor   : hooks LLM calls and chain lifecycle
"""

from agentshield.interceptors.base import BaseInterceptor
from agentshield.interceptors.llm_interceptor import LLMInterceptor

__all__ = [
    "BaseInterceptor",
    "LLMInterceptor",
]
