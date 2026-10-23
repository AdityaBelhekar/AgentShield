"""LangChain / LangGraph agent middleware.

Every tool call the agent makes is routed through the same enforcement engine as
``Shield.tool``, using the framework's own ``wrap_tool_call`` hook. Nothing is
monkey-patched: the middleware is passed to ``create_agent(..., middleware=[...])``.

Install the extra first::

    pip install "agentshield-x[langchain]"

Usage::

    from langchain.agents import create_agent

    shield = Shield.from_policy("policy.yaml")
    agent = create_agent(model, tools, middleware=[shield.langchain()])

    with shield.session(user="u_123", task="triage inbox"):
        agent.invoke({"messages": [...]})

The middleware needs an active session, like every other entry point. It implements the
sync and async hooks, so ``invoke``, ``stream``, ``ainvoke`` and ``astream`` are all
covered. Use either this middleware or ``shield.tool(...)`` for a tool, not both, or the
call is checked and counted twice.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain.agents.middleware.types import ToolCallRequest
from langchain_core.messages import ToolMessage
from langgraph.types import Command

from agentshield.session import ToolCall
from agentshield.shield import Shield

ToolResult = ToolMessage | Command[Any]
ToolHandler = Callable[[ToolCallRequest], ToolResult]
AsyncToolHandler = Callable[[ToolCallRequest], Awaitable[ToolResult]]


class ShieldMiddleware(AgentMiddleware[Any, Any, Any]):
    """Checks, approves and records every tool call made by a LangChain agent."""

    def __init__(self, shield: Shield) -> None:
        super().__init__()
        self.shield = shield

    def wrap_tool_call(self, request: ToolCallRequest, handler: ToolHandler) -> ToolResult:
        call = _tool_call(request)
        self.shield._authorize(call)
        try:
            result = handler(request)
        except BaseException:
            self.shield.engine.record(call)
            raise
        self.shield.engine.record(call)
        return self._spotlight(call, result)

    async def awrap_tool_call(
        self, request: ToolCallRequest, handler: AsyncToolHandler
    ) -> ToolResult:
        call = _tool_call(request)
        self.shield._authorize(call)
        try:
            result = await handler(request)
        except BaseException:
            self.shield.engine.record(call)
            raise
        self.shield.engine.record(call)
        return self._spotlight(call, result)

    def _spotlight(self, call: ToolCall, result: ToolResult) -> ToolResult:
        if isinstance(result, ToolMessage):
            content = self.shield._spotlight_result(call, result.content)
            if content is not result.content:
                return result.model_copy(update={"content": content})
        return result


def _tool_call(request: ToolCallRequest) -> ToolCall:
    arguments = request.tool_call.get("args") or {}
    return ToolCall(name=request.tool_call["name"], args=dict(arguments))
