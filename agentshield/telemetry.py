"""OpenTelemetry events for decisions. A no-op unless ``opentelemetry-api`` is installed.

Each decision becomes one ``agentshield.decision`` span event. It is added to the current
span when one is recording (for example a framework's ``execute_tool`` span); otherwise a
short ``execute_tool {name}`` span is started to carry it, with the GenAI semantic
convention attributes ``gen_ai.operation.name`` and ``gen_ai.tool.name``. Tool arguments
are never attached.

Telemetry cannot affect enforcement: every error here is swallowed. Configure your tracer
provider with a ``BatchSpanProcessor`` so export runs off the agent's thread; a
``SimpleSpanProcessor`` exports inline, and a slow exporter would then slow tool calls.

    pip install "agentshield-x[otel]"
"""

from __future__ import annotations

from functools import cache
from types import ModuleType

from agentshield.session import Decision, Session, ToolCall


@cache
def _trace() -> ModuleType | None:
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace


def emit_decision(call: ToolCall, decision: Decision, session: Session | None, policy: str) -> None:
    """Record one decision on the current trace. Never raises."""
    try:
        trace = _trace()
        if trace is None:
            return
        attributes = {
            "gen_ai.tool.name": call.name,
            "agentshield.verdict": decision.verdict.value,
            "agentshield.rule": decision.rule or "",
            "agentshield.reason": decision.reason,
            "agentshield.session.id": session.id if session is not None else "",
            "agentshield.policy.digest": policy,
        }
        span = trace.get_current_span()
        if span.is_recording():
            span.add_event("agentshield.decision", attributes)
            return
        tracer = trace.get_tracer("agentshield")
        with tracer.start_as_current_span(
            f"execute_tool {call.name}",
            attributes={"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": call.name},
        ) as own:
            own.add_event("agentshield.decision", attributes)
    except Exception:  # noqa: BLE001, S110 - telemetry must never change a decision
        pass
