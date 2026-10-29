"""Decision events on OpenTelemetry, and proof that telemetry cannot affect tool calls."""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Iterator, Sequence

import pytest

from agentshield import PolicyViolationError, Shield

pytest.importorskip("opentelemetry.sdk")

from opentelemetry import trace  # noqa: E402
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import (  # noqa: E402
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)


class SlowFailingExporter(SpanExporter):
    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        time.sleep(0.5)
        raise RuntimeError("collector is down")


class BrokenProcessor(SpanProcessor):
    def on_end(self, span: ReadableSpan) -> None:
        raise RuntimeError("processor bug")


MEMORY = InMemorySpanExporter()
BROKEN = BrokenProcessor()
PROVIDER = TracerProvider()
PROVIDER.add_span_processor(SimpleSpanProcessor(MEMORY))
PROVIDER.add_span_processor(BatchSpanProcessor(SlowFailingExporter(), schedule_delay_millis=1))
trace.set_tracer_provider(PROVIDER)


@pytest.fixture(autouse=True, scope="module")
def _stop_exporting_after_this_module() -> Iterator[None]:
    # The global provider cannot be unset; shut it down so later tests don't feed it.
    yield
    PROVIDER.shutdown()


def _shield() -> Shield:
    return Shield.from_policy({"version": 2, "tools": {"lookup": {}, "bash": {"deny": True}}})


def test_each_decision_is_a_span_event_with_genai_attributes() -> None:
    MEMORY.clear()
    shield = _shield()
    lookup = shield.tool("lookup", lambda q: q.upper())
    bash = shield.tool("bash", lambda command: command)

    with shield.session(user="alice") as session:
        assert lookup("x") == "X"
        with pytest.raises(PolicyViolationError):
            bash("ls")

    spans = MEMORY.get_finished_spans()
    assert [s.name for s in spans] == ["execute_tool lookup", "execute_tool bash"]
    assert spans[0].attributes is not None
    assert spans[0].attributes["gen_ai.operation.name"] == "execute_tool"
    events = [s.events[0] for s in spans]
    assert all(e.name == "agentshield.decision" for e in events)
    assert events[0].attributes is not None and events[1].attributes is not None
    assert events[0].attributes["agentshield.verdict"] == "allow"
    assert events[1].attributes["agentshield.verdict"] == "deny"
    assert events[1].attributes["agentshield.rule"] == "tools.bash.deny"
    assert events[1].attributes["agentshield.session.id"] == session.id
    assert events[1].attributes["gen_ai.tool.name"] == "bash"
    assert "agentshield.args" not in events[1].attributes


def test_the_event_joins_an_existing_span() -> None:
    MEMORY.clear()
    shield = _shield()
    lookup = shield.tool("lookup", lambda q: q)
    with shield.session(), trace.get_tracer("app").start_as_current_span("agent step"):
        lookup("x")
    (span,) = MEMORY.get_finished_spans()
    assert span.name == "agent step"
    assert [e.name for e in span.events] == ["agentshield.decision"]


def test_failing_and_slow_exporters_do_not_touch_tool_calls() -> None:
    PROVIDER.add_span_processor(BROKEN)
    shield = _shield()
    lookup = shield.tool("lookup", lambda q: q)
    started = time.perf_counter()
    with shield.session():
        results = [lookup(i) for i in range(20)]
    assert results == list(range(20))
    # The exporter takes 0.5 s per batch and raises; calls must not wait for it.
    assert time.perf_counter() - started < 0.5


def test_without_opentelemetry_it_is_a_no_op() -> None:
    code = (
        "import sys\n"
        "sys.modules['opentelemetry'] = None  # import fails, as if the extra were absent\n"
        "from agentshield import Shield\n"
        "shield = Shield.from_policy({'version': 2, 'tools': {'t': {}}})\n"
        "t = shield.tool('t', lambda: 42)\n"
        "with shield.session():\n"
        "    print(t())\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "42"
