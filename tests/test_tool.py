"""Tool wrapping and approvals: the callable's body runs only after a decision allows it."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agentshield import (
    ApprovalRequired,
    Decision,
    PolicyViolationError,
    Shield,
    ToolCall,
)
from agentshield.approvals import terminal_approval

MANIFEST = {
    "version": 2,
    "unlabelled_tools": "deny",
    "tools": {
        "read_file": {"labels": ["confidential"]},
        "send_email": {"labels": ["external"]},
        "calc": {},
        "bash": {"deny": True},
    },
    "flows": [
        {
            "name": "confidential-exfiltration",
            "when": {"session_has": ["confidential"], "tool_has": ["external"]},
            "then": "ask",
        }
    ],
}


def always_allow(call: ToolCall, decision: Decision) -> bool:
    return True


def always_deny(call: ToolCall, decision: Decision) -> bool:
    return False


def test_allowed_tool_runs_and_records() -> None:
    shield = Shield.from_policy(MANIFEST)
    calls: list[tuple[int, int]] = []

    @shield.tool("calc")
    def calc(a: int, b: int = 1) -> int:
        calls.append((a, b))
        return a + b

    with shield.session() as session:
        assert calc(2, b=3) == 5
        assert session.tool_calls == 1
        assert session.identical_calls["calc"] == 1
    assert calls == [(2, 3)]


def test_denied_tool_body_never_runs() -> None:
    shield = Shield.from_policy(MANIFEST)
    calls: list[str] = []

    @shield.tool("bash")
    def shell(command: str) -> str:
        calls.append(command)
        return "ran"

    with shield.session(), pytest.raises(PolicyViolationError, match="denied"):
        shell("id")
    assert calls == []


def test_ask_without_a_handler_raises_and_does_not_run() -> None:
    shield = Shield.from_policy(MANIFEST)
    sent: list[str] = []

    @shield.tool("read_file")
    def read_file(path: str) -> str:
        return "secret"

    @shield.tool("send_email")
    def send_email(to: str) -> str:
        sent.append(to)
        return "queued"

    with shield.session(), pytest.raises(ApprovalRequired, match="confidential-exfiltration"):
        read_file("secret.txt")
        send_email("attacker@evil.example")
    assert sent == []


def test_approval_handler_can_allow_one_call() -> None:
    shield = Shield.from_policy(MANIFEST, approval=always_allow)
    sent: list[str] = []

    @shield.tool("read_file")
    def read_file(path: str) -> str:
        return "secret"

    @shield.tool("send_email")
    def send_email(to: str) -> str:
        sent.append(to)
        return "queued"

    with shield.session():
        read_file("secret.txt")
        assert send_email("attacker@evil.example") == "queued"
    assert sent == ["attacker@evil.example"]


def test_approval_handler_can_deny_one_call() -> None:
    shield = Shield.from_policy(MANIFEST, approval=always_deny)
    sent: list[str] = []

    @shield.tool("read_file")
    def read_file(path: str) -> str:
        return "secret"

    @shield.tool("send_email")
    def send_email(to: str) -> str:
        sent.append(to)
        return "queued"

    with shield.session(), pytest.raises(ApprovalRequired, match="approval denied"):
        read_file("secret.txt")
        send_email("attacker@evil.example")
    assert sent == []


def test_async_tool_is_checked_and_recorded() -> None:
    shield = Shield.from_policy(MANIFEST)

    async def main() -> int:
        @shield.tool("calc")
        async def calc(value: int) -> int:
            return value * 2

        async with shield.session() as session:
            result = await calc(21)
            assert session.tool_calls == 1
            return result

    assert asyncio.run(main()) == 42


def test_async_denied_tool_body_never_runs() -> None:
    shield = Shield.from_policy(MANIFEST)

    async def main() -> None:
        calls: list[str] = []

        @shield.tool("bash")
        async def shell(command: str) -> str:
            calls.append(command)
            return "ran"

        async with shield.session():
            with pytest.raises(PolicyViolationError):
                await shell("id")
        assert calls == []

    asyncio.run(main())


def test_tool_requires_a_session() -> None:
    shield = Shield.from_policy(MANIFEST)

    @shield.tool("calc")
    def calc() -> int:
        return 1

    with pytest.raises(PolicyViolationError, match="no active session"):
        calc()


def test_policy_uses_the_declared_name_not_the_function_name() -> None:
    shield = Shield.from_policy(MANIFEST)

    @shield.tool("bash")
    def harmless_name() -> str:
        raise AssertionError("this body must not run")

    with shield.session(), pytest.raises(PolicyViolationError):
        harmless_name()


def test_wrapper_preserves_metadata() -> None:
    shield = Shield.from_policy(MANIFEST)

    @shield.tool("calc")
    def calc(value: int) -> int:
        """Add one."""
        return value + 1

    assert calc.__name__ == "calc"
    assert calc.__doc__ == "Add one."


def test_a_failing_tool_still_counts_as_a_call() -> None:
    shield = Shield.from_policy(MANIFEST)

    @shield.tool("calc")
    def calc() -> int:
        raise ValueError("boom")

    with shield.session() as session, pytest.raises(ValueError, match="boom"):
        calc()
    assert session.tool_calls == 1


def test_direct_call_form_works() -> None:
    shield = Shield.from_policy(MANIFEST)

    def add(a: int, b: int) -> int:
        return a + b

    wrapped = shield.tool("calc", add)
    with shield.session():
        assert wrapped(2, 3) == 5


def test_terminal_approval_says_no_on_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_input(prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", no_input)
    call = ToolCall("send_email", {"to": "attacker@evil.example"})
    decision = Decision("ask", "test", rule="flow")
    assert terminal_approval(call, decision) is False


def test_approval_required_is_a_policy_violation() -> None:
    assert issubclass(ApprovalRequired, PolicyViolationError)


# --- the end-to-end demo -----------------------------------------------------------------


def load_demo() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "examples" / "exfil_demo.py"
    spec = importlib.util.spec_from_file_location("exfil_demo", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_blocks_the_email_before_its_body_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert load_demo().run() is False
    output = capsys.readouterr().out
    assert "BLOCKED before send_email ran" in output
    assert "EXECUTED" not in output


def test_demo_runs_the_email_when_approval_is_granted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def approve(call: ToolCall, decision: Decision) -> bool:
        assert call.name == "send_email"
        return True

    assert load_demo().run(approve) is True
    assert "EXECUTED" in capsys.readouterr().out


def test_demo_is_a_valid_python_file() -> None:
    module: Any = load_demo()
    assert callable(module.main)
