"""The HTML flow-graph viewer, rendered from the stage 5 demo's audit file."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from agentshield import AuditLog, Decision, Session, ToolCall, Verdict
from agentshield.cli import main
from agentshield.policy import load_policy
from agentshield.ui import render_html

DEMO = Path(__file__).resolve().parents[1] / "examples" / "exfil_demo.py"


def _demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("exfil_demo", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_audit_renders_with_the_blocked_send_email_edge(tmp_path: Path) -> None:
    demo = _demo()
    audit = tmp_path / "demo.jsonl"
    assert demo.run(audit=str(audit)) is False

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert [(r.get("tool"), r.get("verdict"), r.get("rule")) for r in records[-2:]] == [
        ("send_email", "ask", "untrusted-and-confidential-to-external"),
        ("send_email", "deny", "approval"),
    ]

    html = render_html(audit, load_policy(demo.POLICY))
    assert '<g class="call blocked" data-tool="send_email">' in html
    assert html.count('class="edge blocked"') == 1
    assert '<g class="call allowed" data-tool="web_fetch">' in html
    assert "untrusted data</text>" in html and "confidential data</text>" in html
    assert "ask → not approved" in html
    assert "<script" not in html


def test_cli_writes_the_page_next_to_the_audit_file(tmp_path: Path) -> None:
    audit = tmp_path / "demo.jsonl"
    _demo().run(audit=str(audit))
    assert main(["ui", str(audit)]) == 0
    assert "send_email" in (tmp_path / "demo.html").read_text(encoding="utf-8")


def test_audit_content_is_escaped(tmp_path: Path) -> None:
    path = tmp_path / "evil.jsonl"
    with AuditLog(path) as audit:
        audit.write(
            ToolCall("<script>alert(1)</script>"),
            Decision(Verdict.DENY, '"><img src=x onerror=alert(1)>'),
            Session(),
        )
    html = render_html(path)
    assert "<script>alert" not in html and "<img" not in html
    assert "&lt;script&gt;" in html
