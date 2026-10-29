"""Render an audit log as one self-contained HTML page of flow graphs.

``agentshield ui audit.jsonl [--policy p.yaml]`` writes ``audit.html``. Each session is a
graph read top to bottom: the model on the left, every attempted tool call on the right.
An arrow from the model to a tool is the call, coloured by outcome; blocked calls (denied,
or ``ask`` without an approval) are red.
A dashed arrow back from a tool is data entering the session: with ``--policy``, results
from ``untrusted`` and ``confidential`` tools are marked as the sources they are (the audit
records do not carry labels themselves).

Audit content is attacker-influenced (tool names, reasons), so everything is escaped and
the page runs no script.
"""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from agentshield.policy import Policy

_ROW = 64
_TOP = 70
_MODEL_X, _MODEL_W = 24, 150
_TOOL_X, _TOOL_W = 500, 236
_WIDTH = _TOOL_X + _TOOL_W + 24
_SOURCE_LABELS = ("untrusted", "confidential")


def read_records(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Decision records grouped by session id, in file order."""
    sessions: dict[str, list[dict[str, Any]]] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if isinstance(record, dict) and record.get("type") == "record":
            sessions.setdefault(str(record.get("session")), []).append(record)
    return sessions


def render_html(path: str | Path, policy: Policy | None = None) -> str:
    sessions = read_records(path)
    sections = [_session_section(sid, records, policy) for sid, records in sessions.items()]
    body = "\n".join(sections) or "<p>No decision records in this file.</p>"
    return _PAGE.format(title=escape(Path(path).name), body=body)


def _labels(policy: Policy | None, tool: str) -> list[str]:
    if policy is None or tool not in policy.tools:
        return []
    return sorted(str(label) for label in policy.tools[tool].labels)


def _calls(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per attempted call; an ``approval`` record resolves the ``ask`` before it."""
    calls: list[dict[str, Any]] = []
    for record in records:
        verdict = str(record.get("verdict"))
        previous = calls[-1] if calls else None
        if (
            record.get("rule") == "approval"
            and previous is not None
            and previous["verdict"] == "ask"
            and previous["tool"] == str(record.get("tool"))
        ):
            approved = verdict == "allow"
            previous["verdict"] = "ask → approved" if approved else "ask → not approved"
            previous["kind"] = "asked" if approved else "blocked"
            continue
        calls.append(
            {
                "seq": str(record.get("seq")),
                "tool": str(record.get("tool")),
                "verdict": verdict,
                "kind": {"allow": "allowed", "ask": "asked"}.get(verdict, "blocked"),
                "rule": str(record.get("rule") or ""),
                "reason": str(record.get("reason") or ""),
            }
        )
    return calls


def _session_section(sid: str, records: list[dict[str, Any]], policy: Policy | None) -> str:
    first = records[0]
    calls = _calls(records)
    height = _TOP + _ROW * len(calls) + 20
    parts = [
        f'<svg viewBox="0 0 {_WIDTH} {height}" width="{_WIDTH}" role="img" '
        f'aria-label="Flow graph for session {escape(sid)}">',
        _MARKERS,
        f'<rect class="node model" x="{_MODEL_X}" y="{_TOP - 40}" width="{_MODEL_W}" '
        f'height="{height - _TOP + 20}" rx="10"/>',
        f'<text class="node-title" x="{_MODEL_X + _MODEL_W / 2}" y="{_TOP - 16}">model</text>',
    ]
    rows = []
    for i, call in enumerate(calls):
        y = _TOP + _ROW * i + 20
        tool, verdict, kind = call["tool"], call["verdict"], call["kind"]
        labels = _labels(policy, tool)
        reason = escape(call["reason"])
        label_text = f" [{', '.join(labels)}]" if labels else ""
        parts.append(
            f'<g class="call {kind}" data-tool="{escape(tool)}"><title>{reason}</title>'
            f'<rect class="node tool" x="{_TOOL_X}" y="{y - 22}" width="{_TOOL_W}" '
            f'height="40" rx="8"/>'
            f'<text class="node-label" x="{_TOOL_X + 12}" y="{y + 3}">'
            f"{escape(tool)}{escape(label_text)}</text>"
            f'<line class="edge {kind}" x1="{_MODEL_X + _MODEL_W}" y1="{y - 6}" '
            f'x2="{_TOOL_X - 4}" y2="{y - 6}" marker-end="url(#arrow-{kind})"/>'
            f'<text class="edge-label {kind}" x="{(_MODEL_X + _MODEL_W + _TOOL_X) / 2}" '
            f'y="{y - 12}">#{escape(call["seq"])} {escape(verdict)}'
            f"{' ✕' if kind == 'blocked' else ''}</text>"
        )
        sources = [label for label in labels if label in _SOURCE_LABELS]
        if kind != "blocked" and sources:
            parts.append(
                f'<line class="edge data" x1="{_TOOL_X}" y1="{y + 8}" '
                f'x2="{_MODEL_X + _MODEL_W + 4}" y2="{y + 8}" marker-end="url(#arrow-data)"/>'
                f'<text class="edge-label data" x="{(_MODEL_X + _MODEL_W + _TOOL_X) / 2}" '
                f'y="{y + 22}">{escape(" + ".join(sources))} data</text>'
            )
        parts.append("</g>")
        rows.append(
            f'<tr class="{kind}"><td>{escape(call["seq"])}</td>'
            f"<td>{escape(tool)}</td><td>{escape(verdict)}</td>"
            f"<td>{escape(call['rule'])}</td><td>{reason}</td></tr>"
        )
    parts.append("</svg>")
    who = ", ".join(
        f"{key}: {escape(str(first.get(key)))}" for key in ("user", "task") if first.get(key)
    )
    return (
        f"<section><h2>Session <code>{escape(sid)}</code></h2>"
        f'<p class="meta">{who or "no user or task"} · {len(calls)} calls</p>'
        f'<div class="graph">{"".join(parts)}</div>'
        "<table><thead><tr><th>#</th><th>tool</th><th>verdict</th><th>rule</th>"
        f"<th>reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>"
    )


_MARKERS = (
    "<defs>"
    + "".join(
        f'<marker id="arrow-{kind}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        f'markerHeight="7" orient="auto-start-reverse"><path class="head {kind}" '
        'd="M0,0 L10,5 L0,10 z"/></marker>'
        for kind in ("allowed", "asked", "blocked", "data")
    )
    + "</defs>"
)

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentShield flow: {title}</title>
<style>
:root {{
  --bg: #ffffff; --fg: #1d1f23; --muted: #5d6470; --node: #f3f4f6; --stroke: #9aa1ab;
  --allowed: #1f7a4d; --asked: #b26b00; --blocked: #c62828; --data: #3567b5;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #15171a; --fg: #e6e8eb; --muted: #9aa1ab; --node: #23262b; --stroke: #4b515a;
    --allowed: #4cc38a; --asked: #f0a640; --blocked: #ff6b6b; --data: #7aa7ff;
  }}
}}
body {{ background: var(--bg); color: var(--fg); margin: 0 auto; padding: 24px 16px;
  max-width: 980px; font: 14px/1.5 system-ui, sans-serif; }}
h1 {{ font-size: 20px; }} h2 {{ font-size: 16px; margin-top: 32px; }}
.meta, .legend {{ color: var(--muted); }}
.graph {{ overflow-x: auto; }} svg {{ max-width: 100%; height: auto; }}
.node {{ fill: var(--node); stroke: var(--stroke); }}
.node-title {{ fill: var(--fg); font-weight: 600; text-anchor: middle; }}
.node-label {{ fill: var(--fg); font: 13px ui-monospace, monospace; }}
.edge {{ stroke-width: 2; }} .edge.data {{ stroke-dasharray: 5 4; }}
.edge-label {{ font-size: 12px; text-anchor: middle; }}
.edge.allowed, .head.allowed {{ stroke: var(--allowed); fill: var(--allowed); }}
.edge.asked, .head.asked {{ stroke: var(--asked); fill: var(--asked); }}
.edge.blocked, .head.blocked {{ stroke: var(--blocked); fill: var(--blocked); }}
.edge.data, .head.data {{ stroke: var(--data); fill: var(--data); }}
.edge-label.allowed {{ fill: var(--allowed); }} .edge-label.asked {{ fill: var(--asked); }}
.edge-label.blocked {{ fill: var(--blocked); font-weight: 600; }}
.edge-label.data {{ fill: var(--data); }}
.call.blocked .tool {{ stroke: var(--blocked); stroke-width: 2; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 13px; }}
th, td {{ text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--stroke);
  vertical-align: top; }}
tr.blocked td {{ color: var(--blocked); }} tr.asked td {{ color: var(--asked); }}
code {{ font-size: 12px; }}
</style></head><body>
<h1>AgentShield flow graph: {title}</h1>
<p class="legend">Solid arrows are tool calls (green allowed, orange approved by a person,
red blocked). Dashed arrows are untrusted or confidential data returned to the model.
Hover a call for the reason.</p>
{body}
</body></html>
"""
