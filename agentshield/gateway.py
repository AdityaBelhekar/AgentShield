"""A stdio MCP gateway: every ``tools/call`` passes through the engine.

``agentshield gateway --policy p.yaml -- <server command>`` starts the downstream MCP
server and sits between it and the client on stdin/stdout. Messages are newline-delimited
JSON-RPC, as the MCP stdio transport defines them. Everything except ``tools/call`` is
forwarded byte for byte, so the gateway works with any protocol version the two ends
negotiate. A ``tools/call`` is checked first:

- ``allow``: forwarded unchanged; the response is recorded (taint) and, for an
  ``untrusted`` tool, its text content is delimited like ``Shield.tool`` results.
- ``deny`` or ``ask``: answered by the gateway with a tool error the model can read. The
  downstream server never sees the request. There is no human on a stdio pipe, so ``ask``
  is treated as ``deny``.

Fail-closed on input the gateway cannot read: a client line that is not one JSON object
with unique keys, or a batch that contains a ``tools/call``, gets an error instead of being
forwarded, so the server cannot be handed something the engine did not check.

One gateway process serves one client connection, so it holds one session.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Sequence
from contextlib import suppress
from typing import IO, Any

from agentshield.session import Label, Session, ToolCall, Verdict
from agentshield.shield import Shield
from agentshield.spotlight import delimit

INVALID_REQUEST = -32600
PARSE_ERROR = -32700


class Gateway:
    """Proxies one MCP client connection to one downstream server process."""

    def __init__(self, shield: Shield, command: Sequence[str]) -> None:
        if not command:
            raise ValueError("gateway needs a downstream server command")
        self.shield = shield
        self.command = list(command)
        self.session = Session(task="mcp-gateway")
        self._pending: dict[Any, ToolCall] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()

    def run(self, stdin: IO[bytes], stdout: IO[bytes]) -> int:
        """Pump both directions until either side closes; return the server's exit code."""
        server = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        assert server.stdin is not None and server.stdout is not None
        server_in, server_out = server.stdin, server.stdout

        def client_to_server() -> None:
            try:
                for line in stdin:
                    forward, reply = self.from_client(line)
                    if reply is not None:
                        self._write(stdout, reply)
                    if forward is not None:
                        server_in.write(forward)
                        server_in.flush()
            except (BrokenPipeError, OSError):
                pass
            finally:
                with suppress(OSError):
                    server_in.close()

        pump = threading.Thread(target=client_to_server, daemon=True)
        pump.start()
        try:
            for line in server_out:
                self._write(stdout, self.from_server(line))
        except (BrokenPipeError, OSError):
            pass
        return server.wait()

    def from_client(self, line: bytes) -> tuple[bytes | None, bytes | None]:
        """Return ``(line to forward to the server, reply to send to the client)``."""
        if not line.strip():
            return None, None
        try:
            message = json.loads(line, object_pairs_hook=_unique_keys)
        except ValueError as exc:
            return None, _error(
                None, PARSE_ERROR, f"AgentShield gateway: unreadable message: {exc}"
            )

        if isinstance(message, list):
            if any(_is_tool_call(item) for item in message):
                replies = [
                    json.loads(_error(item.get("id"), INVALID_REQUEST, _BATCH_REFUSED))
                    for item in message
                    if isinstance(item, dict) and "id" in item and "method" in item
                ]
                return None, _encode(replies) if replies else None
            return line, None

        if not _is_tool_call(message):
            return line, None

        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        message_id = message.get("id")
        if (
            not isinstance(name, str)
            or not isinstance(arguments, dict | None)
            or not isinstance(message_id, str | int | None)
            or isinstance(message_id, bool)
        ):
            return None, _error(None, INVALID_REQUEST, "malformed tools/call request")

        call = ToolCall(name, dict(arguments or {}))
        decision = self.shield.engine.check(call, self.session)
        if decision.verdict is not Verdict.ALLOW:
            if "id" not in message:
                return None, None  # a notification gets no reply
            prefix = "needs approval" if decision.verdict is Verdict.ASK else "denied"
            return None, _encode(
                {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"AgentShield {prefix}: {decision.reason}"}
                        ],
                        "isError": True,
                        # Required from protocol 2026-07-28; older clients ignore it.
                        "resultType": "complete",
                    },
                }
            )
        if "id" in message:
            with self._lock:
                self._pending[message_id] = call
        return line, None

    def from_server(self, line: bytes) -> bytes:
        """Record a response to a checked ``tools/call``; pass everything else through."""
        try:
            message = json.loads(line)
        except ValueError:
            return line
        if not isinstance(message, dict) or "method" in message or "id" not in message:
            return line
        with self._lock:
            call = self._pending.pop(message["id"], None)
        if call is None:
            return line

        self.shield.engine.record(call, session=self.session)
        rule = self.shield.policy.tools.get(call.name)
        result = message.get("result")
        if rule is None or Label.UNTRUSTED not in rule.labels or not isinstance(result, dict):
            return line
        content = result.get("content")
        if not isinstance(content, list):
            return line
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = delimit(str(block.get("text", "")), source=call.name)
        return _encode(message)

    def _write(self, stdout: IO[bytes], data: bytes) -> None:
        with self._write_lock:
            stdout.write(data)
            stdout.flush()


_BATCH_REFUSED = "AgentShield gateway: batches containing tools/call are not supported"


def run_gateway(shield: Shield, command: Sequence[str]) -> int:
    """Run a gateway on this process's stdin/stdout."""
    return Gateway(shield, command).run(sys.stdin.buffer, sys.stdout.buffer)


def _is_tool_call(message: object) -> bool:
    return isinstance(message, dict) and message.get("method") == "tools/call"


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # A duplicate key could be read one way here and another way by the server.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _error(message_id: Any, code: int, text: str) -> bytes:
    return _encode({"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": text}})


def _encode(message: object) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"
