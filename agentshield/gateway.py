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

Hardening:

- ``mcp.allowed_servers`` in the policy lists the exact server commands the gateway may
  start (the command words joined by single spaces). Anything else is refused.
- With a lockfile (``--lock``), the hash of every tool's name, title, description, input
  schema and annotations is written the first time the tool is listed. If a later listing
  shows a different hash, calls to that tool are denied: a description is part of the
  prompt, and a server that rewrites one after review is changing what the model is told.
  Delete the tool's entry from the lockfile to accept the new version.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import IO, Any

from agentshield.exceptions import PolicyViolationError
from agentshield.session import Decision, Label, Session, ToolCall, Verdict
from agentshield.shield import Shield
from agentshield.spotlight import delimit
from agentshield.telemetry import emit_decision

INVALID_REQUEST = -32600
PARSE_ERROR = -32700


class Gateway:
    """Proxies one MCP client connection to one downstream server process."""

    def __init__(
        self, shield: Shield, command: Sequence[str], *, lock: str | Path | None = None
    ) -> None:
        if not command:
            raise ValueError("gateway needs a downstream server command")
        self.shield = shield
        self.command = list(command)
        self.server_key = " ".join(self.command)
        allowed = shield.policy.mcp.allowed_servers
        if allowed is not None and self.server_key not in allowed:
            raise PolicyViolationError(
                f"server command {self.server_key!r} is not in the policy's mcp.allowed_servers"
            )
        self.session = Session(task="mcp-gateway")
        self.lock_path = Path(lock) if lock is not None else None
        if self.lock_path is not None:
            read_lock(self.lock_path)  # fail at start, not mid-session, on a bad lockfile
        self.changed_tools: set[str] = set()
        self._pending: dict[Any, ToolCall] = {}
        self._listing: set[Any] = set()
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
            if isinstance(message, dict) and message.get("method") == "tools/list":
                list_id = message.get("id")
                if isinstance(list_id, str | int) and not isinstance(list_id, bool):
                    with self._lock:
                        self._listing.add(list_id)
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
        if name in self.changed_tools:
            decision = Decision(
                Verdict.DENY,
                f"tool {name!r} changed its description since it was locked",
                rule="mcp.tool_changed",
            )
            digest = self.shield.policy.digest
            if self.shield.audit is not None:
                with suppress(Exception):  # already a deny; a failed write changes nothing
                    self.shield.audit.write(call, decision, self.session, policy=digest)
            emit_decision(call, decision, self.session, digest)
        else:
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
            listing = message["id"] in self._listing
            self._listing.discard(message["id"])
        if listing:
            self._check_tools(message.get("result"))
            return line
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

    def _check_tools(self, result: object) -> None:
        if self.lock_path is None or not isinstance(result, dict):
            return
        tools = [t for t in result.get("tools") or [] if isinstance(t, dict) and "name" in t]
        with self._lock:
            lock = read_lock(self.lock_path)
            pinned = lock["servers"].setdefault(self.server_key, {})
            for tool in tools:
                name, digest = str(tool["name"]), tool_digest(tool)
                if pinned.setdefault(name, digest) != digest:
                    self.changed_tools.add(name)
            write_lock(self.lock_path, lock)

    def _write(self, stdout: IO[bytes], data: bytes) -> None:
        with self._write_lock:
            stdout.write(data)
            stdout.flush()


_BATCH_REFUSED = "AgentShield gateway: batches containing tools/call are not supported"


def run_gateway(shield: Shield, command: Sequence[str], *, lock: str | Path | None = None) -> int:
    """Run a gateway on this process's stdin/stdout."""
    return Gateway(shield, command, lock=lock).run(sys.stdin.buffer, sys.stdout.buffer)


_PINNED_FIELDS = ("name", "title", "description", "inputSchema", "annotations")


def tool_digest(tool: dict[str, Any]) -> str:
    """SHA-256 over the parts of a tool definition the model reads or relies on."""
    pinned = {key: tool.get(key) for key in _PINNED_FIELDS}
    return hashlib.sha256(json.dumps(pinned, sort_keys=True).encode()).hexdigest()


def read_lock(path: Path) -> dict[str, Any]:
    """Load a lockfile, or return an empty one if it does not exist yet."""
    if not path.exists():
        return {"version": 1, "servers": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"{path} is not an AgentShield MCP lockfile")
    data.setdefault("servers", {})
    return data


def list_server_tools(command: Sequence[str]) -> list[dict[str, Any]]:
    """Start ``command``, do the initialize handshake, and return every listed tool."""
    # ponytail: blocking reads with no timeout; a server that never answers hangs this.
    server = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert server.stdin is not None and server.stdout is not None
    send, out = server.stdin, server.stdout

    def request(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        send.write(
            _encode({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        )
        send.flush()
        for line in out:
            message = json.loads(line)
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    raise ValueError(f"{method} failed: {message['error']}")
                result: dict[str, Any] = message["result"]
                return result
        raise ValueError(f"server closed before answering {method}")

    try:
        request(
            0,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agentshield-draft", "version": "0"},
            },
        )
        send.write(_encode({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        tools: list[dict[str, Any]] = []
        params: dict[str, Any] = {}
        for request_id in range(1, 1000):
            page = request(request_id, "tools/list", params)
            tools.extend(t for t in page.get("tools", []) if isinstance(t, dict))
            if not page.get("nextCursor"):
                break
            params = {"cursor": page["nextCursor"]}
        return tools
    finally:
        with suppress(OSError):
            send.close()
        server.terminate()
        server.wait()


def draft_policy(tools: Sequence[dict[str, Any]], server_key: str) -> str:
    """A starting policy for a server: every tool at its most restrictive labels.

    The server's descriptions and annotations are shown as comments, not trusted: a
    server can claim ``readOnlyHint`` for a tool that sends email. Relax each label only
    after reading what the tool really does.
    """
    lines = [
        "# Draft AgentShield policy. Review every tool before using it.",
        "# Descriptions and annotations below come from the server and are unverified.",
        "version: 2",
        "extends: strict",
        "mcp:",
        f"  allowed_servers: [{json.dumps(server_key)}]",
        "tools:",
    ]
    for tool in sorted(tools, key=lambda t: str(t.get("name"))):
        description = " ".join(str(tool.get("description") or "").split())[:200]
        hints = tool.get("annotations") or {}
        lines.append(f"  # {description}" if description else "  # (no description)")
        if isinstance(hints, dict) and hints:
            shown = ", ".join(f"{key}={value}" for key, value in sorted(hints.items()))
            lines.append(f"  # server hints: {' '.join(shown.split())[:200]}")
        lines.append(f"  {json.dumps(str(tool.get('name')))}: {{labels: [untrusted, external]}}")
    return "\n".join(lines) + "\n"


def write_lock(path: Path, lock: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


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
