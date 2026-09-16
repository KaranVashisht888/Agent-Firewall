"""Minimal hand-rolled stdio MCP-subset used only by the demo mock servers.

This implements just enough of the Model Context Protocol -- newline
delimited JSON-RPC 2.0 over stdio, with `initialize`, `tools/list`, and
`tools/call` -- to drive the mcp-firewall demo without adding the `mcp`
SDK as a runtime dependency. The SDK itself is still used, as a dev/test
only dependency, to build a separate real server for one integration test
proving the proxy also works against genuine SDK traffic (see
tests/fixtures/sdk_server.py).
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable

PROTOCOL_VERSION = "2024-11-05"


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], list[dict[str, Any]]]


class MiniMCPServer:
    def __init__(self, name: str, version: str = "0.1.0") -> None:
        self.name = name
        self.version = version
        self._tools: dict[str, Tool] = {}

    def tool(self, name: str, description: str, input_schema: dict[str, Any]):
        def decorator(fn: Callable[[dict[str, Any]], list[dict[str, Any]]]):
            self._tools[name] = Tool(name, description, input_schema, fn)
            return fn

        return decorator

    def _handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = msg.get("method")
        msg_id = msg.get("id")
        is_notification = "id" not in msg

        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": self.version},
            }
            return None if is_notification else _ok(msg_id, result)

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            tools = [
                {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
                for t in self._tools.values()
            ]
            return None if is_notification else _ok(msg_id, {"tools": tools})

        if method == "tools/call":
            params = msg.get("params") or {}
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            tool = self._tools.get(tool_name)
            if tool is None:
                return None if is_notification else _err(msg_id, -32602, f"unknown tool: {tool_name}")
            try:
                content = tool.handler(arguments)
                return None if is_notification else _ok(msg_id, {"content": content, "isError": False})
            except Exception as exc:
                error_content = [{"type": "text", "text": str(exc)}]
                return None if is_notification else _ok(msg_id, {"content": error_content, "isError": True})

        if method == "ping":
            return None if is_notification else _ok(msg_id, {})

        # Unknown method: reply with JSON-RPC "method not found" for
        # requests, silently ignore unknown notifications -- same as any
        # real MCP server would for a method it doesn't implement.
        return None if is_notification else _err(msg_id, -32601, f"method not found: {method}")

    def serve(self) -> None:
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            response = self._handle(msg)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()


def _ok(msg_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
