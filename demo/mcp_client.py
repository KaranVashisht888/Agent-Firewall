"""A tiny synchronous JSON-RPC-over-stdio client, used by the demo agent (and
later the bench harness) to speak MCP to a subprocess -- normally
`mcp-firewall run ...` wrapping one of the mock servers.
"""
from __future__ import annotations

import json
import subprocess
import threading
from typing import Any


class MCPClientError(RuntimeError):
    pass


class StdioMCPClient:
    def __init__(self, command: list[str], *, cwd: str | None = None) -> None:
        self._proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            bufsize=0,
            cwd=cwd,
        )
        self._next_id = 1
        self._lock = threading.Lock()

    def _write(self, msg: dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self._proc.stdin.flush()

    def _read_response(self) -> dict[str, Any]:
        assert self._proc.stdout is not None
        line = self._proc.stdout.readline()
        if not line:
            raise MCPClientError("downstream process closed stdout unexpectedly")
        return json.loads(line.decode("utf-8"))

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        with self._lock:
            msg_id = self._next_id
            self._next_id += 1
            self._write({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})
            response = self._read_response()
        if response.get("id") != msg_id:
            raise MCPClientError(f"response id mismatch: expected {msg_id}, got {response.get('id')}")
        if "error" in response:
            raise MCPClientError(f"{method} failed: {response['error']}")
        return response.get("result")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self, client_name: str = "mcp-firewall-demo-agent") -> Any:
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "0.1.0"},
            },
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list")
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
