"""Method-agnostic MCP stdio proxy.

Spawns a downstream MCP server as a subprocess and relays newline-delimited
JSON-RPC 2.0 messages between the real client (this process's stdin/stdout)
and that server byte-for-byte in both directions. Only `tools/call` and
`tools/list` messages are parsed and recorded in the audit log; every other
method -- including methods this proxy has never heard of, notifications,
progress updates, and cancellations -- is forwarded verbatim, with the
original bytes and request id completely untouched. This is deliberate:
re-serialising every message would risk silently breaking a real client
that depends on exact framing, and would require this proxy to know about
every current and future MCP method to stay transparent.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any

from mcp_firewall.audit import AuditLog

INSPECTED_METHODS = {"tools/call", "tools/list"}


def _id_key(request_id: Any) -> str:
    return json.dumps(request_id)


class Proxy:
    def __init__(
        self,
        *,
        server_name: str,
        command: list[str],
        audit: AuditLog,
        trust_level: str = "untrusted",
        stderr_to_devnull: bool = True,
    ) -> None:
        self.server_name = server_name
        self.command = command
        self.audit = audit
        self.trust_level = trust_level
        self._stderr_to_devnull = stderr_to_devnull
        self._pending: dict[str, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._proc: subprocess.Popen | None = None

    def run(self) -> int:
        """Blocks until the downstream server exits or the client's stdin closes."""
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if self._stderr_to_devnull else None,
            bufsize=0,
        )
        assert self._proc.stdin is not None and self._proc.stdout is not None

        t_to_server = threading.Thread(
            target=self._pump,
            args=(sys.stdin.buffer, self._proc.stdin, "to_server"),
            daemon=True,
        )
        t_to_client = threading.Thread(
            target=self._pump,
            args=(self._proc.stdout, sys.stdout.buffer, "to_client"),
            daemon=True,
        )
        t_to_server.start()
        t_to_client.start()

        self._proc.wait()
        t_to_server.join(timeout=1)
        t_to_client.join(timeout=1)
        return self._proc.returncode or 0

    def _pump(self, src, dst, direction: str) -> None:
        try:
            while True:
                line = src.readline()
                if not line:
                    break
                self._observe(line, direction)
                try:
                    dst.write(line)
                    dst.flush()
                except (BrokenPipeError, ValueError, OSError):
                    break
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    def _observe(self, raw_line: bytes, direction: str) -> None:
        stripped = raw_line.strip()
        if not stripped:
            return
        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            return  # not a JSON-RPC message; forward untouched, don't inspect
        if not isinstance(msg, dict):
            return

        if direction == "to_server":
            self._observe_outgoing(msg)
        else:
            self._observe_incoming(msg)

    def _observe_outgoing(self, msg: dict) -> None:
        method = msg.get("method")
        if method not in INSPECTED_METHODS:
            return
        request_id = msg.get("id")
        params = msg.get("params") or {}
        tool_name = params.get("name") if method == "tools/call" else None
        args = params.get("arguments") if method == "tools/call" else None

        if request_id is not None:
            with self._pending_lock:
                self._pending[_id_key(request_id)] = {"method": method, "tool_name": tool_name}

        self.audit.log_request(
            server_name=self.server_name,
            method=method,
            request_id=request_id,
            tool_name=tool_name,
            args=args,
        )

    def _observe_incoming(self, msg: dict) -> None:
        request_id = msg.get("id")
        if request_id is None:
            return  # notification from the server; we never tagged it as pending
        key = _id_key(request_id)
        with self._pending_lock:
            pending = self._pending.pop(key, None)
        if pending is None:
            return  # response to a method we don't inspect

        is_error = "error" in msg
        result = msg.get("error") if is_error else msg.get("result")
        self.audit.log_response(
            server_name=self.server_name,
            method=pending["method"],
            request_id=request_id,
            tool_name=pending.get("tool_name"),
            result=result,
            is_error=is_error,
        )
