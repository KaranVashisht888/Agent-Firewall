"""Method-agnostic MCP stdio proxy.

Spawns a downstream MCP server as a subprocess and relays newline-delimited
JSON-RPC 2.0 messages between the real client (this process's stdin/stdout)
and that server. Only `tools/call` and `tools/list` messages are parsed;
every other method -- including methods this proxy has never heard of,
notifications, progress updates, and cancellations -- is forwarded
verbatim, with the original bytes and request id completely untouched.

Within `tools/call`, two things happen beyond Phase 1's plain logging:

- Outgoing requests are checked against the policy (if one is loaded)
  *before* being forwarded to the real server. A denied call never reaches
  the downstream server at all; the proxy synthesises a JSON-RPC error
  response and sends it straight back to the client instead.
- Incoming successful results are labelled (source server, trust level,
  secret-or-not) and persisted to the shared LabelStore, so a later call --
  possibly to a completely different server, hence a different proxy
  process -- can be checked against everything this session has seen so far.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from mcp_firewall.audit import AuditLog
from mcp_firewall.labels import Label, LabelStore, detect_secret
from mcp_firewall.policy import Policy, Verdict

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
        policy: Policy | None = None,
        label_store: LabelStore | None = None,
        repo_root: Path | None = None,
        stderr_to_devnull: bool = True,
    ) -> None:
        self.server_name = server_name
        self.command = command
        self.audit = audit
        self.trust_level = trust_level
        self.policy = policy
        self.label_store = label_store
        self.repo_root = repo_root or Path.cwd()
        self._stderr_to_devnull = stderr_to_devnull
        self._pending: dict[str, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._stdout_lock = threading.Lock()
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
            target=self._pump_to_server, args=(sys.stdin.buffer, self._proc.stdin), daemon=True
        )
        t_to_client = threading.Thread(
            target=self._pump_to_client, args=(self._proc.stdout, sys.stdout.buffer), daemon=True
        )
        t_to_server.start()
        t_to_client.start()

        self._proc.wait()
        t_to_server.join(timeout=1)
        t_to_client.join(timeout=1)
        return self._proc.returncode or 0

    # ---- client -> server -------------------------------------------------

    def _pump_to_server(self, src, dst) -> None:
        try:
            while True:
                line = src.readline()
                if not line:
                    break
                self._handle_outgoing(line, dst)
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    def _handle_outgoing(self, raw_line: bytes, dst) -> None:
        msg = self._parse(raw_line)
        if msg is None:
            self._write(dst, raw_line)
            return

        method = msg.get("method")
        if method == "tools/call":
            self._handle_outgoing_tools_call(msg, dst, raw_line)
            return

        if method == "tools/list":
            request_id = msg.get("id")
            if request_id is not None:
                with self._pending_lock:
                    self._pending[_id_key(request_id)] = {"method": "tools/list", "tool_name": None}
            self.audit.log_request(server_name=self.server_name, method="tools/list", request_id=request_id)

        self._write(dst, raw_line)

    def _handle_outgoing_tools_call(self, msg: dict, dst, raw_line: bytes) -> None:
        request_id = msg.get("id")
        params = msg.get("params") or {}
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}

        verdict = Verdict(True)
        if self.policy is not None and self.label_store is not None:
            verdict = self.policy.evaluate(
                server=self.server_name,
                tool=tool_name,
                arguments=arguments,
                label_store=self.label_store,
                repo_root=self.repo_root,
            )

        self.audit.log_request(
            server_name=self.server_name,
            method="tools/call",
            request_id=request_id,
            tool_name=tool_name,
            args=arguments,
            verdict=verdict.verdict_str,
            reason=verdict.reason,
        )

        if verdict.allow:
            if request_id is not None:
                with self._pending_lock:
                    self._pending[_id_key(request_id)] = {"method": "tools/call", "tool_name": tool_name}
            self._write(dst, raw_line)
        elif request_id is not None:
            self._send_deny_response(request_id, verdict.reason or "denied by policy")

    def _send_deny_response(self, request_id: Any, reason: str) -> None:
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32001, "message": f"mcp-firewall: denied - {reason}"},
        }
        line = (json.dumps(response) + "\n").encode("utf-8")
        with self._stdout_lock:
            try:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass

    # ---- server -> client -------------------------------------------------

    def _pump_to_client(self, src, dst) -> None:
        try:
            while True:
                line = src.readline()
                if not line:
                    break
                self._handle_incoming(line, dst)
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    def _handle_incoming(self, raw_line: bytes, dst) -> None:
        msg = self._parse(raw_line)
        if msg is not None:
            self._observe_incoming(msg)
        with self._stdout_lock:
            self._write(dst, raw_line)

    def _observe_incoming(self, msg: dict) -> None:
        request_id = msg.get("id")
        if request_id is None:
            return
        with self._pending_lock:
            pending = self._pending.pop(_id_key(request_id), None)
        if pending is None:
            return

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

        if pending["method"] == "tools/call" and not is_error and self.label_store is not None:
            self._label_result(pending.get("tool_name"), request_id, result)

    def _label_result(self, tool_name: str | None, request_id: Any, result: Any) -> None:
        if not isinstance(result, dict):
            return
        content = result.get("content") or []
        extra_patterns = self.policy.secret_patterns if self.policy is not None else None
        for block in content:
            if not (isinstance(block, dict) and block.get("type") == "text"):
                continue
            text = block.get("text", "")
            if not text.strip():
                continue
            label = Label(
                source_server=self.server_name,
                trust_level=self.trust_level,
                is_secret=detect_secret(text, extra_patterns),
            )
            self.label_store.add_span(text, label, origin_tool=tool_name, origin_request_id=request_id)

    # ---- shared helpers -----------------------------------------------------

    @staticmethod
    def _parse(raw_line: bytes) -> dict | None:
        stripped = raw_line.strip()
        if not stripped:
            return None
        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        return msg if isinstance(msg, dict) else None

    @staticmethod
    def _write(dst, raw_line: bytes) -> None:
        try:
            dst.write(raw_line)
            dst.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass
