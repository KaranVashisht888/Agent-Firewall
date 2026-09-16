"""Proves the proxy is method-agnostic: only tools/call and tools/list are
parsed and recorded, while every other method -- known or not, request or
notification -- still flows through untouched with ids preserved.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_firewall.audit import AuditLog

REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_SERVER = REPO_ROOT / "tests" / "fixtures" / "echo_server.py"


class _ProxyHarness:
    def __init__(self, audit_db: Path):
        self.audit_db = audit_db
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mcp_firewall.cli",
                "run",
                "--server",
                "test_srv",
                "--trust-level",
                "untrusted",
                "--audit-db",
                str(audit_db),
                "--",
                sys.executable,
                str(ECHO_SERVER),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(REPO_ROOT),
            bufsize=0,
        )

    def send(self, msg: dict) -> None:
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def recv(self, timeout: float = 5.0) -> dict:
        import threading

        result: dict = {}
        exc: list = []

        def _read():
            try:
                line = self.proc.stdout.readline()
                result["line"] = line
            except Exception as e:  # pragma: no cover
                exc.append(e)

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive() or "line" not in result:
            raise TimeoutError("no response from proxy within timeout")
        return json.loads(result["line"].decode("utf-8"))

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


@pytest.fixture
def harness(tmp_path):
    h = _ProxyHarness(tmp_path / "audit.db")
    yield h
    h.close()


def test_unknown_method_is_forwarded_and_id_preserved(harness):
    harness.send({"jsonrpc": "2.0", "id": "req-1", "method": "some/future/method", "params": {"x": 1}})
    response = harness.recv()
    assert response["id"] == "req-1"
    assert response["result"]["echoed_method"] == "some/future/method"
    assert response["result"]["echoed_params"] == {"x": 1}


def test_numeric_and_string_ids_both_preserved(harness):
    harness.send({"jsonrpc": "2.0", "id": 42, "method": "ping", "params": {}})
    response = harness.recv()
    assert response["id"] == 42

    harness.send({"jsonrpc": "2.0", "id": "abc-def", "method": "ping", "params": {}})
    response = harness.recv()
    assert response["id"] == "abc-def"


def test_notification_with_no_id_produces_no_response_and_no_crash(harness):
    harness.send({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 0.5}})
    # Follow with a real request; if the notification broke anything this will time out.
    harness.send({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
    response = harness.recv()
    assert response["id"] == 1


def test_cancellation_notification_is_forwarded_silently(harness):
    harness.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}})
    harness.send({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
    response = harness.recv()
    assert response["id"] == 2


def test_tools_call_and_tools_list_are_logged_but_other_methods_are_not(harness):
    harness.send({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    harness.recv()

    harness.send(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_doc", "arguments": {"path": "notes.txt"}},
        }
    )
    harness.recv()

    harness.send({"jsonrpc": "2.0", "id": 3, "method": "some/other/method", "params": {}})
    harness.recv()

    harness.send({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    harness.send({"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {}})
    harness.recv()

    harness.close()

    audit = AuditLog(harness.audit_db)
    rows = audit.all_rows()
    audit.close()

    methods_logged = {r["method"] for r in rows}
    assert methods_logged == {"tools/list", "tools/call"}

    call_rows = [r for r in rows if r["method"] == "tools/call"]
    assert any(r["direction"] == "request" and r["tool_name"] == "read_doc" for r in call_rows)
    assert any(r["direction"] == "response" for r in call_rows)
