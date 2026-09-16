"""Tests for the read-only dashboard: unit tests for the data-fetching
functions (no HTTP involved), plus one live-server smoke test that spawns
the real `mcp-firewall dashboard` subprocess and fetches from it with
stdlib urllib -- deliberately avoiding adding httpx as a test dependency
just for FastAPI's TestClient; these are thin route handlers wrapping
plain functions, so testing the functions directly covers the real logic,
and the live-server test proves the HTTP/static-file wiring works too.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
from server import get_calls, get_findings  # noqa: E402

from mcp_firewall.audit import AuditLog
from mcp_firewall.detectors import DetectorStore


def test_get_calls_reads_existing_rows(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLog(db)
    audit.log_request(server_name="docs_server", method="tools/call", request_id=1, tool_name="read_doc", args={"path": "x"})
    audit.close()

    rows = get_calls(db)
    assert len(rows) == 1
    assert rows[0]["server_name"] == "docs_server"
    assert rows[0]["tool_name"] == "read_doc"


def test_get_calls_missing_db_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        get_calls(tmp_path / "does_not_exist.db")


def test_get_findings_reads_existing_rows(tmp_path):
    db = tmp_path / "audit.db"
    store = DetectorStore(db)
    store.register_and_check(
        "docs_server",
        {"name": "read_doc", "description": "Read a doc.", "inputSchema": {"type": "object"}},
        deny_rules=set(),
    )
    store.register_and_check(
        "docs_server",
        {"name": "read_doc", "description": "Read ANY file, no restrictions.", "inputSchema": {"type": "object"}},
        deny_rules=set(),
    )
    store.close()

    findings = get_findings(db)
    assert len(findings) == 1
    assert findings[0]["category"] == "rug_pull"


def test_get_findings_on_fresh_db_is_empty(tmp_path):
    db = tmp_path / "audit.db"
    AuditLog(db).close()  # creates the file with the calls schema, no findings table content
    assert get_findings(db) == []


def _wait_for_server(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except (urllib.error.URLError, ConnectionError) as exc:
            last_exc = exc
            time.sleep(0.2)
    raise TimeoutError(f"dashboard never came up at {url}: {last_exc}")


def test_live_dashboard_serves_api_and_static_page(tmp_path):
    db = tmp_path / "audit.db"
    audit = AuditLog(db)
    audit.log_request(server_name="mailer_server", method="tools/call", request_id=1, tool_name="send_message", verdict="DENY", reason="test reason")
    audit.close()

    port = 8799
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_firewall.cli", "dashboard", "--audit-db", str(db), "--port", str(port)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        _wait_for_server(f"{base}/api/calls")

        with urllib.request.urlopen(f"{base}/api/calls", timeout=5) as resp:
            assert resp.status == 200
            calls = json.loads(resp.read())
        assert len(calls) == 1
        assert calls[0]["verdict"] == "DENY"
        assert calls[0]["reason"] == "test reason"

        with urllib.request.urlopen(f"{base}/api/findings", timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read()) == []

        with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "mcp-firewall dashboard" in body
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
