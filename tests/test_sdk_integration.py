"""Integration test proving the proxy works against a real, official-SDK
based MCP server -- not just our own hand-rolled mini_mcp.py mock servers.
`mcp` is a dev/test-only dependency; mcp_firewall and the demo servers never
import it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_proxy_passthrough import _ProxyHarness  # noqa: E402

from mcp_firewall.audit import AuditLog

REPO_ROOT = Path(__file__).resolve().parent.parent
SDK_SERVER = REPO_ROOT / "tests" / "fixtures" / "sdk_server.py"


class _SDKProxyHarness(_ProxyHarness):
    def __init__(self, audit_db: Path):
        import subprocess
        import sys as _sys

        self.audit_db = audit_db
        self.proc = subprocess.Popen(
            [
                _sys.executable,
                "-m",
                "mcp_firewall.cli",
                "run",
                "--server",
                "sdk_srv",
                "--trust-level",
                "untrusted",
                "--audit-db",
                str(audit_db),
                "--",
                _sys.executable,
                str(SDK_SERVER),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(REPO_ROOT),
            bufsize=0,
        )


@pytest.fixture
def sdk_harness(tmp_path):
    h = _SDKProxyHarness(tmp_path / "audit.db")
    yield h
    h.close()


def test_proxy_relays_real_sdk_initialize_handshake(sdk_harness):
    sdk_harness.send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-firewall-test", "version": "0.1.0"},
            },
        }
    )
    response = sdk_harness.recv()
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "sdk_test_server"
    sdk_harness.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})


def test_proxy_relays_real_sdk_tools_list_and_tools_call(sdk_harness):
    sdk_harness.send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-firewall-test", "version": "0.1.0"},
            },
        }
    )
    sdk_harness.recv()
    sdk_harness.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    sdk_harness.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools_response = sdk_harness.recv()
    tool_names = [t["name"] for t in tools_response["result"]["tools"]]
    assert tool_names == ["add"]

    sdk_harness.send(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 2, "b": 3}},
        }
    )
    call_response = sdk_harness.recv()
    assert call_response["result"]["content"][0]["text"] == "5"

    sdk_harness.close()

    audit = AuditLog(sdk_harness.audit_db)
    rows = audit.all_rows()
    audit.close()

    call_rows = [r for r in rows if r["method"] == "tools/call"]
    assert any(r["direction"] == "request" and r["tool_name"] == "add" for r in call_rows)
    assert any(r["direction"] == "response" and r["is_error"] == 0 for r in call_rows)
