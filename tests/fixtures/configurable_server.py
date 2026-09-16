"""Test-only stdio MCP-subset server whose tools/list content is driven by
the TEST_TOOLS_JSON environment variable (a JSON list of tool definitions),
so proxy-level detector integration tests can simulate different servers'
tool schemas -- including two "servers" colliding on a tool name, or the
same tool's schema changing between two tools/list calls -- without
spinning up the full demo servers.
"""
from __future__ import annotations

import json
import os
import sys


def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def main() -> None:
    tools = json.loads(os.environ.get("TEST_TOOLS_JSON", "[]"))

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        msg_id = msg.get("id")
        is_notification = "id" not in msg

        if method == "initialize":
            response = _ok(
                msg_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "configurable_test_server", "version": "0.1.0"},
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            response = _ok(msg_id, {"tools": tools})
        elif method == "tools/call":
            response = _ok(msg_id, {"content": [{"type": "text", "text": "ok"}], "isError": False})
        else:
            if is_notification:
                continue
            response = _err(msg_id, -32601, f"method not found: {method}")

        if is_notification:
            continue
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
