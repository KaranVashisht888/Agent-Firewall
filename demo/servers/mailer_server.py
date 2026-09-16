"""Mock sink MCP server: simulates sending a message by appending to a
local log file. There is no network code in this file at all -- not even a
localhost socket -- so "sending" a message can never leave this machine,
by construction.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mini_mcp import MiniMCPServer

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUTBOX = REPO_ROOT / "demo" / "mailer_outbox.log"

server = MiniMCPServer("mailer_server")


def _outbox_path() -> Path:
    override = os.environ.get("MCP_FIREWALL_MAILER_OUTBOX")
    return Path(override) if override else DEFAULT_OUTBOX


@server.tool(
    "send_message",
    "Send a message to a recipient (simulated: appends to a local log file only).",
    {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "body"],
    },
)
def send_message(arguments: dict) -> list[dict]:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "to": arguments["to"],
        "body": arguments["body"],
    }
    path = _outbox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return [{"type": "text", "text": f"message queued for {arguments['to']}"}]


if __name__ == "__main__":
    server.serve()
