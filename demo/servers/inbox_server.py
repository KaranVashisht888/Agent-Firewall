"""Mock UNTRUSTED MCP server: returns canned "emails" from a fixture file.

Every email this server returns is inert plain text loaded from
demo/fixtures/*.txt. Nothing here executes anything -- an email body that
contains what looks like an instruction is just a string a downstream tool
call must never be permitted to act on unchecked. See demo/fixtures/README.md.
"""
from __future__ import annotations

import os
from pathlib import Path

from mini_mcp import MiniMCPServer

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "demo" / "fixtures"
DEFAULT_FIXTURE = FIXTURES / "benign_emails.txt"

server = MiniMCPServer("inbox_server")


def _fixture_path() -> Path:
    override = os.environ.get("MCP_FIREWALL_INBOX_FIXTURE")
    return Path(override) if override else DEFAULT_FIXTURE


def _load_emails() -> list[dict]:
    path = _fixture_path()
    if not path.is_file():
        return []
    raw = path.read_text(encoding="utf-8")
    records = [r.strip("\n") for r in raw.split("\n===\n") if r.strip()]
    emails = []
    for record in records:
        headers, _, body = record.partition("\n\n")
        fields = {}
        for line in headers.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                fields[key.strip().lower()] = value.strip()
        emails.append(
            {
                "id": fields.get("id", ""),
                "from": fields.get("from", ""),
                "subject": fields.get("subject", ""),
                "body": body.strip(),
            }
        )
    return emails


@server.tool(
    "list_emails",
    "List emails in the inbox (id, from, subject only).",
    {"type": "object", "properties": {}},
)
def list_emails(arguments: dict) -> list[dict]:
    emails = _load_emails()
    lines = [f"{e['id']}: {e['from']} - {e['subject']}" for e in emails]
    return [{"type": "text", "text": "\n".join(lines)}]


@server.tool(
    "get_email",
    "Fetch the full body of one email by id.",
    {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    },
)
def get_email(arguments: dict) -> list[dict]:
    target = str(arguments["id"])
    for email in _load_emails():
        if email["id"] == target:
            text = f"From: {email['from']}\nSubject: {email['subject']}\n\n{email['body']}"
            return [{"type": "text", "text": text}]
    raise ValueError(f"no such email: {target}")


if __name__ == "__main__":
    server.serve()
