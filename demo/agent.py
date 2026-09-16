"""The demo's driving "agent" -- what plays the role of the MCP client/host.

IMPORTANT, read before trusting any firewall-off number this agent produces:
by default (`--backend scripted`) this is a deterministic, WORST-CASE
COMPLIANT agent. Starting in the phase that adds attack scenarios, it will
follow any imperative instruction it finds in tool output -- including text
from the untrusted inbox_server -- with no judgement of its own. That makes
it maximally exploitable on purpose: it exists to prove the firewall (an
information-flow control layer) blocks the bad outcome even when the layer
above it (the agent) is fully compliant with an attacker's instructions.

Firewall-off attack "success" with the scripted agent is therefore true by
construction, not an empirical finding about how real agents behave -- it
just confirms the fixture would work if nothing were policing it. The real
measurement of how often an actual model falls for these fixtures is the
optional `--backend ollama` path (a locally-run open model), reported in the
README as a separate table and never conflated with the scripted numbers.

Phase 1 only exercises the benign pass-through path below; the worst-case
instruction-following behaviour and the ollama backend are added when the
attack scenarios and bench harness land.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_client import StdioMCPClient  # noqa: E402

DOCS_SERVER = REPO_ROOT / "demo" / "servers" / "docs_server.py"
INBOX_SERVER = REPO_ROOT / "demo" / "servers" / "inbox_server.py"
MAILER_SERVER = REPO_ROOT / "demo" / "servers" / "mailer_server.py"


def _proxied(server_name: str, trust_level: str, script: Path, audit_db: str) -> StdioMCPClient:
    command = [
        sys.executable,
        "-m",
        "mcp_firewall.cli",
        "run",
        "--server",
        server_name,
        "--trust-level",
        trust_level,
        "--audit-db",
        audit_db,
        "--",
        sys.executable,
        str(script),
    ]
    return StdioMCPClient(command, cwd=str(REPO_ROOT))


def run_scripted_demo(audit_db: str) -> None:
    print(f"[demo] audit log: {audit_db}")

    docs = _proxied("docs_server", "trusted", DOCS_SERVER, audit_db)
    inbox = _proxied("inbox_server", "untrusted", INBOX_SERVER, audit_db)
    mailer = _proxied("mailer_server", "untrusted", MAILER_SERVER, audit_db)

    try:
        for name, client in (("docs_server", docs), ("inbox_server", inbox), ("mailer_server", mailer)):
            client.initialize()
            tools = client.list_tools()
            print(f"[demo] {name}: tools = {[t['name'] for t in tools]}")

        doc_result = docs.call_tool("read_doc", {"path": "notes.txt"})
        print(f"[demo] docs_server.read_doc(notes.txt) -> {doc_result['content'][0]['text']!r}")

        email_list = inbox.call_tool("list_emails")
        print(f"[demo] inbox_server.list_emails() ->\n{email_list['content'][0]['text']}")

        email = inbox.call_tool("get_email", {"id": "1"})
        print(f"[demo] inbox_server.get_email(1) -> {email['content'][0]['text']!r}")

        send_result = mailer.call_tool(
            "send_message",
            {"to": "ops@example.local", "body": "Weekly sync moved to 3pm Thursdays."},
        )
        print(f"[demo] mailer_server.send_message(...) -> {send_result['content'][0]['text']!r}")
    finally:
        docs.close()
        inbox.close()
        mailer.close()

    print("[demo] done. Inspect the run with: mcp-firewall report --audit-db " + audit_db)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the mcp-firewall demo scenario.")
    parser.add_argument("--audit-db", default="audit.db")
    parser.add_argument("--backend", default="scripted", choices=["scripted", "ollama"])
    args = parser.parse_args(argv)

    if args.backend == "ollama":
        print("error: --backend ollama is not implemented yet (added with the bench harness phase)", file=sys.stderr)
        return 2

    run_scripted_demo(args.audit_db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
