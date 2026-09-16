"""Mock TRUSTED MCP server: serves text documents from demo/sandbox/ only.

Path containment is enforced here directly, independent of and in addition
to anything mcp-firewall's policy engine does -- this mock filesystem tool
must never be relied on to expose data outside demo/sandbox/, firewall or
not.
"""
from __future__ import annotations

from pathlib import Path

from mini_mcp import MiniMCPServer

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SANDBOX = (REPO_ROOT / "demo" / "sandbox").resolve()

server = MiniMCPServer("docs_server")


def _resolve_in_sandbox(rel_path: str) -> Path:
    candidate = (SANDBOX / rel_path).resolve()
    if candidate != SANDBOX and SANDBOX not in candidate.parents:
        raise ValueError(f"path escapes sandbox, refusing: {rel_path}")
    return candidate


@server.tool(
    "read_doc",
    "Read a text document from the sandboxed docs store.",
    {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "path relative to the sandbox root"}},
        "required": ["path"],
    },
)
def read_doc(arguments: dict) -> list[dict]:
    path = _resolve_in_sandbox(arguments["path"])
    if not path.is_file():
        raise ValueError(f"no such document: {arguments['path']}")
    text = path.read_text(encoding="utf-8")
    return [{"type": "text", "text": text}]


@server.tool(
    "list_docs",
    "List available document names in the sandboxed docs store.",
    {"type": "object", "properties": {}},
)
def list_docs(arguments: dict) -> list[dict]:
    names = sorted(p.name for p in SANDBOX.glob("*.txt"))
    return [{"type": "text", "text": "\n".join(names)}]


if __name__ == "__main__":
    server.serve()
