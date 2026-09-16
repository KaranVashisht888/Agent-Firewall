"""Mock TRUSTED MCP server: serves text documents from demo/sandbox/ only.

Path containment is enforced here directly, independent of and in addition
to anything mcp-firewall's policy engine does -- this mock filesystem tool
must never be relied on to expose data outside demo/sandbox/, firewall or
not. Path arguments are repo-root-relative (e.g. "demo/sandbox/notes.txt"),
matching the convention policy.yaml's allow_paths globs are written
against; see the note at the top of policy.yaml.
"""
from __future__ import annotations

import re
from pathlib import Path

from mini_mcp import MiniMCPServer

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SANDBOX = (REPO_ROOT / "demo" / "sandbox").resolve()

_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")

server = MiniMCPServer("docs_server")


def _resolve_in_sandbox(rel_path: str) -> Path:
    if not rel_path or not rel_path.strip():
        raise ValueError("empty path")

    # Reject anything that looks rooted or drive-qualified before it ever
    # touches pathlib's join -- `Path("/etc/passwd").is_absolute()` is
    # False on Windows (no drive letter), and `REPO_ROOT / "/etc/passwd"`
    # silently drops REPO_ROOT and keeps only the drive, so these checks
    # can't be replaced by a single is_absolute() call.
    normalized = rel_path.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_PREFIX_RE.match(rel_path) or Path(rel_path).is_absolute():
        raise ValueError(f"absolute paths are not allowed: {rel_path}")

    if ".." in Path(normalized).parts:
        raise ValueError(f"path traversal ('..') is not allowed: {rel_path}")

    # resolve(strict=False) follows any symlinks that do exist along the
    # path (including the final component), so an in-sandbox symlink
    # pointing outside still resolves to its real, out-of-sandbox target
    # here -- the containment check below then rejects it.
    candidate = (REPO_ROOT / rel_path).resolve(strict=False)
    try:
        candidate.relative_to(SANDBOX)
    except ValueError:
        raise ValueError(f"path escapes sandbox, refusing: {rel_path}") from None
    return candidate


@server.tool(
    "read_doc",
    "Read a text document from the sandboxed docs store.",
    {
        "type": "object",
        "properties": {"path": {"type": "string", "description": "path relative to the repo root, e.g. demo/sandbox/notes.txt"}},
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
