"""Unit tests for docs_server's own sandbox containment -- this must hold
independently of anything mcp_firewall's policy engine checks, since the
mock filesystem tool is required (by the project's safety constraints) to
reject any path outside demo/sandbox/ on its own.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo" / "servers"))
import docs_server  # noqa: E402


def test_relative_path_inside_sandbox_is_allowed():
    result = docs_server._resolve_in_sandbox("demo/sandbox/notes.txt")
    assert result == (docs_server.SANDBOX / "notes.txt").resolve()


def test_parent_traversal_is_rejected():
    with pytest.raises(ValueError, match="traversal"):
        docs_server._resolve_in_sandbox("demo/sandbox/../../fake_secrets_elsewhere.txt")


def test_parent_traversal_targeting_repo_root_file_is_rejected():
    with pytest.raises(ValueError, match="traversal"):
        docs_server._resolve_in_sandbox("../../../../etc/passwd")


def test_absolute_posix_style_path_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        docs_server._resolve_in_sandbox("/etc/passwd")


def test_absolute_windows_style_path_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        docs_server._resolve_in_sandbox("C:/Windows/win.ini")


def test_absolute_windows_style_backslash_path_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        docs_server._resolve_in_sandbox("C:\\Windows\\win.ini")


def test_sibling_directory_with_sandbox_as_string_prefix_does_not_match():
    # "demo/sandbox_evil/x.txt" must NOT be treated as inside demo/sandbox/,
    # even though the string "demo/sandbox" is a literal prefix of
    # "demo/sandbox_evil". This is exactly the bug fnmatch("demo/sandbox*")
    # or a naive str.startswith(str(SANDBOX)) check would fall into.
    with pytest.raises(ValueError, match="escapes sandbox"):
        docs_server._resolve_in_sandbox("demo/sandbox_evil/x.txt")


def test_empty_path_is_rejected():
    with pytest.raises(ValueError):
        docs_server._resolve_in_sandbox("")


def test_symlink_inside_sandbox_pointing_outside_is_rejected(tmp_path):
    outside_target = tmp_path / "outside_secret.txt"
    outside_target.write_text("not in the sandbox", encoding="utf-8")
    link_path = docs_server.SANDBOX / "escape_link.txt"

    try:
        if link_path.exists() or link_path.is_symlink():
            link_path.unlink()
        os.symlink(outside_target, link_path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")

    try:
        with pytest.raises(ValueError, match="escapes sandbox"):
            docs_server._resolve_in_sandbox("demo/sandbox/escape_link.txt")
    finally:
        link_path.unlink(missing_ok=True)


def test_read_doc_rejects_traversal_end_to_end():
    with pytest.raises(ValueError):
        docs_server.read_doc({"path": "demo/sandbox/../fake_secrets_elsewhere.txt"})


def test_read_doc_reads_a_real_sandboxed_file():
    result = docs_server.read_doc({"path": "demo/sandbox/notes.txt"})
    assert "standup" in result[0]["text"].lower()
