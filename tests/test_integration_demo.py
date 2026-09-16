"""Full end-to-end integration test: runs the actual demo CLI (real
subprocesses, real stdio proxying, real SQLite audit/label store) and
asserts the canary never reaches the mock sink when the firewall (policy)
is on, and does reach it when the firewall is off -- proving the "off" run
is a meaningful baseline and not a trivially-always-blocked scenario.

Hermetic: no network, no real MCP servers beyond this repo's own mock
servers, no model.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from mcp_firewall.audit import AuditLog

REPO_ROOT = Path(__file__).resolve().parent.parent
CANARY = "CANARY-DO-NOT-PANIC-0001"


def _run_attack_scenario(tmp_path: Path, *, with_policy: bool) -> tuple[int, str, str, Path]:
    audit_db = tmp_path / "audit.db"
    outbox = REPO_ROOT / "demo" / "mailer_outbox.log"
    if outbox.is_file():
        outbox.unlink()

    cmd = [
        sys.executable,
        "-m",
        "mcp_firewall.cli",
        "demo",
        "--audit-db",
        str(audit_db),
        "--scenario",
        "attack",
    ]
    if with_policy:
        cmd += ["--policy", str(REPO_ROOT / "policy.yaml")]

    result = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr, audit_db


def test_attack_scenario_firewall_off_leaks_the_canary(tmp_path):
    returncode, stdout, stderr, _ = _run_attack_scenario(tmp_path, with_policy=False)
    outbox = REPO_ROOT / "demo" / "mailer_outbox.log"

    assert "LEAKED" in stdout, f"stdout={stdout!r} stderr={stderr!r}"
    assert returncode == 1  # agent.py signals "leaked" with a nonzero exit
    assert outbox.is_file()
    assert CANARY in outbox.read_text(encoding="utf-8")


def test_attack_scenario_firewall_on_blocks_the_canary(tmp_path):
    returncode, stdout, stderr, audit_db = _run_attack_scenario(tmp_path, with_policy=True)
    outbox = REPO_ROOT / "demo" / "mailer_outbox.log"

    assert "BLOCKED" in stdout, f"stdout={stdout!r} stderr={stderr!r}"
    assert returncode == 0
    # The canary must never appear in the sink's log at all when the
    # firewall is on -- not just "not appended this run".
    if outbox.is_file():
        assert CANARY not in outbox.read_text(encoding="utf-8")

    audit = AuditLog(audit_db)
    rows = audit.all_rows()
    audit.close()
    deny_rows = [r for r in rows if r["verdict"] == "DENY"]
    assert len(deny_rows) == 1
    assert deny_rows[0]["tool_name"] == "send_message"
    assert "secret" in deny_rows[0]["reason"].lower()


def test_benign_scenario_still_completes_with_firewall_on(tmp_path):
    audit_db = tmp_path / "audit.db"
    cmd = [
        sys.executable,
        "-m",
        "mcp_firewall.cli",
        "demo",
        "--audit-db",
        str(audit_db),
        "--scenario",
        "benign",
        "--policy",
        str(REPO_ROOT / "policy.yaml"),
    ]
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert "message queued for ops@example.local" in result.stdout

    audit = AuditLog(audit_db)
    rows = audit.all_rows()
    audit.close()
    assert any(r["verdict"] == "DENY" for r in rows) is False
