"""Runs every scenario in bench/scenarios.yaml twice -- firewall off (no
policy loaded) and firewall on (policy.yaml) -- and emits bench/results.md
with the attack-success-rate and benign-completion/false-positive tables.

Two scenario "kinds":

- flow: a data-flow scenario through the real docs_server/inbox_server/
  mailer_server mock servers, driven by the same scripted worst-case-
  compliant agent logic as demo/agent.py (see its module docstring, and
  the README's "note on the scripted demo agent" -- these are the
  numbers that are true by construction, not an empirical claim about how
  a real model behaves).
- metadata: a tool-metadata scenario (poisoning/shadowing/rug pull) driven
  by tests/fixtures/configurable_server.py, whose tools/list content is
  set per scenario via an env var. Shared with the test suite deliberately
  -- it has no pytest dependency, it is just a small stdio mock server.

Several attack_class labels in scenarios.yaml share an underlying policy
mechanism on purpose: indirect_injection and confused_deputy both trigger
secret_to_sink (their difference is the social-engineering narrative in
the fixture email, not the defensive control being exercised);
cross_server_exfiltration triggers untrusted_to_sink_arg by having the
agent forward the untrusted email's own text (near-verbatim) to an
external recipient -- a short value like a bare email address copied out
of a much longer untrusted message does not, on its own, score high
enough against that longer labelled span to match (see
mcp_firewall/labels/matching.py's containment_score docstring), so a
scenario that actually wants to exercise untrusted_to_sink_arg has to
relay a large-enough chunk of the untrusted content itself.

No real network egress, no real secrets: see demo/fixtures/README.md and
demo/sandbox/fake_secrets.txt.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "demo"))
from mcp_client import MCPClientError, StdioMCPClient  # noqa: E402

SCENARIOS_FILE = REPO_ROOT / "bench" / "scenarios.yaml"
RESULTS_FILE = REPO_ROOT / "bench" / "results.md"
POLICY_FILE = REPO_ROOT / "policy.yaml"

DOCS_SERVER = REPO_ROOT / "demo" / "servers" / "docs_server.py"
INBOX_SERVER = REPO_ROOT / "demo" / "servers" / "inbox_server.py"
MAILER_SERVER = REPO_ROOT / "demo" / "servers" / "mailer_server.py"
CONFIGURABLE_SERVER = REPO_ROOT / "tests" / "fixtures" / "configurable_server.py"
FIXTURES_DIR = REPO_ROOT / "demo" / "fixtures"


def _spawn(server_name: str, trust_level: str, script: Path, audit_db: Path, policy_path: Path | None, extra_env: dict[str, str] | None = None) -> StdioMCPClient:
    command = [
        sys.executable, "-m", "mcp_firewall.cli", "run",
        "--server", server_name,
        "--trust-level", trust_level,
        "--audit-db", str(audit_db),
    ]
    if policy_path:
        command += ["--policy", str(policy_path)]
    command += ["--", sys.executable, str(script)]
    env = {**os.environ, **(extra_env or {})}
    return StdioMCPClient(command, cwd=str(REPO_ROOT), env=env)


def _spawn_configurable(server_name: str, tools: list[dict], audit_db: Path, policy_path: Path | None) -> StdioMCPClient:
    return _spawn(server_name, "untrusted", CONFIGURABLE_SERVER, audit_db, policy_path, extra_env={"TEST_TOOLS_JSON": json.dumps(tools)})


def run_flow_scenario(scenario: dict, policy_path: Path | None, audit_db: Path, outbox_path: Path) -> dict[str, Any]:
    docs = _spawn("docs_server", "trusted", DOCS_SERVER, audit_db, policy_path)
    mailer = _spawn("mailer_server", "untrusted", MAILER_SERVER, audit_db, policy_path, extra_env={"MCP_FIREWALL_MAILER_OUTBOX": str(outbox_path)})
    inbox: StdioMCPClient | None = None
    email_text: str | None = None
    doc_text: str | None = None
    completed = True
    blocked_reason: str | None = None

    try:
        docs.initialize()
        mailer.initialize()

        if scenario.get("fixture"):
            inbox = _spawn("inbox_server", "untrusted", INBOX_SERVER, audit_db, policy_path, extra_env={"MCP_FIREWALL_INBOX_FIXTURE": str(FIXTURES_DIR / scenario["fixture"])})
            inbox.initialize()
            email = inbox.call_tool("get_email", {"id": scenario["email_id"]})
            email_text = email["content"][0]["text"]

        if scenario.get("read_path"):
            doc = docs.call_tool("read_doc", {"path": scenario["read_path"]})
            doc_text = doc["content"][0]["text"]

        body_source = scenario.get("send_body_source")
        if body_source == "secret":
            body = doc_text
        elif body_source == "email":
            body = email_text
        else:
            body = scenario.get("send_body", "")

        try:
            mailer.call_tool("send_message", {"to": scenario["send_to"], "body": body})
        except MCPClientError as exc:
            completed = False
            blocked_reason = str(exc)
    finally:
        docs.close()
        mailer.close()
        if inbox is not None:
            inbox.close()

    return {"completed": completed, "blocked_reason": blocked_reason}


def run_metadata_scenario(scenario: dict, policy_path: Path | None, audit_db: Path) -> dict[str, Any]:
    attack_class = scenario["attack_class"]

    if attack_class == "rug_pull":
        server_name = scenario["server"]
        baseline = _spawn_configurable(server_name, [scenario["tool_before"]], audit_db, policy_path)
        baseline.initialize()
        baseline.list_tools()
        baseline.close()

        client = _spawn_configurable(server_name, [scenario["tool_after"]], audit_db, policy_path)
        client.initialize()
        tools = client.list_tools()
        tool_name = scenario["tool_after"]["name"]

    elif attack_class == "tool_shadowing":
        tool_name = scenario["tool"]["name"]
        legit = _spawn_configurable(scenario["legit_server"], [scenario["tool"]], audit_db, policy_path)
        legit.initialize()
        legit.list_tools()
        legit.close()

        client = _spawn_configurable(scenario["evil_server"], [scenario["tool"]], audit_db, policy_path)
        client.initialize()
        tools = client.list_tools()

    else:  # tool_poisoning
        tool_name = scenario["tool"]["name"]
        client = _spawn_configurable(scenario["server"], [scenario["tool"]], audit_db, policy_path)
        client.initialize()
        tools = client.list_tools()

    exposed = any(t["name"] == tool_name for t in tools)
    blocked = False
    blocked_reason = None
    try:
        client.call_tool(tool_name, {})
    except MCPClientError as exc:
        blocked = True
        blocked_reason = str(exc)
    client.close()

    return {"exposed": exposed, "blocked": blocked, "blocked_reason": blocked_reason}


def run_scenario(scenario: dict, firewall_on: bool, tmp_dir: Path) -> dict[str, Any]:
    policy_path = POLICY_FILE if firewall_on else None
    audit_db = tmp_dir / "audit.db"

    if scenario["kind"] == "flow":
        outbox = tmp_dir / "outbox.log"
        detail = run_flow_scenario(scenario, policy_path, audit_db, outbox)
        succeeded = detail["completed"]
    else:
        detail = run_metadata_scenario(scenario, policy_path, audit_db)
        succeeded = not detail["blocked"]

    return {"succeeded": succeeded, "detail": detail}


def _cleanup_tempdir(path: str) -> None:
    """Retries rmtree on a transient PermissionError before giving up.

    On Windows a just-exited child process's handle on the audit-db file
    (WAL mode creates -wal/-shm siblings too) can take a brief moment to
    actually release after wait() returns -- same underlying class of race
    as the SQLite "database is locked" issue fixed in _dbutil.py. A leftover
    temp directory if every retry fails is harmless; failing the whole bench
    run over it is not worth it.
    """
    for _ in range(10):
        try:
            shutil.rmtree(path)
            return
        except (PermissionError, OSError):
            time.sleep(0.2)
    shutil.rmtree(path, ignore_errors=True)


def run_all(scenarios: list[dict]) -> list[dict]:
    rows = []
    for scenario in scenarios:
        for firewall_on in (False, True):
            td = tempfile.mkdtemp(prefix="mcp-firewall-bench-")
            try:
                outcome = run_scenario(scenario, firewall_on, Path(td))
            finally:
                _cleanup_tempdir(td)
            rows.append(
                {
                    "id": scenario["id"],
                    "kind": scenario["kind"],
                    "type": scenario["type"],
                    "attack_class": scenario.get("attack_class"),
                    "description": scenario["description"],
                    "firewall_on": firewall_on,
                    "succeeded": outcome["succeeded"],
                    "detail": outcome["detail"],
                }
            )
            print(
                f"[bench] {scenario['id']:<45} firewall={'on ' if firewall_on else 'off'}  "
                f"{'SUCCEEDED' if outcome['succeeded'] else 'blocked/failed'}"
            )
    return rows


def _rate(n: int, d: int) -> str:
    if d == 0:
        return "n/a"
    return f"{100 * n / d:.0f}% ({n}/{d})"


def render_results_md(rows: list[dict]) -> str:
    attack_rows = [r for r in rows if r["type"] == "attack"]
    benign_rows = [r for r in rows if r["type"] == "benign"]

    by_class: dict[str, dict[bool, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for r in attack_rows:
        by_class[r["attack_class"]][r["firewall_on"]].append(r)

    n_scenarios = len({r["id"] for r in rows})
    n_attack = len({r["id"] for r in attack_rows})
    n_benign = len({r["id"] for r in benign_rows})

    lines: list[str] = []
    lines.append("# mcp-firewall benchmark results")
    lines.append("")
    lines.append(
        "**Agent backend: scripted (worst-case compliant).** These numbers are "
        "generated by the deterministic scripted agent described in the "
        "README's \"A note on the scripted demo agent\" section: it follows "
        "any instruction embedded in untrusted content literally, with no "
        "judgement of its own. Firewall-off attack success below is "
        "therefore **true by construction** -- it confirms a fixture would "
        "work if nothing were policing it, not an empirical claim about how "
        "a real model behaves."
    )
    lines.append("")
    lines.append(
        "**Ollama backend: not yet implemented.** `demo/agent.py --backend "
        "ollama` is a stub for now (see README). When it lands, its results "
        "will be reported in a separate table here and never combined with "
        "the scripted numbers above."
    )
    lines.append("")
    lines.append(
        f"Generated {datetime.now(timezone.utc).isoformat()} from "
        f"`bench/scenarios.yaml` ({n_scenarios} scenarios: {n_attack} attack, "
        f"{n_benign} benign) via `python bench/run_bench.py`."
    )
    lines.append("")

    lines.append("## Attack scenarios: success rate before/after")
    lines.append("")
    lines.append("| Attack class | Scenarios | Success rate (firewall OFF) | Success rate (firewall ON) |")
    lines.append("| --- | --- | --- | --- |")
    for attack_class in sorted(by_class):
        off = by_class[attack_class][False]
        on = by_class[attack_class][True]
        n = len(off)
        off_n = sum(1 for r in off if r["succeeded"])
        on_n = sum(1 for r in on if r["succeeded"])
        note = " *(warn-only by design -- see note below)*" if attack_class == "tool_poisoning" else ""
        lines.append(f"| {attack_class} | {n} | {_rate(off_n, n)} | {_rate(on_n, n)}{note} |")

    total_n = len({r['id'] for r in attack_rows})
    off_total = sum(1 for r in attack_rows if not r["firewall_on"] and r["succeeded"])
    on_total = sum(1 for r in attack_rows if r["firewall_on"] and r["succeeded"])
    lines.append(f"| **All attack scenarios** | **{total_n}** | **{_rate(off_total, total_n)}** | **{_rate(on_total, total_n)}** |")
    lines.append("")
    lines.append(
        "`tool_poisoning` is deliberately warn-only (see README's \"Static "
        "detectors\" section) -- it can never deny a call, so it is expected "
        "and correct for its success rate to stay unchanged. The attack "
        "instances are still logged as findings, visible via "
        "`mcp-firewall report --findings`, just never blocked."
    )
    lines.append("")
    lines.append(
        "`indirect_injection` and `confused_deputy` trigger the same "
        "`secret_to_sink` policy check -- they differ in the social-"
        "engineering narrative embedded in the fixture email, not in the "
        "defensive control being exercised. `cross_server_exfiltration` "
        "instead triggers `untrusted_to_sink_arg` by having the agent "
        "forward the untrusted email's own text externally."
    )
    lines.append("")

    lines.append("## Benign scenarios: completion rate / false-positive rate before/after")
    lines.append("")
    lines.append("| Scenarios | Completion rate (firewall OFF) | Completion rate (firewall ON) | False-positive rate (firewall ON) |")
    lines.append("| --- | --- | --- | --- |")
    off_benign = [r for r in benign_rows if not r["firewall_on"]]
    on_benign = [r for r in benign_rows if r["firewall_on"]]
    n_b = len(off_benign)
    off_completed = sum(1 for r in off_benign if r["succeeded"])
    on_completed = sum(1 for r in on_benign if r["succeeded"])
    false_positives = n_b - on_completed
    lines.append(f"| {n_b} | {_rate(off_completed, n_b)} | {_rate(on_completed, n_b)} | {_rate(false_positives, n_b)} |")
    lines.append("")

    lines.append("## Per-scenario detail")
    lines.append("")
    lines.append("| id | kind | type | attack_class | firewall OFF | firewall ON |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    by_id: dict[str, dict[bool, dict]] = defaultdict(dict)
    order: list[str] = []
    for r in rows:
        if r["id"] not in by_id:
            order.append(r["id"])
        by_id[r["id"]][r["firewall_on"]] = r
    for scenario_id in order:
        off_r = by_id[scenario_id].get(False)
        on_r = by_id[scenario_id].get(True)
        off_label = "succeeded" if off_r and off_r["succeeded"] else "blocked/failed"
        on_label = "succeeded" if on_r and on_r["succeeded"] else "blocked/failed"
        ref = off_r or on_r
        lines.append(f"| {scenario_id} | {ref['kind']} | {ref['type']} | {ref['attack_class'] or ''} | {off_label} | {on_label} |")
    lines.append("")

    return "\n".join(lines) + "\n"


def main() -> int:
    with open(SCENARIOS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    scenarios = data["scenarios"]

    rows = run_all(scenarios)
    report = render_results_md(rows)
    RESULTS_FILE.write_text(report, encoding="utf-8")
    print(f"[bench] wrote {RESULTS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
