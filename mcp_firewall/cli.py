"""Command-line entry point for mcp-firewall."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from mcp_firewall.audit import AuditLog
from mcp_firewall.detectors import DENY_CATEGORIES, DetectorEngine, DetectorStore
from mcp_firewall.labels import LabelStore
from mcp_firewall.policy import Policy
from mcp_firewall.proxy import Proxy

REPO_ROOT = Path(__file__).resolve().parent.parent


def _cmd_run(args: argparse.Namespace) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("error: no downstream command given (use: mcp-firewall run --server NAME -- <command> ...)", file=sys.stderr)
        return 2
    audit = AuditLog(args.audit_db)
    label_store = LabelStore(args.audit_db)
    detector_store = DetectorStore(args.audit_db)
    policy = Policy.load(args.policy) if args.policy else None
    detector_engine = DetectorEngine(
        detector_store,
        deny_rules=(set(policy.rules) & DENY_CATEGORIES) if policy else set(),
        warn_threshold=policy.tool_poisoning_warn_threshold if policy else 0.5,
    )
    proxy = Proxy(
        server_name=args.server,
        command=command,
        audit=audit,
        trust_level=args.trust_level,
        policy=policy,
        label_store=label_store,
        detector_engine=detector_engine,
        repo_root=REPO_ROOT,
    )
    try:
        return proxy.run()
    finally:
        audit.close()
        label_store.close()
        detector_store.close()


def _cmd_demo(args: argparse.Namespace) -> int:
    demo_agent = REPO_ROOT / "demo" / "agent.py"
    cmd = [sys.executable, str(demo_agent), "--audit-db", args.audit_db, "--scenario", args.scenario]
    if args.policy:
        cmd += ["--policy", args.policy]
    result = subprocess.run(cmd)
    return result.returncode


def _cmd_report(args: argparse.Namespace) -> int:
    if args.findings:
        return _print_findings(args.audit_db)

    audit = AuditLog(args.audit_db)
    rows = audit.all_rows()
    audit.close()
    if not rows:
        print("(audit log is empty)")
        return 0
    for row in rows:
        summary = row["tool_name"] or row["method"] or ""
        verdict = row["verdict"] or ""
        reason = row["reason"] or ""
        print(f"{row['ts']}  {row['server_name']:<14} {row['direction']:<9} {summary:<20} {verdict:<12} {reason}")
    return 0


def _print_findings(audit_db: str) -> int:
    detector_store = DetectorStore(audit_db)
    findings = detector_store.all_findings()
    detector_store.close()
    if not findings:
        print("(no findings)")
        return 0
    for f in findings:
        tag = "ENFORCED" if f["enforced"] else "logged"
        score = f" score={f['score']:.2f}" if f["score"] is not None else ""
        print(f"{f['ts']}  [{f['severity'].upper():<4}/{tag:<8}] {f['category']:<15} {f['server_name']}.{f['tool_name']}{score}  {f['message']}")
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(REPO_ROOT / "dashboard"))
    import server as dashboard_server  # local import: fastapi/uvicorn only needed for this command

    return dashboard_server.main(["--audit-db", args.audit_db, "--port", str(args.port)])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-firewall")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="wrap a single downstream MCP server as a proxy")
    p_run.add_argument("--server", required=True, help="logical name of the downstream server")
    p_run.add_argument("--trust-level", default="untrusted", choices=["trusted", "untrusted"])
    p_run.add_argument("--audit-db", default="audit.db")
    p_run.add_argument("--policy", default=None, help="path to policy.yaml; omit to run in pass-through-only mode (no DENY)")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="-- <command> <args...> for the real server")
    p_run.set_defaults(func=_cmd_run)

    p_demo = sub.add_parser("demo", help="run the local end-to-end demo against the mock servers")
    p_demo.add_argument("--audit-db", default="audit.db")
    p_demo.add_argument("--policy", default=None, help="path to policy.yaml; omit for firewall-off pass-through")
    p_demo.add_argument("--scenario", default="benign", choices=["benign", "attack"])
    p_demo.set_defaults(func=_cmd_demo)

    p_report = sub.add_parser("report", help="print the audit log")
    p_report.add_argument("--audit-db", default="audit.db")
    p_report.add_argument("--findings", action="store_true", help="print detector findings instead of the call log")
    p_report.set_defaults(func=_cmd_report)

    p_dashboard = sub.add_parser("dashboard", help="serve a read-only HTML dashboard over the audit log (127.0.0.1 only)")
    p_dashboard.add_argument("--audit-db", default="audit.db")
    p_dashboard.add_argument("--port", type=int, default=8765)
    p_dashboard.set_defaults(func=_cmd_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
