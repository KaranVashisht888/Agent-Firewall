"""Static checks on tool metadata (from `tools/list` responses).

Two different confidence tiers, deliberately kept separate:

- **Deny-capable** (deterministic, near-zero false positives): schema
  pinning / rug pull, cross-server tool-name shadowing, and invisible or
  bidi-control Unicode characters in a tool description. Each has its own
  opt-in `deny:` rule in policy.yaml (`rug_pull`, `tool_shadowing`,
  `invisible_chars`); when active, the proxy filters the flagged tool out
  of the `tools/list` result the client sees and refuses any `tools/call`
  to it.
- **Warn-only** (heuristic): imperative-instruction ("tool poisoning")
  patterns in a description. This produces a 0-1 confidence score and the
  matched text, always just logged -- there is deliberately no deny rule
  for it, because legitimate tool descriptions are often imperative too
  ("Call this before fetching user data"), so blocking on it would
  over-block. Tune what surfaces in `mcp-firewall report --findings` with
  policy.yaml's `detectors.warn_threshold`.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_firewall._dbutil import connect_with_schema

DENY_CATEGORIES = {"rug_pull", "tool_shadowing", "invisible_chars"}
WARN_CATEGORIES = {"tool_poisoning"}

_INVISIBLE_UNICODE_CATEGORIES = {"Cf", "Co", "Cs"}  # format, private-use, surrogate
_ALLOWED_CONTROL = {"\n", "\r", "\t"}

# (pattern, weight). Weights are summed and capped at 1.0; tuned so a single
# strong phrase ("ignore previous instructions") already clears a sensible
# default warn_threshold (0.5) on its own, while a lone mildly-imperative
# phrase common in ordinary tool docs does not.
POISONING_PATTERNS: list[tuple[re.Pattern, float]] = [
    (re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.I), 0.7),
    (re.compile(r"disregard (the|your|all|any) (guidelines|rules|policy|instructions)", re.I), 0.7),
    (re.compile(r"do not (tell|inform|mention|notify) the user", re.I), 0.6),
    (re.compile(r"without (asking|confirming|telling|notifying)", re.I), 0.4),
    (re.compile(r"\bsecretly\b", re.I), 0.5),
    (re.compile(r"this is (a |the )?system (administrator|prompt)", re.I), 0.5),
    (re.compile(r"before (calling|using|invoking) any other tool", re.I), 0.4),
    (re.compile(r"send (it|this|the (contents|data|secret|file))\b.{0,40}\bto\b", re.I), 0.4),
    (re.compile(r"\bimmediately\b.{0,20}\bwithout\b", re.I), 0.3),
    (re.compile(r"do this (immediately|now|urgently)", re.I), 0.3),
]


@dataclass(frozen=True)
class Finding:
    category: str  # "rug_pull" | "tool_shadowing" | "invisible_chars" | "tool_poisoning"
    severity: str  # "deny" | "warn"
    server: str
    tool: str
    message: str
    enforced: bool = False
    score: float | None = None
    matched_span: str | None = None


def hash_tool_schema(tool: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema"),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def find_invisible_chars(text: str) -> list[str]:
    """Distinct invisible/format/control characters found in `text` (chars
    a person reading the description would not see, or that can reorder
    how it displays -- zero-width spaces, bidi overrides, BOM, raw control
    bytes -- excluding ordinary newline/tab whitespace).
    """
    found: list[str] = []
    for ch in text or "":
        if ch in _ALLOWED_CONTROL:
            continue
        category = unicodedata.category(ch)
        if category in _INVISIBLE_UNICODE_CATEGORIES or (category == "Cc"):
            if ch not in found:
                found.append(ch)
    return found


def score_tool_poisoning(text: str) -> tuple[float, list[tuple[str, float]]]:
    """Sum the weights of every imperative-instruction pattern that matches
    `text`, capped at 1.0. Returns (score, [(matched_text, weight), ...]).
    """
    if not text:
        return 0.0, []
    matches: list[tuple[str, float]] = []
    total = 0.0
    for pattern, weight in POISONING_PATTERNS:
        m = pattern.search(text)
        if m:
            matches.append((m.group(0), weight))
            total += weight
    return min(total, 1.0), matches


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_registry (
    server_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    schema_hash TEXT NOT NULL,
    description TEXT,
    first_seen_ts TEXT NOT NULL,
    last_seen_ts TEXT NOT NULL,
    flagged INTEGER NOT NULL DEFAULT 0,
    flagged_reason TEXT,
    PRIMARY KEY (server_name, tool_name)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    server_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    message TEXT NOT NULL,
    enforced INTEGER NOT NULL,
    score REAL,
    matched_span TEXT
);
"""


class DetectorStore:
    """SQLite-backed tool registry and findings log, shared across every
    `mcp-firewall run` process pointed at the same audit db -- this is what
    lets a tool name registered by one server's proxy be recognised as
    shadowed when a different server's proxy later registers the same name.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = connect_with_schema(self.path, SCHEMA)

    def register_and_check(self, server_name: str, tool: dict[str, Any], *, deny_rules: set[str]) -> list[Finding]:
        tool_name = tool.get("name", "")
        description = tool.get("description") or ""
        schema_hash = hash_tool_schema(tool)
        now = _now()
        findings: list[Finding] = []

        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tool_registry WHERE server_name=? AND tool_name=?", (server_name, tool_name)
            ).fetchone()

            if row is None:
                self._conn.execute(
                    "INSERT INTO tool_registry (server_name, tool_name, schema_hash, description, "
                    "first_seen_ts, last_seen_ts, flagged, flagged_reason) VALUES (?, ?, ?, ?, ?, ?, 0, NULL)",
                    (server_name, tool_name, schema_hash, description, now, now),
                )
                pinned_hash = schema_hash
            else:
                pinned_hash = row["schema_hash"]
                self._conn.execute(
                    "UPDATE tool_registry SET last_seen_ts=? WHERE server_name=? AND tool_name=?",
                    (now, server_name, tool_name),
                )
            self._conn.commit()

            others = [
                r["server_name"]
                for r in self._conn.execute(
                    "SELECT DISTINCT server_name FROM tool_registry WHERE tool_name=? AND server_name!=?",
                    (tool_name, server_name),
                )
            ]

        if pinned_hash != schema_hash:
            enforced = "rug_pull" in deny_rules
            findings.append(
                Finding(
                    category="rug_pull",
                    severity="deny",
                    server=server_name,
                    tool=tool_name,
                    message=f"schema for '{tool_name}' changed since it was first pinned",
                    enforced=enforced,
                )
            )

        if others:
            enforced = "tool_shadowing" in deny_rules
            findings.append(
                Finding(
                    category="tool_shadowing",
                    severity="deny",
                    server=server_name,
                    tool=tool_name,
                    message=f"tool name '{tool_name}' is also defined by: {', '.join(sorted(others))}",
                    enforced=enforced,
                )
            )

        invisible = find_invisible_chars(description)
        if invisible:
            enforced = "invisible_chars" in deny_rules
            names = ", ".join(f"U+{ord(c):04X}" for c in invisible)
            findings.append(
                Finding(
                    category="invisible_chars",
                    severity="deny",
                    server=server_name,
                    tool=tool_name,
                    message=f"description for '{tool_name}' contains invisible/control characters: {names}",
                    enforced=enforced,
                )
            )

        score, matches = score_tool_poisoning(description)
        if score > 0:
            findings.append(
                Finding(
                    category="tool_poisoning",
                    severity="warn",
                    server=server_name,
                    tool=tool_name,
                    message=f"description for '{tool_name}' contains imperative-instruction language",
                    enforced=False,
                    score=score,
                    matched_span="; ".join(m for m, _ in matches),
                )
            )

        if any(f.enforced for f in findings):
            reasons = "; ".join(f"{f.category}: {f.message}" for f in findings if f.enforced)
            with self._lock:
                self._conn.execute(
                    "UPDATE tool_registry SET flagged=1, flagged_reason=? WHERE server_name=? AND tool_name=?",
                    (reasons, server_name, tool_name),
                )
                self._conn.commit()

        self._log_findings(findings)
        return findings

    def is_blocked(self, server_name: str, tool_name: str) -> Finding | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tool_registry WHERE server_name=? AND tool_name=?", (server_name, tool_name)
            ).fetchone()
        if row is None or not row["flagged"]:
            return None
        return Finding(
            category="flagged",
            severity="deny",
            server=server_name,
            tool=tool_name,
            message=row["flagged_reason"] or "tool is flagged",
            enforced=True,
        )

    def _log_findings(self, findings: list[Finding]) -> None:
        if not findings:
            return
        now = _now()
        with self._lock:
            self._conn.executemany(
                "INSERT INTO findings (ts, category, severity, server_name, tool_name, message, "
                "enforced, score, matched_span) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        now,
                        f.category,
                        f.severity,
                        f.server,
                        f.tool,
                        f.message,
                        1 if f.enforced else 0,
                        f.score,
                        f.matched_span,
                    )
                    for f in findings
                ],
            )
            self._conn.commit()

    def all_findings(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM findings ORDER BY id ASC"))

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class DetectorEngine:
    def __init__(self, store: DetectorStore, *, deny_rules: set[str] | None = None, warn_threshold: float = 0.5) -> None:
        self.store = store
        self.deny_rules = deny_rules or set()
        self.warn_threshold = warn_threshold

    def process_tools_list(self, server_name: str, tools: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[Finding]]:
        """Registers/checks every tool, returns (tools with enforced-deny
        entries filtered out, every finding raised -- enforced or not).
        """
        filtered: list[dict[str, Any]] = []
        all_findings: list[Finding] = []
        for tool in tools:
            findings = self.store.register_and_check(server_name, tool, deny_rules=self.deny_rules)
            all_findings.extend(findings)
            if any(f.enforced for f in findings):
                continue
            filtered.append(tool)
        return filtered, all_findings

    def check_blocked(self, server_name: str, tool_name: str) -> Finding | None:
        return self.store.is_blocked(server_name, tool_name)
