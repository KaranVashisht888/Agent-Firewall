"""Label model and propagation.

Every tool result observed by the proxy is labelled with where it came
from, how much it should be trusted, and whether it looks like a secret.
Because each downstream server runs behind its own `mcp-firewall run`
process (mirroring how a real MCP host spawns one process per server),
labelled spans are persisted to a SQLite table shared by every proxy
instance pointed at the same audit database -- that's how taint tracked in
one process (e.g. inbox_server) is visible when another process (e.g.
mailer_server) evaluates a later call.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_firewall._dbutil import connect_with_schema

from mcp_firewall.labels.matching import best_containment, normalize

DEFAULT_SECRET_PATTERNS = [
    r"CANARY-[A-Z0-9-]+",
    r"AKIA[0-9A-Z]{16}",
    r"sk-[A-Za-z0-9]{20,}",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS label_spans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source_server TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    is_secret INTEGER NOT NULL,
    text TEXT NOT NULL,
    normalized_text TEXT NOT NULL,
    origin_tool TEXT,
    origin_request_id TEXT
);
CREATE TABLE IF NOT EXISTS near_misses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    sink_server TEXT NOT NULL,
    sink_tool TEXT NOT NULL,
    argument_name TEXT,
    span_id INTEGER,
    score REAL NOT NULL,
    encoding TEXT,
    candidate_snippet TEXT,
    needle_snippet TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snippet(text: str, limit: int = 120) -> str:
    text = text.strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True)
class Label:
    source_server: str
    trust_level: str  # "trusted" | "untrusted"
    is_secret: bool


@dataclass(frozen=True)
class SpanMatch:
    span_id: int
    label: Label
    score: float
    encoding: str | None


def detect_secret(text: str, extra_patterns: list[str] | None = None) -> bool:
    patterns = DEFAULT_SECRET_PATTERNS + list(extra_patterns or [])
    return any(re.search(p, text) for p in patterns)


class LabelStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = connect_with_schema(self.path, SCHEMA)

    def add_span(
        self,
        text: str,
        label: Label,
        *,
        origin_tool: str | None = None,
        origin_request_id: Any = None,
    ) -> int:
        if not text or not text.strip():
            return -1
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO label_spans (ts, source_server, trust_level, is_secret, text, "
                "normalized_text, origin_tool, origin_request_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _now(),
                    label.source_server,
                    label.trust_level,
                    1 if label.is_secret else 0,
                    text,
                    normalize(text),
                    origin_tool,
                    str(origin_request_id) if origin_request_id is not None else None,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def find_matches(
        self,
        candidate_text: str,
        *,
        threshold: float,
        near_miss_floor: float = 0.15,
        sink_server: str = "",
        sink_tool: str = "",
        argument_name: str | None = None,
    ) -> list[SpanMatch]:
        """Score `candidate_text` against every stored labelled span, return
        the ones at or above `threshold`, and log everything that scored
        between `near_miss_floor` and `threshold` for later inspection.
        """
        if not candidate_text or not candidate_text.strip():
            return []

        with self._lock:
            spans = list(self._conn.execute("SELECT * FROM label_spans"))

        matches: list[SpanMatch] = []
        near_misses: list[tuple] = []

        for span in spans:
            result = best_containment(span["text"], candidate_text)
            if result.score >= threshold:
                label = Label(span["source_server"], span["trust_level"], bool(span["is_secret"]))
                matches.append(SpanMatch(span["id"], label, result.score, result.encoding))
            elif result.score >= near_miss_floor:
                near_misses.append(
                    (
                        _now(),
                        sink_server,
                        sink_tool,
                        argument_name,
                        span["id"],
                        result.score,
                        result.encoding,
                        _snippet(candidate_text),
                        _snippet(span["text"]),
                    )
                )

        if near_misses:
            with self._lock:
                self._conn.executemany(
                    "INSERT INTO near_misses (ts, sink_server, sink_tool, argument_name, span_id, "
                    "score, encoding, candidate_snippet, needle_snippet) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    near_misses,
                )
                self._conn.commit()

        return matches

    def all_spans(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM label_spans ORDER BY id ASC"))

    def all_near_misses(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM near_misses ORDER BY id ASC"))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
