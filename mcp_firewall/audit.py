"""SQLite-backed append-only audit log for tool calls observed by the proxy.

Only `tools/call` and `tools/list` traffic is recorded here -- every other
JSON-RPC method the proxy sees is forwarded without being logged, matching
the method-agnostic pass-through in proxy.py. Multiple `mcp-firewall run`
processes (one per downstream server, as a real MCP host would spawn them)
may point at the same audit.db file concurrently; writes rely on SQLite's
own file locking, and access within a single process is serialised with a
lock since one sqlite3 connection is not safe to share across threads
without one.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_firewall._dbutil import connect_with_schema

SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    server_name TEXT NOT NULL,
    direction TEXT NOT NULL,      -- 'request' | 'response'
    method TEXT,
    request_id TEXT,
    tool_name TEXT,
    args_json TEXT,
    result_json TEXT,
    is_error INTEGER,
    labels_json TEXT,
    verdict TEXT,                 -- 'PASSTHROUGH' until phase 2 adds ALLOW/DENY
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_calls_request_id ON calls(request_id);
CREATE INDEX IF NOT EXISTS idx_calls_server ON calls(server_name);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id_to_text(request_id: Any) -> str | None:
    if request_id is None:
        return None
    return json.dumps(request_id)


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._conn = connect_with_schema(self.path, SCHEMA)

    def log_request(
        self,
        *,
        server_name: str,
        method: str,
        request_id: Any,
        tool_name: str | None = None,
        args: dict | None = None,
        verdict: str = "PASSTHROUGH",
        reason: str | None = None,
        labels: dict | None = None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO calls (ts, server_name, direction, method, request_id, "
                "tool_name, args_json, result_json, is_error, labels_json, verdict, reason) "
                "VALUES (?, ?, 'request', ?, ?, ?, ?, NULL, NULL, ?, ?, ?)",
                (
                    _now(),
                    server_name,
                    method,
                    _id_to_text(request_id),
                    tool_name,
                    json.dumps(args) if args is not None else None,
                    json.dumps(labels) if labels is not None else None,
                    verdict,
                    reason,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def log_response(
        self,
        *,
        server_name: str,
        method: str,
        request_id: Any,
        tool_name: str | None = None,
        result: Any = None,
        is_error: bool = False,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO calls (ts, server_name, direction, method, request_id, "
                "tool_name, args_json, result_json, is_error, labels_json, verdict, reason) "
                "VALUES (?, ?, 'response', ?, ?, ?, NULL, ?, ?, NULL, NULL, NULL)",
                (
                    _now(),
                    server_name,
                    method,
                    _id_to_text(request_id),
                    tool_name,
                    json.dumps(result) if result is not None else None,
                    1 if is_error else 0,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def all_rows(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM calls ORDER BY id ASC"))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
