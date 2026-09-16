"""Shared helper for opening a SQLite connection that several mcp-firewall
processes point at the same file.

Each downstream server runs behind its own `mcp-firewall run` process, and
each of those processes opens its own connection (AuditLog, LabelStore,
DetectorStore) to the same audit-db file at roughly the same moment during
startup. The first `PRAGMA journal_mode=WAL` and schema creation on a given
file can transiently collide with another process doing the same thing --
`timeout=` on connect() does not fully cover this window on every platform
-- so this retries a "database is locked" error a few times with a short
backoff rather than letting a startup race kill the whole process.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path


def connect_with_schema(
    path: str | Path,
    schema: str,
    *,
    timeout: float = 30,
    retries: int = 25,
    retry_delay: float = 0.05,
) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=timeout)
    conn.row_factory = sqlite3.Row

    last_error: sqlite3.OperationalError | None = None
    for _ in range(retries):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(schema)
            conn.commit()
            return conn
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if "locked" not in message and "busy" not in message:
                raise
            last_error = exc
            time.sleep(retry_delay)

    assert last_error is not None
    raise last_error
