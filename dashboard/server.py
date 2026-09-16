"""Read-only FastAPI dashboard over the audit log and detector findings.

Binds to 127.0.0.1 only, by construction: `main()` passes a hardcoded
host to uvicorn and exposes no flag that could change it. The audit db is
opened in SQLite's own explicit read-only mode (`mode=ro`) -- this process
never writes to it, and errors clearly if the file doesn't exist rather
than silently creating an empty one (which AuditLog's normal read-write
open would do).
"""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _read_only_connection(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"audit db not found: {path}")
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _select_all(db_path: str | Path, table: str) -> list[dict[str, Any]]:
    conn = _read_only_connection(db_path)
    try:
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY id ASC").fetchall()
    except sqlite3.OperationalError:
        rows = []  # table doesn't exist yet (e.g. no tools/list observed)
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_calls(db_path: str | Path) -> list[dict[str, Any]]:
    return _select_all(db_path, "calls")


def get_findings(db_path: str | Path) -> list[dict[str, Any]]:
    return _select_all(db_path, "findings")


def create_app(db_path: str | Path) -> FastAPI:
    app = FastAPI(title="mcp-firewall dashboard")

    @app.get("/api/calls")
    def api_calls() -> list[dict[str, Any]]:
        try:
            return get_calls(db_path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/findings")
    def api_findings() -> list[dict[str, Any]]:
        try:
            return get_findings(db_path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only dashboard over an mcp-firewall audit db.")
    parser.add_argument("--audit-db", default="audit.db")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    app = create_app(args.audit_db)
    print(f"[dashboard] serving http://127.0.0.1:{args.port} for {args.audit_db} (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
