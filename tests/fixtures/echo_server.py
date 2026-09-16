"""Minimal stdio JSON-RPC responder used only by proxy pass-through tests.

For every request that carries an id it echoes the method and params back
inside the result -- this is enough to prove the proxy forwards arbitrary
methods, including ones it doesn't recognise, without corrupting them.
Notifications (no id) are accepted and produce no response, matching real
JSON-RPC semantics.
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if "id" not in msg:
            continue
        response = {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"echoed_method": msg.get("method"), "echoed_params": msg.get("params")},
        }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
