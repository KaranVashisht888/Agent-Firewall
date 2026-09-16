from mcp_firewall.audit import AuditLog


def test_log_request_and_response_round_trip(tmp_path):
    db_path = tmp_path / "audit.db"
    audit = AuditLog(db_path)

    audit.log_request(
        server_name="docs_server",
        method="tools/call",
        request_id=1,
        tool_name="read_doc",
        args={"path": "notes.txt"},
    )
    audit.log_response(
        server_name="docs_server",
        method="tools/call",
        request_id=1,
        tool_name="read_doc",
        result={"content": [{"type": "text", "text": "hello"}]},
        is_error=False,
    )

    rows = audit.all_rows()
    audit.close()

    assert len(rows) == 2
    req, resp = rows
    assert req["direction"] == "request"
    assert req["tool_name"] == "read_doc"
    assert req["args_json"] == '{"path": "notes.txt"}'
    assert req["verdict"] == "PASSTHROUGH"

    assert resp["direction"] == "response"
    assert resp["is_error"] == 0
    assert "hello" in resp["result_json"]


def test_ids_of_various_json_types_are_preserved(tmp_path):
    audit = AuditLog(tmp_path / "audit.db")
    for rid in (1, "abc", None):
        audit.log_request(server_name="s", method="tools/list", request_id=rid)
    rows = audit.all_rows()
    audit.close()
    request_ids = [r["request_id"] for r in rows]
    assert request_ids == ["1", '"abc"', None]


def test_concurrent_processes_can_share_one_db_file(tmp_path):
    db_path = tmp_path / "audit.db"
    a = AuditLog(db_path)
    b = AuditLog(db_path)
    a.log_request(server_name="a", method="tools/list", request_id=1)
    b.log_request(server_name="b", method="tools/list", request_id=1)
    rows = a.all_rows()
    a.close()
    b.close()
    assert {r["server_name"] for r in rows} == {"a", "b"}
