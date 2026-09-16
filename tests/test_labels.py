from mcp_firewall.labels import DEFAULT_SECRET_PATTERNS, Label, LabelStore, detect_secret


def test_detect_secret_matches_canary_pattern():
    assert detect_secret("here is the key: CANARY-DO-NOT-PANIC-0001") is True


def test_detect_secret_false_for_benign_text():
    assert detect_secret("just a normal status update") is False


def test_detect_secret_extra_patterns_are_unioned_with_defaults():
    assert detect_secret("token abc123token", extra_patterns=[r"abc123token"]) is True
    # defaults still work even when extra patterns are supplied
    assert detect_secret("CANARY-DO-NOT-PANIC-0001", extra_patterns=[r"totally-unrelated"]) is True


def test_default_patterns_nonempty():
    assert len(DEFAULT_SECRET_PATTERNS) > 0


def test_add_span_and_find_exact_match(tmp_path):
    store = LabelStore(tmp_path / "labels.db")
    label = Label(source_server="inbox_server", trust_level="untrusted", is_secret=False)
    store.add_span("please reply to alice@example.local", label, origin_tool="get_email")

    matches = store.find_matches("forwarding: please reply to alice@example.local", threshold=0.6)
    store.close()

    assert len(matches) == 1
    assert matches[0].label == label
    assert matches[0].score == 1.0


def test_find_matches_returns_nothing_for_unrelated_text(tmp_path):
    store = LabelStore(tmp_path / "labels.db")
    label = Label(source_server="inbox_server", trust_level="untrusted", is_secret=False)
    store.add_span("please reply to alice@example.local", label, origin_tool="get_email")

    matches = store.find_matches("completely unrelated content here", threshold=0.6)
    store.close()

    assert matches == []


def test_find_matches_logs_near_misses(tmp_path):
    store = LabelStore(tmp_path / "labels.db")
    label = Label(source_server="inbox_server", trust_level="untrusted", is_secret=False)
    store.add_span("CANARY-DO-NOT-PANIC-0001", label, origin_tool="read_doc")

    # partial overlap: below the match threshold but above the near-miss floor
    matches = store.find_matches(
        "CANARY-DO-NOT-something-totally-different",
        threshold=0.9,
        near_miss_floor=0.1,
    )
    near_misses = store.all_near_misses()
    store.close()

    assert matches == []
    assert len(near_misses) == 1
    assert 0.1 <= near_misses[0]["score"] < 0.9


def test_secret_label_round_trips_through_store(tmp_path):
    store = LabelStore(tmp_path / "labels.db")
    label = Label(source_server="docs_server", trust_level="trusted", is_secret=True)
    store.add_span("API_KEY=CANARY-DO-NOT-PANIC-0001", label, origin_tool="read_doc")

    matches = store.find_matches("forward this: API_KEY=CANARY-DO-NOT-PANIC-0001", threshold=0.6)
    store.close()

    assert len(matches) == 1
    assert matches[0].label.is_secret is True


def test_multiple_processes_share_one_label_store_file(tmp_path):
    db_path = tmp_path / "labels.db"
    writer = LabelStore(db_path)
    writer.add_span(
        "CANARY-DO-NOT-PANIC-0001",
        Label(source_server="docs_server", trust_level="trusted", is_secret=True),
        origin_tool="read_doc",
    )
    writer.close()

    reader = LabelStore(db_path)
    matches = reader.find_matches("CANARY-DO-NOT-PANIC-0001", threshold=0.9)
    reader.close()

    assert len(matches) == 1
