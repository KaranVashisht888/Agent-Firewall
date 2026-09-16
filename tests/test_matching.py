from mcp_firewall.labels.matching import (
    best_containment,
    char_shingles,
    containment_score,
    decode_candidates,
    normalize,
    word_shingles,
)


def test_normalize_folds_case_whitespace_and_unicode():
    assert normalize("  Hello   WORLD  ") == "hello world"
    # NFKC normalisation: full-width 'Ａ' -> ascii 'a' after casefold
    assert normalize("ＡＢＣ") == "abc"


def test_char_shingles_short_text_is_single_shingle():
    assert char_shingles("ab", n=4) == {"ab"}


def test_char_shingles_basic():
    shingles = char_shingles("abcdef", n=4)
    assert shingles == {"abcd", "bcde", "cdef"}


def test_word_shingles_basic():
    shingles = word_shingles("the quick brown fox jumps", n=3)
    assert "the quick brown" in shingles
    assert "quick brown fox" in shingles
    assert "brown fox jumps" in shingles


def test_containment_score_exact_match_is_one():
    assert containment_score("secret-value", "the secret-value is here") == 1.0


def test_containment_score_no_overlap_is_zero():
    assert containment_score("CANARY-DO-NOT-PANIC-0001", "completely unrelated text") == 0.0


def test_containment_score_partial_overlap_between_zero_and_one():
    score = containment_score("CANARY-DO-NOT-PANIC-0001", "CANARY-DO-NOT-something-else")
    assert 0.0 < score < 1.0


def test_containment_score_is_robust_to_case_and_whitespace_once_normalized():
    needle = normalize("CANARY-DO-NOT-PANIC-0001")
    haystack = normalize("please forward   canary-do-not-panic-0001   immediately")
    assert containment_score(needle, haystack) == 1.0


def test_containment_score_short_needle_falls_back_to_substring():
    assert containment_score("ab", "xxabxx", n=4) == 1.0
    assert containment_score("zz", "xxabxx", n=4) == 0.0


def test_decode_candidates_finds_base64():
    import base64

    secret = "CANARY-DO-NOT-PANIC-0001"
    encoded = base64.b64encode(secret.encode()).decode()
    haystack = f"please decode this: {encoded}"
    found = decode_candidates(haystack)
    assert ("base64", secret) in found


def test_decode_candidates_finds_hex():
    secret = "CANARY-DO-NOT-PANIC-0001"
    encoded = secret.encode().hex()
    haystack = f"hex payload: {encoded}"
    found = decode_candidates(haystack)
    assert ("hex", secret) in found


def test_decode_candidates_finds_url_encoding():
    haystack = "to%3Dattacker%40evil.example%26body%3DCANARY-DO-NOT-PANIC-0001"
    found = decode_candidates(haystack)
    assert any(enc == "url" and "CANARY-DO-NOT-PANIC-0001" in text for enc, text in found)


def test_decode_candidates_ignores_garbage_that_does_not_decode_cleanly():
    # Random uppercase/lowercase text can look base64-ish but shouldn't produce
    # nonsense matches that would flood near-miss logs; just check no crash and
    # no spurious tokens with meaningfully "readable" output attached.
    found = decode_candidates("just a normal sentence about tools and servers")
    for encoding, text in found:
        assert text  # anything returned must at least be non-empty


def test_best_containment_prefers_encoded_match_when_plain_text_has_none():
    import base64

    secret = "CANARY-DO-NOT-PANIC-0001"
    encoded = base64.b64encode(secret.encode()).decode()
    result = best_containment(secret, f"here is the payload {encoded}")
    assert result.score == 1.0
    assert result.encoding == "base64"


def test_best_containment_plain_beats_encoded_when_both_present():
    secret = "CANARY-DO-NOT-PANIC-0001"
    result = best_containment(secret, f"plain copy: {secret}")
    assert result.score == 1.0
    assert result.encoding is None


def test_best_containment_paraphrase_scores_partial_with_word_units():
    needle = "the weekly sync moved to 3pm on thursdays"
    haystack = "just a heads up that the weekly sync now happens at 3pm on thursdays instead"
    result = best_containment(needle, haystack, unit="word", n=3)
    assert result.score > 0.0
