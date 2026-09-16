"""Taint matching: deciding whether a new tool-call argument was derived
from a previously labelled value.

Exact substring matching is not enough -- a compliant-but-careless agent
will paraphrase, re-case, re-whitespace, or even transport a value through
a reversible encoding (base64, hex, URL-encoding) on the way to a sink. This
module normalises text before comparing, scores overlap with character/word
shingles (n-grams) using a *containment* score rather than symmetric
similarity (we care how much of a short labelled value shows up inside a
possibly much longer argument, not how similar the two strings are overall),
and also tries a handful of common reversible encodings against the
haystack. It has no knowledge of labels, storage, or policy -- pure
string-in, score-out functions, unit tested in isolation.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

_WS_RE = re.compile(r"\s+")
_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX_TOKEN_RE = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")

DEFAULT_CHAR_N = 4
DEFAULT_WORD_N = 3


def normalize(text: str) -> str:
    """Case-fold, Unicode-normalise, and collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = text.casefold()
    text = _WS_RE.sub(" ", text).strip()
    return text


def char_shingles(text: str, n: int = DEFAULT_CHAR_N) -> set[str]:
    if not text:
        return set()
    if len(text) <= n:
        return {text}
    return {text[i : i + n] for i in range(len(text) - n + 1)}


def word_shingles(text: str, n: int = DEFAULT_WORD_N) -> set[str]:
    words = text.split(" ")
    words = [w for w in words if w]
    if not words:
        return set()
    if len(words) <= n:
        return {" ".join(words)}
    return {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)}


def containment_score(needle: str, haystack: str, *, unit: str = "char", n: int | None = None) -> float:
    """Fraction of the needle's shingles that also appear in the haystack.

    Asymmetric on purpose: `needle` is the (usually short) labelled value,
    `haystack` is the (usually longer) candidate argument that may or may
    not contain it, verbatim or paraphrased. 1.0 means every shingle of the
    needle turned up somewhere in the haystack; 0.0 means none did.
    """
    if not needle.strip() or not haystack.strip():
        return 0.0

    if unit == "word":
        shingle_n = n or DEFAULT_WORD_N
        needle_words = [w for w in needle.split(" ") if w]
        if len(needle_words) < shingle_n:
            return 1.0 if needle in haystack else 0.0
        needle_sh = word_shingles(needle, shingle_n)
        hay_sh = word_shingles(haystack, shingle_n)
    else:
        shingle_n = n or DEFAULT_CHAR_N
        if len(needle) < shingle_n:
            return 1.0 if needle in haystack else 0.0
        needle_sh = char_shingles(needle, shingle_n)
        hay_sh = char_shingles(haystack, shingle_n)

    if not needle_sh:
        return 0.0
    return len(needle_sh & hay_sh) / len(needle_sh)


def decode_candidates(haystack: str) -> list[tuple[str, str]]:
    """Return (encoding_name, decoded_text) for plausible encoded substrings
    or transforms found in haystack. Best-effort: anything that fails to
    decode to something plausible is skipped rather than raising.
    """
    candidates: list[tuple[str, str]] = []

    for match in _BASE64_TOKEN_RE.finditer(haystack):
        token = match.group(0)
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
            text = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if text and _is_mostly_printable(text):
            candidates.append(("base64", text))

    for match in _HEX_TOKEN_RE.finditer(haystack):
        token = match.group(0)
        try:
            decoded = bytes.fromhex(token)
            text = decoded.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if text and _is_mostly_printable(text):
            candidates.append(("hex", text))

    if "%" in haystack:
        try:
            unquoted = urllib.parse.unquote(haystack, errors="strict")
        except Exception:
            unquoted = None
        if unquoted and unquoted != haystack:
            candidates.append(("url", unquoted))

    return candidates


def _is_mostly_printable(text: str, threshold: float = 0.9) -> bool:
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable())
    return printable / len(text) >= threshold


@dataclass
class MatchScore:
    score: float
    encoding: str | None  # None means the plain (unencoded) haystack matched best


def best_containment(needle: str, haystack: str, *, unit: str = "char", n: int | None = None) -> MatchScore:
    """Score `needle` against `haystack` directly and against every encoded
    variant of `haystack` this module knows how to try; return the best.
    """
    norm_needle = normalize(needle)
    best = MatchScore(score=containment_score(norm_needle, normalize(haystack), unit=unit, n=n), encoding=None)

    for encoding, decoded in decode_candidates(haystack):
        score = containment_score(norm_needle, normalize(decoded), unit=unit, n=n)
        if score > best.score:
            best = MatchScore(score=score, encoding=encoding)

    return best
