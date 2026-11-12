import hashlib
import json

import pytest

from aer import CanonicalizationError, canonicalize, strict_loads


def test_valid_vectors(vectors):
    cases = json.loads((vectors / "canonicalization.json").read_text(encoding="utf-8"))["valid"]
    assert len(cases) >= 10
    for case in cases:
        canonical = canonicalize(strict_loads(case["input"]))
        assert canonical.decode("utf-8") == case["canonical"], case["name"]
        assert hashlib.sha256(canonical).hexdigest() == case["sha256"], case["name"]


def test_rejected_vectors(vectors):
    for case in json.loads((vectors / "canonicalization.json").read_text(encoding="utf-8"))["rejected"]:
        with pytest.raises(CanonicalizationError):
            canonicalize(strict_loads(case["input"]))


def test_rfc8785_sorting_example():
    # Member order from RFC 8785 section 3.2.3.
    value = {"€": 1, "\r": 2, "דּ": 3, "1": 4, "\U0001f600": 5, "\u0080": 6, "ö": 7}
    order = list(json.loads(canonicalize(value).decode("utf-8")))
    assert order == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


def test_canonical_form_is_idempotent():
    value = {"b": [1, {"d": None, "c": "x"}], "a": "é"}
    once = canonicalize(value)
    assert canonicalize(strict_loads(once.decode("utf-8"))) == once


def test_python_only_types_are_rejected():
    for bad in (1.0, float("nan"), {1: "a"}, {"a": b"bytes"}, {"a": {1, 2}}, 2**53):
        with pytest.raises(CanonicalizationError):
            canonicalize(bad)


def test_booleans_are_not_integers():
    assert canonicalize([True, 1, False, 0]) == b"[true,1,false,0]"
