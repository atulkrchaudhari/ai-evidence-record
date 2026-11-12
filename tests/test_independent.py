"""Cross-check canonicalisation against an independent RFC 8785 implementation."""

import hashlib
import json
import random
import string

import pytest

from aer import canonicalize, strict_loads
from aer.chain import read_lines

rfc8785 = pytest.importorskip("rfc8785")

ALPHABET = string.ascii_letters + string.digits + ' "\\/\n\t\r\b\f\x00\x1f\x7fé€דּ\U0001f600 ­\U0001d11e中'


def _random_value(rng, depth=0):
    kind = rng.randint(0, 6 if depth < 4 else 3)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        return rng.randint(-(2**53) + 1, 2**53 - 1)
    if kind == 3:
        return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 8)))
    if kind == 4:
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {
        "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 8))): _random_value(rng, depth + 1)
        for _ in range(rng.randint(0, 5))
    }


def test_random_values_match_independent_implementation():
    rng = random.Random(8785)
    for _ in range(20000):
        value = _random_value(rng)
        ours = canonicalize(value)
        assert ours == rfc8785.dumps(value)
        assert canonicalize(strict_loads(ours.decode("utf-8"))) == ours


def test_vector_record_hashes_match_independent_implementation(vectors):
    for line in read_lines(vectors / "valid.jsonl"):
        record = json.loads(line)
        claimed = record.pop("record_hash")
        assert hashlib.sha256(rfc8785.dumps(record)).hexdigest() == claimed
