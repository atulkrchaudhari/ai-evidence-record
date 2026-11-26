import copy
import hashlib
import hmac

import pytest

from aer import GENESIS_HASH, build_record, compute_record_hash, content_digest, validate_record

from .conftest import ACTOR, POLICY


def _record(**overrides):
    fields = {
        "chain_id": "c",
        "sequence": 0,
        "record_id": "r0",
        "timestamp": "2026-01-01T00:00:00Z",
        "actor": ACTOR,
        "event": {"type": "input"},
        "decision": {"verdict": "allow", "policy": POLICY},
        "prev_hash": GENESIS_HASH,
    }
    fields.update(overrides)
    return build_record(**fields)


def test_build_produces_a_valid_record():
    record = _record()
    assert validate_record(record) == []
    assert record["record_hash"] == compute_record_hash(record)


def test_hash_ignores_member_order_but_not_content():
    record = _record()
    shuffled = dict(reversed(list(record.items())))
    assert compute_record_hash(shuffled) == record["record_hash"]
    changed = copy.deepcopy(record)
    changed["decision"]["verdict"] = "block"
    assert compute_record_hash(changed) != record["record_hash"]


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda r: r.pop("actor"), "record.actor: required"),
        (lambda r: r.update(extra=1), "record.extra: unknown member"),
        (lambda r: r.update(spec="aer/9"), "record.spec"),
        (lambda r: r.update(sequence=-1), "record.sequence"),
        (lambda r: r.update(sequence=True), "record.sequence"),
        (lambda r: r.update(timestamp="2026-01-01T00:00:00+05:30"), "record.timestamp"),
        (lambda r: r.update(prev_hash="ABC"), "record.prev_hash"),
        (lambda r: r["actor"].update(principal=""), "record.actor.principal"),
        (lambda r: r["event"].update(type="nope"), "record.event.type"),
        (lambda r: r["event"].update(type="tool_call"), "record.event.tool: required"),
        (lambda r: r["decision"].update(verdict="maybe"), "record.decision.verdict"),
        (lambda r: r["decision"].pop("policy"), "record.decision.policy: required"),
        (lambda r: r.update(scope={"requested": ["a", "a"], "granted": []}), "duplicates"),
        (lambda r: r.update(ext={"Bad Key": 1}), "record.ext.Bad Key"),
        (lambda r: r["event"].update(content_digest={"alg": "md5", "value": "0" * 64}), "content_digest.alg"),
        (lambda r: r["event"].update(content_digest={"alg": "hmac-sha-256", "value": "0" * 64}), "key_id: required"),
        (lambda r: r["event"].update(content_digest={"alg": "sha-256", "value": "0" * 64, "key_id": "k"}), "key_id: not permitted"),
    ],
)
def test_validation_errors(mutate, fragment):
    record = copy.deepcopy(_record())
    mutate(record)
    errors = validate_record(record)
    assert any(fragment in e for e in errors), errors


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda r: r.update(timestamp="2026-01-01T00:00:00Z\n"), "record.timestamp"),
        (lambda r: r.update(timestamp="\u0662\u0660\u0662\u0666-01-01T00:00:00Z"), "record.timestamp"),
        (lambda r: r.update(timestamp="2026-01-01T00:00:00.\uff11Z"), "record.timestamp"),
        (lambda r: r.update(prev_hash="0" * 64 + "\n"), "record.prev_hash"),
        (lambda r: r.update(record_hash=r["record_hash"] + "\n"), "record.record_hash"),
        (lambda r: r["event"].update(content_digest={"alg": "sha-256", "value": "0" * 64 + "\n"}), "content_digest.value"),
        (lambda r: r.update(ext={"acme.id\n": 1}), "record.ext.acme.id"),
    ],
)
def test_patterns_match_the_whole_string_in_ascii(mutate, fragment):
    # A trailing line feed and digits outside ASCII are not part of any permitted form.
    record = copy.deepcopy(_record())
    mutate(record)
    errors = validate_record(record)
    assert any(fragment in e for e in errors), errors


def test_build_refuses_invalid_input():
    with pytest.raises(ValueError):
        _record(event={"type": "tool_call"})


def test_content_digest_plain_and_keyed():
    assert content_digest("abc") == {"alg": "sha-256", "value": hashlib.sha256(b"abc").hexdigest()}
    keyed = content_digest("abc", key=b"k", key_id="k1")
    assert keyed == {"alg": "hmac-sha-256", "value": hmac.new(b"k", b"abc", hashlib.sha256).hexdigest(), "key_id": "k1"}
    with pytest.raises(ValueError):
        content_digest("abc", key=b"k")
