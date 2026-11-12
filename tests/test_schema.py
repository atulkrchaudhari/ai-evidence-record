"""The JSON Schemas and the reference validator must agree."""

import copy
import json

import pytest

from aer import strict_loads, validate_record
from aer.chain import read_lines
from aer.checkpoint import validate_checkpoint

jsonschema = pytest.importorskip("jsonschema")

from .conftest import ROOT  # noqa: E402


def _validator(name):
    schema = json.loads((ROOT / "schema" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


MUTATIONS = [
    lambda r: r.pop("decision"),
    lambda r: r.update(unknown=1),
    lambda r: r.update(spec="aer/0.2"),
    lambda r: r.update(sequence=-1),
    lambda r: r.update(timestamp="yesterday"),
    lambda r: r.update(record_hash="xyz"),
    lambda r: r["actor"].update(agent=""),
    lambda r: r["actor"].update(parent_agent=5),
    lambda r: r["event"].update(type="tool_call") if "tool" not in r["event"] else r["event"].pop("tool"),
    lambda r: r["event"].update(content_digest={"alg": "hmac-sha-256", "value": "0" * 64}),
    lambda r: r["event"].update(content_digest={"alg": "sha-256", "value": "0" * 64, "key_id": "k"}),
    lambda r: r["decision"].update(verdict="deny"),
    lambda r: r["decision"]["policy"].pop("version"),
    lambda r: r.update(scope={"requested": ["a", "a"], "granted": []}),
    lambda r: r.update(scope={"requested": ["a"]}),
    lambda r: r.update(ext={"UPPER": 1}),
    lambda r: r.update(ext=[]),
]


def test_schema_and_validator_agree_on_records(vectors):
    validator = _validator("aer-record-0.1.schema.json")
    records = [strict_loads(line) for line in read_lines(vectors / "valid.jsonl")]
    for record in records:
        assert validate_record(record) == [] and validator.is_valid(record)
    for record in records:
        for mutate in MUTATIONS:
            broken = copy.deepcopy(record)
            mutate(broken)
            assert validate_record(broken), mutate
            assert not validator.is_valid(broken), mutate


def test_schema_and_validator_agree_on_checkpoints(vectors):
    validator = _validator("aer-checkpoint-0.1.schema.json")
    for name in ("checkpoint.json", "checkpoint-unsigned.json"):
        checkpoint = json.loads((vectors / name).read_text(encoding="utf-8"))
        assert validate_checkpoint(checkpoint) == [] and validator.is_valid(checkpoint)
        for change in ({"spec": "x"}, {"sequence": -1}, {"extra": 1}, {"signature": {"alg": "rsa", "key_id": "k", "value": "AA"}}):
            broken = {**checkpoint, **change}
            assert validate_checkpoint(broken) and not validator.is_valid(broken), change
