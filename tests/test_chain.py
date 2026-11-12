import json

import pytest

from aer import ChainWriter, verify_log
from aer.chain import read_lines, verify_records

from .conftest import ACTOR, POLICY


def _codes(result):
    return [(f.code, f.line) for f in result.findings if f.is_error]


def test_written_log_verifies(make_log):
    path, writer = make_log(5)
    result = verify_log(path)
    assert result.ok and result.records == 5
    assert result.head == writer.head and result.chain_id == "chain-1"


def test_writer_resumes_an_existing_log(make_log):
    path, first = make_log(2)
    second = ChainWriter(path)
    assert second.head == first.head and second.next_sequence == 2 and second.chain_id == "chain-1"
    second.append(actor=ACTOR, event={"type": "output"}, decision={"verdict": "block", "policy": POLICY})
    assert verify_log(path).ok and verify_log(path).records == 3


def test_writer_refuses_a_broken_log(make_log):
    path, _ = make_log(3)
    lines = read_lines(path)
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not verify"):
        ChainWriter(path)


def test_writer_refuses_a_different_chain_id(make_log):
    path, _ = make_log(1)
    with pytest.raises(ValueError, match="chain_id"):
        ChainWriter(path, chain_id="other")


def test_empty_log_verifies_with_zero_records(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    result = verify_log(path)
    assert result.ok and result.records == 0 and result.head is None


def test_first_record_must_link_to_genesis(make_log):
    path, _ = make_log(3)
    assert _codes(verify_records(read_lines(path)[1:])) == [("E_SEQUENCE", 1), ("E_PREV_HASH", 1)]


def test_parse_faults_are_reported(make_log):
    path, _ = make_log(2)
    lines = read_lines(path)
    duplicate = lines[1][:-1] + ',"spec":"aer/0.1"}'
    result = verify_records([lines[0], "not json", "", duplicate])
    assert [c for c, _ in _codes(result)] == ["E_PARSE", "E_PARSE", "E_PARSE"]


def test_float_anywhere_in_a_record_is_a_parse_fault(make_log):
    path, _ = make_log(1)
    record = json.loads(read_lines(path)[0])
    record["ext"] = {"score": 0.5}
    assert _codes(verify_records([json.dumps(record)])) == [("E_PARSE", 1)]


def test_duplicate_record_id_and_foreign_chain(make_log, tmp_path):
    path, writer = make_log(1)
    writer.append(actor=ACTOR, event={"type": "input"}, decision={"verdict": "allow", "policy": POLICY}, record_id="r0")
    assert ("E_DUPLICATE_ID", 2) in _codes(verify_log(path))

    other = ChainWriter(tmp_path / "other.jsonl", chain_id="chain-2")
    other.append(actor=ACTOR, event={"type": "input"}, decision={"verdict": "allow", "policy": POLICY})
    spliced = verify_records([read_lines(path)[0], read_lines(tmp_path / "other.jsonl")[0]])
    assert ("E_CHAIN_ID", 2) in _codes(spliced)


def test_timestamp_regression_is_a_warning_not_an_error(tmp_path):
    writer = ChainWriter(tmp_path / "t.jsonl", chain_id="c")
    for stamp in ("2026-01-01T00:00:01.5Z", "2026-01-01T00:00:01.25Z"):
        writer.append(actor=ACTOR, event={"type": "input"}, decision={"verdict": "allow", "policy": POLICY}, timestamp=stamp)
    result = verify_log(tmp_path / "t.jsonl")
    assert result.ok and any(f.code == "W_TIMESTAMP_ORDER" and f.line == 2 for f in result.findings)


def test_published_vectors(vectors):
    from aer import load_public_key, strict_loads

    expected = json.loads((vectors / "expected.json").read_text(encoding="utf-8"))
    for case in expected["cases"]:
        checkpoint = strict_loads((vectors / case["checkpoint"]).read_text(encoding="utf-8")) if "checkpoint" in case else None
        key = load_public_key((vectors / case["public_key"]).read_bytes()) if "public_key" in case else None
        result = verify_log(vectors / case["log"], checkpoint, key)
        assert result.ok is case["ok"], case
        assert [[c, line] for c, line in _codes(result)] == case["errors"], case


def test_vectors_are_reproducible(vectors, tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("generate_vectors", vectors / "generate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.generate(tmp_path)
    for produced in tmp_path.iterdir():
        assert produced.read_bytes() == (vectors / produced.name).read_bytes(), produced.name
