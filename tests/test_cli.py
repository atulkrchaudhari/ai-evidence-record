import json

from aer.cli import main


def test_verify_exit_codes(vectors, capsys):
    assert main(["verify", str(vectors / "valid.jsonl")]) == 0
    assert "VERIFIED: 6 records" in capsys.readouterr().out
    assert main(["verify", str(vectors / "tampered-field.jsonl")]) == 1
    assert "E_RECORD_HASH  line 3" in capsys.readouterr().out
    assert main(["verify", str(vectors / "missing.jsonl")]) == 2


def test_verify_json_with_checkpoint(vectors, capsys):
    code = main([
        "verify", str(vectors / "truncated.jsonl"), "--json",
        "--checkpoint", str(vectors / "checkpoint.json"),
        "--public-key", str(vectors / "checkpoint-public-key.json"),
    ])
    report = json.loads(capsys.readouterr().out)
    assert code == 1 and report["ok"] is False and report["findings"][0]["code"] == "E_CHECKPOINT"


def test_keygen_checkpoint_verify(make_log, tmp_path, capsys):
    path, _ = make_log(3)
    private, public, checkpoint = tmp_path / "k.pem", tmp_path / "k.pub", tmp_path / "cp.json"
    assert main(["keygen", "--private", str(private), "--public", str(public)]) == 0
    assert main(["keygen", "--private", str(private), "--public", str(public)]) == 2
    assert main(["checkpoint", str(path), "--private-key", str(private), "--out", str(checkpoint)]) == 0
    capsys.readouterr()
    assert main(["verify", str(path), "--checkpoint", str(checkpoint), "--public-key", str(public)]) == 0
    assert "VERIFIED: 3 records" in capsys.readouterr().out


def test_checkpoint_refused_for_a_broken_log(vectors, capsys):
    assert main(["checkpoint", str(vectors / "deleted-record.jsonl")]) == 1


def test_hash_command(tmp_path, capsys):
    source = tmp_path / "v.json"
    source.write_text('{ "b": 1, "a": [true, null] }', encoding="utf-8")
    assert main(["hash", str(source), "--show"]) == 0
    digest, canonical = capsys.readouterr().out.split()
    assert canonical == '{"a":[true,null],"b":1}' and len(digest) == 64
    source.write_text("1.5", encoding="utf-8")
    assert main(["hash", str(source)]) == 2
