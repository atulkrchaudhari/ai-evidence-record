import pytest

from aer import generate_keypair, load_private_key, load_public_key, make_checkpoint, verify_log
from aer.chain import read_lines

from .conftest import ACTOR, POLICY


@pytest.fixture
def keys():
    private_pem, public_pem = generate_keypair()
    return load_private_key(private_pem), load_public_key(public_pem)


def _errors(result):
    return [f.code for f in result.findings if f.is_error]


def test_signed_checkpoint_round_trip(make_log, keys):
    path, _ = make_log(4)
    checkpoint = make_checkpoint(verify_log(path), private_key=keys[0])
    assert checkpoint["sequence"] == 3 and checkpoint["signature"]["alg"] == "ed25519"
    assert verify_log(path, checkpoint, keys[1]).ok


def test_log_may_grow_past_a_checkpoint(make_log, keys):
    path, writer = make_log(2)
    checkpoint = make_checkpoint(verify_log(path), private_key=keys[0])
    writer.append(actor=ACTOR, event={"type": "output"}, decision={"verdict": "allow", "policy": POLICY})
    assert verify_log(path, checkpoint, keys[1]).ok


def test_truncation_is_detected_only_with_a_checkpoint(make_log, keys):
    path, _ = make_log(4)
    checkpoint = make_checkpoint(verify_log(path), private_key=keys[0])
    path.write_text("\n".join(read_lines(path)[:2]) + "\n", encoding="utf-8")
    assert verify_log(path).ok
    assert _errors(verify_log(path, checkpoint, keys[1])) == ["E_CHECKPOINT"]


def test_wrong_key_and_missing_key(make_log, keys):
    path, _ = make_log(2)
    checkpoint = make_checkpoint(verify_log(path), private_key=keys[0])
    other = load_public_key(generate_keypair()[1])
    assert _errors(verify_log(path, checkpoint, other)) == ["E_SIGNATURE"]
    assert _errors(verify_log(path, checkpoint)) == ["E_SIGNATURE"]


def test_edited_checkpoint_fails_signature(make_log, keys):
    path, _ = make_log(3)
    checkpoint = make_checkpoint(verify_log(path), private_key=keys[0])
    checkpoint["issued_at"] = "2020-01-01T00:00:00Z"
    assert _errors(verify_log(path, checkpoint, keys[1])) == ["E_SIGNATURE"]


def test_unsigned_checkpoint_warns(make_log):
    path, _ = make_log(2)
    result = verify_log(path, make_checkpoint(verify_log(path)))
    assert result.ok and any(f.code == "W_UNSIGNED_CHECKPOINT" for f in result.findings)


def test_checkpoint_for_another_chain_and_malformed(make_log, keys):
    path, _ = make_log(2)
    checkpoint = make_checkpoint(verify_log(path))
    assert _errors(verify_log(path, {**checkpoint, "chain_id": "other"})) == ["E_CHECKPOINT"]
    assert "E_CHECKPOINT" in _errors(verify_log(path, {"spec": "nope"}))


def test_no_checkpoint_for_an_empty_or_broken_log(tmp_path, make_log):
    empty = tmp_path / "e.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        make_checkpoint(verify_log(empty))
    path, _ = make_log(3)
    lines = read_lines(path)
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        make_checkpoint(verify_log(path))


def test_public_key_as_jwk(make_log, keys, vectors):
    import json

    from aer.checkpoint import public_key_to_jwk

    path, _ = make_log(2)
    checkpoint = make_checkpoint(verify_log(path), private_key=keys[0])
    jwk = public_key_to_jwk(keys[1])
    assert jwk["kid"] == checkpoint["signature"]["key_id"]
    assert verify_log(path, checkpoint, load_public_key(json.dumps(jwk).encode())).ok
    with pytest.raises(ValueError, match="private key"):
        load_public_key(json.dumps({**jwk, "d": "AAAA"}).encode())
    with pytest.raises(ValueError):
        load_public_key(b'{"kty": "RSA"}')
    published = json.loads((vectors / "checkpoint-public-key.json").read_text(encoding="utf-8"))
    assert published["kid"] == json.loads((vectors / "checkpoint.json").read_text(encoding="utf-8"))["signature"]["key_id"]
