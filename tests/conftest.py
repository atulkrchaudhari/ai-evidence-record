from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "test-vectors"

ACTOR = {"principal": "user:alice", "agent": "agent:bot"}
POLICY = {"id": "default", "version": "1"}


@pytest.fixture
def vectors() -> Path:
    return VECTORS


@pytest.fixture
def make_log(tmp_path):
    """Write a small valid log and return (path, writer)."""
    from aer import ChainWriter

    def _make(n: int = 3, name: str = "log.jsonl"):
        writer = ChainWriter(tmp_path / name, chain_id="chain-1")
        for i in range(n):
            writer.append(actor=ACTOR, event={"type": "input"}, decision={"verdict": "allow", "policy": POLICY}, record_id=f"r{i}")
        return tmp_path / name, writer

    return _make
