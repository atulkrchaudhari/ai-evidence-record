"""Append records to a log and verify a log end to end."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import CanonicalizationError, strict_loads
from .record import GENESIS_HASH, build_record, compute_record_hash, validate_record

# Finding codes. Codes starting with E fail verification. W codes are warnings.
E_PARSE = "E_PARSE"
E_SCHEMA = "E_SCHEMA"
E_CHAIN_ID = "E_CHAIN_ID"
E_SEQUENCE = "E_SEQUENCE"
E_PREV_HASH = "E_PREV_HASH"
E_RECORD_HASH = "E_RECORD_HASH"
E_DUPLICATE_ID = "E_DUPLICATE_ID"
E_CHECKPOINT = "E_CHECKPOINT"
E_SIGNATURE = "E_SIGNATURE"
W_TIMESTAMP_ORDER = "W_TIMESTAMP_ORDER"
W_UNSIGNED_CHECKPOINT = "W_UNSIGNED_CHECKPOINT"
W_NO_CHECKPOINT = "W_NO_CHECKPOINT"


@dataclass(frozen=True)
class Finding:
    code: str
    message: str
    line: int | None = None

    @property
    def is_error(self) -> bool:
        return self.code.startswith("E_")

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "line": self.line, "message": self.message}


@dataclass
class VerificationResult:
    records: int = 0
    chain_id: str | None = None
    head: str | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.is_error for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records": self.records,
            "chain_id": self.chain_id,
            "head": self.head,
            "findings": [f.to_dict() for f in self.findings],
        }


def _fraction_key(timestamp: str) -> tuple[str, str]:
    """Split a validated timestamp so that it compares correctly as a pair."""
    seconds, _, fraction = timestamp[:-1].partition(".")
    return seconds, fraction.ljust(9, "0")


def verify_records(lines: list[str]) -> VerificationResult:
    """Verify the records of one chain, given as JSON Lines."""
    result = VerificationResult()
    expected_prev = GENESIS_HASH
    expected_sequence = 0
    previous_timestamp: tuple[str, str] | None = None
    seen_ids: set[str] = set()

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            result.findings.append(Finding(E_PARSE, "blank line inside the log", number))
            continue
        try:
            record = strict_loads(line)
        except CanonicalizationError as exc:
            result.findings.append(Finding(E_PARSE, str(exc), number))
            continue

        errors = validate_record(record)
        if errors:
            result.findings.extend(Finding(E_SCHEMA, e, number) for e in errors)
            # Without a well-formed record the chain state cannot be advanced safely.
            if not isinstance(record, dict) or not isinstance(record.get("record_hash"), str):
                continue

        if result.chain_id is None and isinstance(record.get("chain_id"), str):
            result.chain_id = record["chain_id"]
        elif record.get("chain_id") != result.chain_id:
            result.findings.append(Finding(E_CHAIN_ID, "chain_id differs from the first record", number))

        if record.get("sequence") != expected_sequence:
            result.findings.append(
                Finding(E_SEQUENCE, f"expected sequence {expected_sequence}, found {record.get('sequence')!r}", number)
            )
        if record.get("prev_hash") != expected_prev:
            result.findings.append(Finding(E_PREV_HASH, "prev_hash does not match the preceding record", number))

        try:
            actual = compute_record_hash(record)
        except CanonicalizationError as exc:
            result.findings.append(Finding(E_RECORD_HASH, f"record cannot be canonicalized: {exc}", number))
            actual = None
        if actual is not None and actual != record.get("record_hash"):
            result.findings.append(Finding(E_RECORD_HASH, "record_hash does not match the record content", number))

        record_id = record.get("record_id")
        if isinstance(record_id, str):
            if record_id in seen_ids:
                result.findings.append(Finding(E_DUPLICATE_ID, f"record_id {record_id!r} already used", number))
            seen_ids.add(record_id)

        if not errors:
            current = _fraction_key(record["timestamp"])
            if previous_timestamp is not None and current < previous_timestamp:
                result.findings.append(Finding(W_TIMESTAMP_ORDER, "timestamp is earlier than the preceding record", number))
            previous_timestamp = current

        # Continue from what the file claims, so one fault is reported once
        # instead of cascading down the rest of the log.
        expected_prev = record["record_hash"]
        expected_sequence = (record["sequence"] + 1) if isinstance(record.get("sequence"), int) else expected_sequence + 1
        result.records += 1
        result.head = record["record_hash"]
    return result


def read_lines(path: str | os.PathLike[str]) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def verify_log(path: str | os.PathLike[str], checkpoint: dict[str, Any] | None = None, public_key: Any = None) -> VerificationResult:
    """Verify a log file, optionally against a checkpoint.

    Without a checkpoint, removal of records from the end of the log cannot
    be detected. The result carries a warning to say so.
    """
    from .checkpoint import check_against_checkpoint  # local import avoids a cycle

    lines = read_lines(path)
    result = verify_records(lines)
    if checkpoint is None:
        result.findings.append(Finding(W_NO_CHECKPOINT, "no checkpoint supplied: truncation of the log tail is not detectable"))
    else:
        result.findings.extend(check_against_checkpoint(lines, result, checkpoint, public_key))
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ChainWriter:
    """Appends records to a JSON Lines log.

    One writer per log. The writer keeps the chain head in memory, so two
    writers on the same file would fork the chain. Each append is flushed
    and synced to disk before it returns.
    """

    def __init__(self, path: str | os.PathLike[str], chain_id: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._head = GENESIS_HASH
        self._next = 0
        self.chain_id = chain_id

        if self.path.exists() and self.path.stat().st_size > 0:
            result = verify_records(read_lines(self.path))
            if not result.ok:
                first = next(f for f in result.findings if f.is_error)
                raise ValueError(f"refusing to append to a log that does not verify: line {first.line}: {first.message}")
            if chain_id is not None and chain_id != result.chain_id:
                raise ValueError("chain_id does not match the existing log")
            self.chain_id = result.chain_id
            self._head = result.head or GENESIS_HASH
            self._next = result.records
        elif self.chain_id is None:
            self.chain_id = str(uuid.uuid4())

    @property
    def head(self) -> str:
        return self._head

    @property
    def next_sequence(self) -> int:
        return self._next

    def append(
        self,
        *,
        actor: dict[str, Any],
        event: dict[str, Any],
        decision: dict[str, Any],
        scope: dict[str, Any] | None = None,
        ext: dict[str, Any] | None = None,
        record_id: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        record = build_record(
            chain_id=self.chain_id,
            sequence=self._next,
            record_id=record_id or str(uuid.uuid4()),
            timestamp=timestamp or utc_now(),
            actor=actor,
            event=event,
            decision=decision,
            prev_hash=self._head,
            scope=scope,
            ext=ext,
        )
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self._head = record["record_hash"]
        self._next += 1
        return record
