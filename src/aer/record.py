"""Evidence records: construction, validation and hashing."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from .canonical import canonicalize

SPEC = "aer/0.1"
GENESIS_HASH = "0" * 64

EVENT_TYPES = ("input", "context", "output", "tool_call", "memory_write", "system")
VERDICTS = ("allow", "block", "redact", "escalate")
DIGEST_ALGS = ("sha-256", "hmac-sha-256")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$")
_EXT_KEY = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

_TOP_REQUIRED = (
    "spec", "chain_id", "sequence", "record_id", "timestamp",
    "actor", "event", "decision", "prev_hash", "record_hash",
)
_TOP_OPTIONAL = ("scope", "ext")


def content_digest(content: bytes | str, *, key: bytes | None = None, key_id: str | None = None) -> dict[str, str]:
    """Digest content for an evidence record.

    Without a key the digest is plain SHA-256. With a key it is HMAC-SHA-256,
    which stops anyone without the key from confirming a guess at the content.
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    if key is None:
        return {"alg": "sha-256", "value": hashlib.sha256(data).hexdigest()}
    if not key_id:
        raise ValueError("key_id is required with a keyed digest")
    return {"alg": "hmac-sha-256", "value": hmac.new(key, data, hashlib.sha256).hexdigest(), "key_id": key_id}


def compute_record_hash(record: dict[str, Any]) -> str:
    """SHA-256 over the canonical form of the record without ``record_hash``."""
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(canonicalize(body)).hexdigest()


def _is_str(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_members(obj: Any, path: str, required: tuple[str, ...], optional: tuple[str, ...], errors: list[str]) -> bool:
    if not isinstance(obj, dict):
        errors.append(f"{path}: must be an object")
        return False
    for name in required:
        if name not in obj:
            errors.append(f"{path}.{name}: required member is missing")
    for name in obj:
        if name not in required and name not in optional:
            errors.append(f"{path}.{name}: unknown member (use ext for extensions)")
    return True


def _check_digest(obj: Any, path: str, errors: list[str]) -> None:
    if not _check_members(obj, path, ("alg", "value"), ("key_id",), errors):
        return
    alg = obj.get("alg")
    if alg not in DIGEST_ALGS:
        errors.append(f"{path}.alg: must be one of {', '.join(DIGEST_ALGS)}")
    if not (isinstance(obj.get("value"), str) and _HEX64.fullmatch(obj["value"])):
        errors.append(f"{path}.value: must be 64 lowercase hexadecimal characters")
    if alg == "hmac-sha-256" and not _is_str(obj.get("key_id")):
        errors.append(f"{path}.key_id: required with hmac-sha-256")
    if alg == "sha-256" and "key_id" in obj:
        errors.append(f"{path}.key_id: not permitted with sha-256")


def validate_record(record: Any) -> list[str]:
    """Return a list of structural errors. An empty list means the record is well formed.

    This checks structure only. Hashes and chain links are checked by
    :func:`aer.chain.verify_chain`.
    """
    errors: list[str] = []
    if not _check_members(record, "record", _TOP_REQUIRED, _TOP_OPTIONAL, errors):
        return errors

    if "spec" in record and record["spec"] != SPEC:
        errors.append(f"record.spec: must be {SPEC!r}")
    for name in ("chain_id", "record_id"):
        if name in record and not _is_str(record[name]):
            errors.append(f"record.{name}: must be a non-empty string")
    if "sequence" in record and not (_is_int(record["sequence"]) and record["sequence"] >= 0):
        errors.append("record.sequence: must be a non-negative integer")
    if "timestamp" in record and not (isinstance(record["timestamp"], str) and _TIMESTAMP.fullmatch(record["timestamp"])):
        errors.append("record.timestamp: must be RFC 3339 in UTC with a 'Z' suffix")
    for name in ("prev_hash", "record_hash"):
        if name in record and not (isinstance(record[name], str) and _HEX64.fullmatch(record[name])):
            errors.append(f"record.{name}: must be 64 lowercase hexadecimal characters")

    actor = record.get("actor")
    if "actor" in record and _check_members(actor, "record.actor", ("principal", "agent"), ("parent_agent", "model"), errors):
        for name in ("principal", "agent"):
            if name in actor and not _is_str(actor[name]):
                errors.append(f"record.actor.{name}: must be a non-empty string")
        if "parent_agent" in actor and not (actor["parent_agent"] is None or _is_str(actor["parent_agent"])):
            errors.append("record.actor.parent_agent: must be a non-empty string or null")
        if "model" in actor and not _is_str(actor["model"]):
            errors.append("record.actor.model: must be a non-empty string")

    event = record.get("event")
    if "event" in record and _check_members(
        event, "record.event", ("type",), ("content_digest", "source", "tool", "correlation_id"), errors
    ):
        if event.get("type") not in EVENT_TYPES:
            errors.append(f"record.event.type: must be one of {', '.join(EVENT_TYPES)}")
        if "content_digest" in event:
            _check_digest(event["content_digest"], "record.event.content_digest", errors)
        for name in ("source", "correlation_id"):
            if name in event and not _is_str(event[name]):
                errors.append(f"record.event.{name}: must be a non-empty string")
        if "tool" in event and _check_members(event["tool"], "record.event.tool", ("name",), ("arguments_digest",), errors):
            if not _is_str(event["tool"].get("name")):
                errors.append("record.event.tool.name: must be a non-empty string")
            if "arguments_digest" in event["tool"]:
                _check_digest(event["tool"]["arguments_digest"], "record.event.tool.arguments_digest", errors)
        if event.get("type") == "tool_call" and "tool" not in event:
            errors.append("record.event.tool: required when event.type is tool_call")

    decision = record.get("decision")
    if "decision" in record and _check_members(
        decision, "record.decision", ("verdict", "policy"), ("reason", "enforced_by"), errors
    ):
        if decision.get("verdict") not in VERDICTS:
            errors.append(f"record.decision.verdict: must be one of {', '.join(VERDICTS)}")
        for name in ("reason", "enforced_by"):
            if name in decision and not _is_str(decision[name]):
                errors.append(f"record.decision.{name}: must be a non-empty string")
        if "policy" in decision and _check_members(decision["policy"], "record.decision.policy", ("id", "version"), (), errors):
            for name in ("id", "version"):
                if not _is_str(decision["policy"].get(name)):
                    errors.append(f"record.decision.policy.{name}: must be a non-empty string")

    if "scope" in record and _check_members(record["scope"], "record.scope", ("requested", "granted"), (), errors):
        for name in ("requested", "granted"):
            items = record["scope"].get(name)
            if not (isinstance(items, list) and all(_is_str(i) for i in items)):
                errors.append(f"record.scope.{name}: must be an array of non-empty strings")
            elif len(set(items)) != len(items):
                errors.append(f"record.scope.{name}: must not contain duplicates")

    if "ext" in record:
        if not isinstance(record["ext"], dict):
            errors.append("record.ext: must be an object")
        else:
            for key in record["ext"]:
                if not _EXT_KEY.fullmatch(key):
                    errors.append(f"record.ext.{key}: extension names use lowercase letters, digits, '.', '_' and '-'")
    return errors


def build_record(
    *,
    chain_id: str,
    sequence: int,
    record_id: str,
    timestamp: str,
    actor: dict[str, Any],
    event: dict[str, Any],
    decision: dict[str, Any],
    prev_hash: str,
    scope: dict[str, Any] | None = None,
    ext: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a record, compute its hash and validate it."""
    record: dict[str, Any] = {
        "spec": SPEC,
        "chain_id": chain_id,
        "sequence": sequence,
        "record_id": record_id,
        "timestamp": timestamp,
        "actor": actor,
        "event": event,
        "decision": decision,
        "prev_hash": prev_hash,
    }
    if scope is not None:
        record["scope"] = scope
    if ext is not None:
        record["ext"] = ext
    record["record_hash"] = compute_record_hash(record)
    errors = validate_record(record)
    if errors:
        raise ValueError("invalid record: " + "; ".join(errors))
    return record
