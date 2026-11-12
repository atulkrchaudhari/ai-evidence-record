"""Checkpoints: a signed or published statement of a chain's state.

A hash chain proves that records were not changed or reordered. It cannot
prove that nothing was removed from the end, and it cannot stop whoever
holds the log from rewriting all of it. A checkpoint held outside the
log owner's control closes both gaps.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from .canonical import canonicalize, strict_loads
from .chain import (
    E_CHECKPOINT,
    E_SIGNATURE,
    W_UNSIGNED_CHECKPOINT,
    Finding,
    VerificationResult,
    utc_now,
)

CHECKPOINT_SPEC = "aer-checkpoint/0.1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _signing_input(checkpoint: dict[str, Any]) -> bytes:
    return canonicalize({k: v for k, v in checkpoint.items() if k != "signature"})


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("signatures need the 'cryptography' package: pip install 'aer-spec[sign]'") from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def key_id_for(public_key: Any) -> str:
    """Default key identifier: SHA-256 of the raw public key, first 16 hex characters."""
    _, serialization, _, _ = _crypto()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private PEM, public PEM) for a new Ed25519 key."""
    _, serialization, Ed25519PrivateKey, _ = _crypto()
    private = Ed25519PrivateKey.generate()
    return (
        private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )


def load_private_key(pem: bytes) -> Any:
    _, serialization, Ed25519PrivateKey, _ = _crypto()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_public_key(pem: bytes) -> Any:
    _, serialization, _, Ed25519PublicKey = _crypto()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def make_checkpoint(result: VerificationResult, *, private_key: Any = None, key_id: str | None = None, issued_at: str | None = None) -> dict[str, Any]:
    """Create a checkpoint for a log that has just been verified."""
    if not result.ok or result.records == 0 or result.head is None:
        raise ValueError("a checkpoint can only be issued for a non-empty log that verifies")
    checkpoint: dict[str, Any] = {
        "spec": CHECKPOINT_SPEC,
        "chain_id": result.chain_id,
        "sequence": result.records - 1,
        "record_hash": result.head,
        "issued_at": issued_at or utc_now(),
    }
    if private_key is not None:
        checkpoint["signature"] = {
            "alg": "ed25519",
            "key_id": key_id or key_id_for(private_key.public_key()),
            "value": _b64url(private_key.sign(_signing_input(checkpoint))),
        }
    return checkpoint


def validate_checkpoint(checkpoint: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(checkpoint, dict):
        return ["checkpoint: must be an object"]
    required = ("spec", "chain_id", "sequence", "record_hash", "issued_at")
    for name in required:
        if name not in checkpoint:
            errors.append(f"checkpoint.{name}: required member is missing")
    for name in checkpoint:
        if name not in required and name != "signature":
            errors.append(f"checkpoint.{name}: unknown member")
    if checkpoint.get("spec") != CHECKPOINT_SPEC:
        errors.append(f"checkpoint.spec: must be {CHECKPOINT_SPEC!r}")
    sequence = checkpoint.get("sequence")
    if not (isinstance(sequence, int) and not isinstance(sequence, bool) and sequence >= 0):
        errors.append("checkpoint.sequence: must be a non-negative integer")
    signature = checkpoint.get("signature")
    if signature is not None:
        if not isinstance(signature, dict) or set(signature) != {"alg", "key_id", "value"}:
            errors.append("checkpoint.signature: must have exactly alg, key_id and value")
        elif signature["alg"] != "ed25519":
            errors.append("checkpoint.signature.alg: must be 'ed25519'")
    return errors


def check_against_checkpoint(lines: list[str], result: VerificationResult, checkpoint: dict[str, Any], public_key: Any = None) -> list[Finding]:
    """Compare a verified log with a checkpoint and verify the signature if there is one."""
    findings: list[Finding] = []
    errors = validate_checkpoint(checkpoint)
    if errors:
        return [Finding(E_CHECKPOINT, e) for e in errors]

    if checkpoint["chain_id"] != result.chain_id:
        findings.append(Finding(E_CHECKPOINT, "checkpoint is for a different chain"))
        return findings

    sequence = checkpoint["sequence"]
    if sequence >= result.records:
        findings.append(
            Finding(E_CHECKPOINT, f"log ends at sequence {result.records - 1} but the checkpoint covers sequence {sequence}: records are missing")
        )
    else:
        try:
            anchored = strict_loads(lines[sequence]).get("record_hash")
        except Exception:
            anchored = None
        if anchored != checkpoint["record_hash"]:
            findings.append(Finding(E_CHECKPOINT, f"record at sequence {sequence} does not match the checkpoint: history was rewritten", sequence + 1))

    signature = checkpoint.get("signature")
    if signature is None:
        findings.append(Finding(W_UNSIGNED_CHECKPOINT, "checkpoint is unsigned: its integrity depends on where it was stored"))
    elif public_key is None:
        findings.append(Finding(E_SIGNATURE, "checkpoint is signed but no public key was supplied"))
    else:
        invalid_signature = _crypto()[0]
        try:
            public_key.verify(_b64url_decode(signature["value"]), _signing_input(checkpoint))
        except (invalid_signature, ValueError):
            findings.append(Finding(E_SIGNATURE, "checkpoint signature is not valid for the supplied public key"))
    return findings
