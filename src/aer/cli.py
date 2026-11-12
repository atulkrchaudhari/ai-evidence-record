"""Command line interface.

    aer verify LOG [--checkpoint FILE] [--public-key FILE] [--json]
    aer checkpoint LOG [--private-key FILE] [--key-id ID] [--out FILE]
    aer keygen --private FILE --public FILE
    aer hash [FILE]

Exit status: 0 the log verifies, 1 verification failed, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .canonical import CanonicalizationError, canonicalize, strict_loads
from .chain import verify_log
from .checkpoint import generate_keypair, key_id_for, load_private_key, load_public_key, make_checkpoint


def _cmd_verify(args: argparse.Namespace) -> int:
    checkpoint = strict_loads(Path(args.checkpoint).read_text(encoding="utf-8")) if args.checkpoint else None
    public_key = load_public_key(Path(args.public_key).read_bytes()) if args.public_key else None
    result = verify_log(args.log, checkpoint, public_key)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        for finding in result.findings:
            where = f"line {finding.line}: " if finding.line else ""
            print(f"{finding.code}  {where}{finding.message}")
        status = "VERIFIED" if result.ok else "FAILED"
        print(f"{status}: {result.records} records, chain {result.chain_id}, head {result.head}")
    return 0 if result.ok else 1


def _cmd_checkpoint(args: argparse.Namespace) -> int:
    result = verify_log(args.log)
    if not result.ok:
        print("the log does not verify, so no checkpoint was issued. Run: aer verify", file=sys.stderr)
        return 1
    private_key = load_private_key(Path(args.private_key).read_bytes()) if args.private_key else None
    checkpoint = make_checkpoint(result, private_key=private_key, key_id=args.key_id)
    text = json.dumps(checkpoint, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_path, public_path = Path(args.private), Path(args.public)
    if private_path.exists() or public_path.exists():
        print("refusing to overwrite an existing key file", file=sys.stderr)
        return 2
    private_pem, public_pem = generate_keypair()
    private_path.touch(mode=0o600)
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    print(f"key_id {key_id_for(load_public_key(public_pem))}")
    return 0


def _cmd_hash(args: argparse.Namespace) -> int:
    text = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    canonical = canonicalize(strict_loads(text))
    print(hashlib.sha256(canonical).hexdigest())
    if args.show:
        print(canonical.decode("utf-8"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aer", description="Verify and anchor AI Evidence Record logs.")
    parser.add_argument("--version", action="version", version=f"aer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a log, optionally against a checkpoint")
    verify.add_argument("log")
    verify.add_argument("--checkpoint", help="checkpoint JSON file")
    verify.add_argument("--public-key", help="Ed25519 public key for a signed checkpoint, as PEM or as a JSON Web Key")
    verify.add_argument("--json", action="store_true", help="machine-readable output")
    verify.set_defaults(func=_cmd_verify)

    checkpoint = sub.add_parser("checkpoint", help="issue a checkpoint for the current head of a log")
    checkpoint.add_argument("log")
    checkpoint.add_argument("--private-key", help="Ed25519 private key (PEM). Omit for an unsigned checkpoint")
    checkpoint.add_argument("--key-id", help="key identifier to record (default: derived from the public key)")
    checkpoint.add_argument("--out", help="write the checkpoint to this file")
    checkpoint.set_defaults(func=_cmd_checkpoint)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 key pair for signing checkpoints")
    keygen.add_argument("--private", required=True)
    keygen.add_argument("--public", required=True)
    keygen.set_defaults(func=_cmd_keygen)

    hash_cmd = sub.add_parser("hash", help="print the SHA-256 of the canonical form of a JSON value")
    hash_cmd.add_argument("file", nargs="?")
    hash_cmd.add_argument("--show", action="store_true", help="also print the canonical form")
    hash_cmd.set_defaults(func=_cmd_hash)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError, RuntimeError, CanonicalizationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
