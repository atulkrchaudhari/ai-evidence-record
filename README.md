# AI Evidence Record (AER)

[![CI](https://github.com/atulkrchaudhari/ai-evidence-record/actions/workflows/ci.yml/badge.svg)](https://github.com/atulkrchaudhari/ai-evidence-record/actions/workflows/ci.yml)
![Spec](https://img.shields.io/badge/spec-0.1%20draft-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An open specification for tamper-evident logs of AI agent decisions, with a reference implementation and a verifier.

An AI system blocks a prompt, refuses a tool call or redacts an output. Months later someone asks you to prove it: a customer's security team, an auditor, a regulator. An ordinary log shows what you say happened. AER lets them check that the log is complete and has not been changed.

- **[SPEC.md](SPEC.md)**: the specification
- **[MAPPINGS.md](MAPPINGS.md)**: how it relates to the EU AI Act, MITRE ATLAS and the NIST AI RMF
- **[test-vectors/](test-vectors)**: conformance vectors for other implementations
- **[schema/](schema)**: JSON Schemas for records and checkpoints

**Status: draft 0.1.** The format may change before 1.0. Feedback is the point of publishing it now.

## What it defines

| Piece | What it is |
|---|---|
| **Record** | One decision about one event: who acted, what happened, what the control decided, under which policy version |
| **Chain** | Each record carries the SHA-256 hash of the one before it, so any edit, insertion, removal or reordering is detectable |
| **Checkpoint** | A statement of the chain's state, optionally signed with Ed25519, kept outside the log owner's control |
| **Verification** | A fixed procedure with fixed error codes, so two verifiers agree on the result |

Records carry digests of content, not the content itself. A record can be handed to a third party without handing over prompts or outputs.

## Design choices

- **Canonical JSON by RFC 8785, with floating-point numbers excluded.** Number serialisation is where canonical JSON implementations disagree. AER permits integers only, so any RFC 8785 library produces the right bytes. The reference implementation is checked against an independent RFC 8785 library on 20,000 random values.
- **Strict parsing is part of the format.** Duplicate members and lenient numbers are rejected, because a verifier that accepts them can be shown one record while it hashes another.
- **The limits are stated.** A hash chain cannot detect removal of its last records or a full rewrite by whoever holds it. That is what checkpoints are for, and the verifier warns when none is supplied.
- **No required dependencies.** Writing and verifying chains uses only the Python standard library. Signing checkpoints uses `cryptography`.

## Install

```
pip install git+https://github.com/atulkrchaudhari/ai-evidence-record          # write and verify
pip install "aer-spec[sign] @ git+https://github.com/atulkrchaudhari/ai-evidence-record"   # and sign checkpoints
```

## Write a log

```python
from aer import ChainWriter, content_digest

log = ChainWriter("decisions.jsonl")

log.append(
    actor={"principal": "user:alice", "agent": "agent:support-bot"},
    event={
        "type": "tool_call",
        "tool": {"name": "http_get", "arguments_digest": content_digest('{"url": "https://attacker.example/collect"}')},
        "correlation_id": "req-1001",
    },
    decision={
        "verdict": "block",
        "reason": "destination_not_allowlisted",
        "policy": {"id": "default", "version": "2026-11-01"},
    },
    scope={"requested": ["http_get:attacker.example"], "granted": ["http_get:example.com"]},
)
```

For content that could be guessed, such as a short answer or a card number, use a keyed digest so that holding the record is not enough to confirm a guess:

```python
content_digest(text, key=secret_key, key_id="2026-11")
```

## Verify a log

```
$ aer verify decisions.jsonl
W_NO_CHECKPOINT  no checkpoint supplied: truncation of the log tail is not detectable
VERIFIED: 6 records, chain 3f1c2a9e-..., head 9500630c...
```

Change one field in one record and run it again:

```
$ aer verify test-vectors/tampered-field.jsonl
E_RECORD_HASH  line 3: record_hash does not match the record content
FAILED: 6 records, chain 3f1c2a9e-..., head 9500630c...
```

Exit status is 0 when the log verifies and 1 when it does not, so the command can gate a pipeline. `--json` gives machine-readable output.

## Anchor it with a checkpoint

```
$ aer keygen --private signer.pem --public signer.pub
$ aer checkpoint decisions.jsonl --private-key signer.pem --out checkpoint.json
$ aer verify decisions.jsonl --checkpoint checkpoint.json --public-key signer.pub
```

`--public-key` accepts PEM or a JSON Web Key. Keep the checkpoint, and the signing key, away from whoever administers the log. With a checkpoint the verifier detects the two things a chain alone cannot:

```
$ aer verify test-vectors/truncated.jsonl --checkpoint test-vectors/checkpoint.json --public-key test-vectors/checkpoint-public-key.json
E_CHECKPOINT  log ends at sequence 3 but the checkpoint covers sequence 5: records are missing

$ aer verify test-vectors/rewritten.jsonl --checkpoint test-vectors/checkpoint.json --public-key test-vectors/checkpoint-public-key.json
E_CHECKPOINT  line 6: record at sequence 5 does not match the checkpoint: history was rewritten
```

## What each attack looks like to the verifier

Every row is a file in `test-vectors/` and is asserted in the test suite.

| What was done to the log | Without a checkpoint | With a checkpoint |
|---|---|---|
| One field edited | `E_RECORD_HASH` at that record | Same |
| One field edited and that record's hash recomputed | `E_PREV_HASH` at the next record | Same |
| A record deleted from the middle | `E_SEQUENCE`, `E_PREV_HASH` | Same |
| Two records swapped | `E_SEQUENCE`, `E_PREV_HASH` | Same |
| Records removed from the end | Not detected | `E_CHECKPOINT` |
| Whole log rewritten with consistent hashes | Not detected | `E_CHECKPOINT` |
| Checkpoint edited to match a shorter log | | `E_SIGNATURE` |

## Implementing AER in another language

You need a JSON parser that can reject duplicate members and non-integer numbers, SHA-256, and an RFC 8785 serialiser (or the five rules in [SPEC.md section 5.2](SPEC.md#52-canonical-form)).

1. Check your canonical form against `test-vectors/canonicalization.json`. `aer hash --show` prints the reference output for any JSON value.
2. Run your verifier over the logs listed in `test-vectors/expected.json` and compare the error codes and line numbers.

An implementation that matches both conforms to section 13 of the specification.

## What AER does not do

- It does not decide what your system must log.
- It does not prove a record is true. It proves the record has not changed since it was written.
- It does not make a system compliant with the EU AI Act or anything else. See [MAPPINGS.md](MAPPINGS.md) for what it covers and what stays with you.
- It does not encrypt anything.

## Prior art

AER borrows from well-understood designs and makes no claim to new cryptography: hash-chained logs as used in secure audit logging, signed tree heads from Certificate Transparency (RFC 6962), and JSON canonicalisation from RFC 8785. What it adds is a record vocabulary for AI agent decisions (principal, agent, delegation, event type, verdict, policy version, requested and granted scope) and a conformance suite.

## Development

```
pip install -e ".[dev]"
ruff check .
pytest
python test-vectors/generate.py   # regenerates the vectors. The test suite checks they are reproducible
```

## Contributing

Comments on the specification are as welcome as code. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

MIT. Written and maintained by [Atul Chaudhari](https://github.com/atulkrchaudhari), [AI Prompt Shield](https://aipromptshield.com).
