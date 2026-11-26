# Changelog

## Unreleased

- TypeScript verifier started in `ts/`. First module: canonical JSON and strict parsing (`ts/src/canonical.ts`), with no runtime dependencies. It passes the 14 valid and 8 rejected cases in `test-vectors/canonicalization.json`. Chain verification, checkpoints and the command line tool are not written yet.
- TypeScript verifier, second module: record validation, record hash and content digests (`ts/src/record.ts`). Every record in the seven conformance logs validates, and the recomputed hash differs from `record_hash` only on line 3 of `tampered-field.jsonl`, as `test-vectors/expected.json` lists. Validation messages match the Python reference.
- Fix: the Python validator accepted a trailing line feed after a timestamp, a 64-character hash, a digest value or an `ext` member name, and accepted digits outside ASCII in a timestamp. The patterns now match the whole string and ASCII digits only. No conformance vector changes.

## 0.1.0

First public draft.

- Specification 0.1: record, chain, checkpoint, verification procedure and finding codes.
- Canonical form by RFC 8785 with floating-point numbers excluded.
- Reference implementation in Python: writer, verifier, Ed25519 checkpoints, `aer` command line tool.
- JSON Schemas for records and checkpoints.
- Conformance vectors: 14 canonicalisation cases, 8 rejected inputs, 7 logs and 13 expected verification results.
