# Changelog

## Unreleased

- TypeScript verifier started in `ts/`. First module: canonical JSON and strict parsing (`ts/src/canonical.ts`), with no runtime dependencies. It passes the 14 valid and 8 rejected cases in `test-vectors/canonicalization.json`. Record hashing, chain verification, checkpoints and the command line tool are not written yet.

## 0.1.0

First public draft.

- Specification 0.1: record, chain, checkpoint, verification procedure and finding codes.
- Canonical form by RFC 8785 with floating-point numbers excluded.
- Reference implementation in Python: writer, verifier, Ed25519 checkpoints, `aer` command line tool.
- JSON Schemas for records and checkpoints.
- Conformance vectors: 14 canonicalisation cases, 8 rejected inputs, 7 logs and 13 expected verification results.
