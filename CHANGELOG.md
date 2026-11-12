# Changelog

## 0.1.0

First public draft.

- Specification 0.1: record, chain, checkpoint, verification procedure and finding codes.
- Canonical form by RFC 8785 with floating-point numbers excluded.
- Reference implementation in Python: writer, verifier, Ed25519 checkpoints, `aer` command line tool.
- JSON Schemas for records and checkpoints.
- Conformance vectors: 14 canonicalisation cases, 8 rejected inputs, 7 logs and 13 expected verification results.
