# Security policy

## Reporting a vulnerability

Please report privately through the "Report a vulnerability" button on this repository's Security tab. Do not open a public issue.

In scope:

- a way to alter, remove, insert or reorder records that the reference verifier does not report, other than the two cases the specification documents as needing a checkpoint,
- two inputs the reference implementation treats as the same record that a conforming RFC 8785 implementation would hash differently, or the reverse,
- a flaw in checkpoint signing or verification, and
- a fault in the specification that makes any of the above possible for a conforming implementation.

You can expect an acknowledgement within 5 working days.

## Test keys

`test-vectors/` contains a public key and signatures made with an Ed25519 key derived from a published seed, and an HMAC key written in `generate.py`. These are test values. They protect nothing and are not secrets.
