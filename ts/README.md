# AER verifier in TypeScript

A second implementation of the AER verifier, written against [SPEC.md](../SPEC.md) and the conformance vectors in [test-vectors/](../test-vectors). It is being built one module at a time and is not complete.

| Module | Status |
|---|---|
| Canonical JSON and strict parsing (`src/canonical.ts`, SPEC section 5) | Done. Passes all 14 valid and 8 rejected cases in `test-vectors/canonicalization.json` |
| Record validation and record hash (`src/record.ts`, SPEC sections 4 and 5.3) | Done. Every record in the seven conformance logs validates, and the hash differs from `record_hash` only on line 3 of `tampered-field.jsonl`, as `test-vectors/expected.json` lists |
| Chain verification | Not started |
| Checkpoint and Ed25519 signature check | Not started |
| Command line tool | Not started |

It does not yet verify a log. Use the Python reference implementation for that.

## Run the tests

Node.js 22.18 or later runs the TypeScript sources directly, so there is no build step and no runtime dependency.

```
cd ts
node --test
```

To type-check as well:

```
npm install
npm run typecheck
```

## Canonical JSON

```ts
import { canonicalize, strictParse } from "./src/canonical.ts";

const bytes = canonicalize(strictParse('{ "b": 1, "a": [true, null] }'));
// {"a":[true,null],"b":1}
```

`strictParse` is used in place of `JSON.parse` because SPEC section 5.1 requires a verifier to reject input that `JSON.parse` accepts: duplicate members, numbers with a fraction or an exponent, integers outside -(2^53 - 1) to 2^53 - 1, and lone surrogates. Both functions throw `CanonicalizationError`.

## Records

```ts
import { strictParse } from "./src/canonical.ts";
import { computeRecordHash, validateRecord } from "./src/record.ts";

const record = strictParse(line) as Record<string, unknown>;
const errors = validateRecord(record); // [] when the record is well formed
const matches = errors.length === 0 && computeRecordHash(record) === record["record_hash"];
```

`validateRecord` checks structure only and returns the same messages as the Python reference implementation. `computeRecordHash` is SHA-256 over the canonical form of the record without `record_hash`. `contentDigest` builds the digest object of SPEC section 4.8, plain SHA-256 or HMAC-SHA-256 with a key. Checking `prev_hash` and `sequence` across records belongs to chain verification, which is not written yet.
