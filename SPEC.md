# AI Evidence Record (AER) Specification

| | |
|---|---|
| **Version** | 0.1 |
| **Status** | Draft. Breaking changes are possible before 1.0 |
| **Editor** | Atul Chaudhari, AI Prompt Shield |
| **Feedback** | Issues and pull requests on this repository |

## 1. Introduction

Systems built on large language models make decisions that someone may later have to account for: an input was allowed, a retrieved document was blocked, a tool call was refused, an output was redacted. Ordinary application logs record these events, but they do not let a third party check that the log is complete and unaltered.

This specification defines

1. a **record**: a JSON object that describes one decision about one event in an AI system,
2. a **chain**: an ordered sequence of records in which each record commits to the one before it,
3. a **checkpoint**: a statement of a chain's state that can be signed and held outside the log owner's control, and
4. a **verification procedure** that any party can run with nothing but the log and, where available, a checkpoint.

### 1.1 Goals

- Any alteration, insertion, removal or reordering of records is detectable.
- Two independent implementations compute the same hash for the same record.
- A record can be verified without access to the content it describes.
- The format is small enough to implement in an afternoon in any language with JSON and SHA-256.

### 1.2 Non-goals

- AER does not define which events a system must log. That depends on the system and on the law that applies to it.
- AER does not prove that a record is true. It proves that a record has not changed since it was written. A system that writes false records produces a valid chain of false records.
- AER does not provide confidentiality. Records are plaintext.
- AER is not a transport, a storage engine or a query language.

## 2. Conventions

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

JSON is as defined in RFC 8259. "Member" means a name and value pair in a JSON object.

## 3. Terminology

| Term | Meaning |
|---|---|
| **Principal** | The human or service on whose behalf an agent acts |
| **Agent** | The AI component that performs the event |
| **Event** | Something an agent received, produced or attempted |
| **Decision** | What a control did about an event |
| **Writer** | The component that appends records to a chain |
| **Verifier** | Any party that checks a chain |
| **Head** | The `record_hash` of the last record in a chain |

## 4. Record

A record is a JSON object. Members not defined here MUST NOT appear at any level except inside `ext`.

### 4.1 Top-level members

| Member | Type | Required | Description |
|---|---|---|---|
| `spec` | string | yes | The literal `aer/0.1` |
| `chain_id` | string | yes | Identifies the chain. Identical in every record of a chain. A UUID is RECOMMENDED |
| `sequence` | integer | yes | Position in the chain. The first record is 0 |
| `record_id` | string | yes | Unique within the chain. A UUID is RECOMMENDED |
| `timestamp` | string | yes | When the decision was made. See 4.2 |
| `actor` | object | yes | Who acted. See 4.3 |
| `event` | object | yes | What happened. See 4.4 |
| `decision` | object | yes | What the control decided. See 4.5 |
| `scope` | object | no | Permission requested and granted. See 4.6 |
| `ext` | object | no | Extensions. See 4.7 |
| `prev_hash` | string | yes | `record_hash` of the preceding record. See 6 |
| `record_hash` | string | yes | Hash of this record. See 5.3 |

All strings described as required MUST be non-empty.

### 4.2 Timestamp

`timestamp` MUST be an RFC 3339 date-time in UTC, written with the `Z` suffix, with zero to nine fractional digits. Numeric offsets such as `+05:30` MUST NOT be used.

```
2026-11-12T10:00:02.000Z
```

### 4.3 `actor`

| Member | Type | Required | Description |
|---|---|---|---|
| `principal` | string | yes | Identifier of the principal |
| `agent` | string | yes | Identifier of the agent |
| `parent_agent` | string or null | no | The agent that delegated the task, or `null` when the agent was invoked directly |
| `model` | string | no | Identifier of the underlying model |

Identifiers are opaque to this specification. Writers SHOULD use stable identifiers and SHOULD NOT place personal data in them when a pseudonymous identifier will serve.

### 4.4 `event`

| Member | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | One of the values below |
| `content_digest` | digest | no | Digest of the content the decision was made on. See 4.8 |
| `source` | string | no | Where the content came from, for example a document identifier |
| `correlation_id` | string | no | Links records that belong to one request or task |
| `tool` | object | when `type` is `tool_call` | `name` (string, required) and `arguments_digest` (digest, optional) |

Values of `type`:

| Value | The event is |
|---|---|
| `input` | Content supplied by the principal |
| `context` | Content retrieved or supplied by a tool, a document store or another agent |
| `output` | Content the agent produced for the principal or for another system |
| `tool_call` | An attempt by the agent to invoke a tool |
| `memory_write` | An attempt to persist content for use in later sessions |
| `system` | A change to the system itself, such as a policy update |

### 4.5 `decision`

| Member | Type | Required | Description |
|---|---|---|---|
| `verdict` | string | yes | `allow`, `block`, `redact` or `escalate` |
| `policy` | object | yes | `id` and `version`, both strings, of the policy in force |
| `reason` | string | no | A machine-readable reason code |
| `enforced_by` | string | no | The control that made the decision |

`escalate` means the decision was handed to a human or to another system. The outcome of that review, when recorded, is a separate record with the same `correlation_id`.

`reason` SHOULD be a short code, not free text, and MUST NOT contain the content that was assessed.

### 4.6 `scope`

`scope` records the permission an agent asked for and the permission it held.

| Member | Type | Required |
|---|---|---|
| `requested` | array of strings, no duplicates | yes |
| `granted` | array of strings, no duplicates | yes |

The syntax of a scope string is not defined by this specification.

### 4.7 `ext`

`ext` is an object for data this specification does not define. Member names MUST match `^[a-z0-9][a-z0-9._-]*$` and SHOULD begin with a prefix that identifies who defined them, for example `acme.ticket_id`. Values MAY be any JSON value permitted by section 5.1.

`ext` is covered by `record_hash` like every other member. A verifier MUST NOT reject a record because it does not recognise an extension.

### 4.8 Digest

A digest is an object.

| Member | Type | Required | Description |
|---|---|---|---|
| `alg` | string | yes | `sha-256` or `hmac-sha-256` |
| `value` | string | yes | 64 lowercase hexadecimal characters |
| `key_id` | string | with `hmac-sha-256` only | Identifies the key. MUST NOT appear with `sha-256` |

`sha-256` is SHA-256 (FIPS 180-4) over the content bytes. `hmac-sha-256` is HMAC (RFC 2104) with SHA-256 over the content bytes under a secret key. The encoding of content into bytes is a matter for the writer and SHOULD be documented by it. UTF-8 is RECOMMENDED for text.

See section 10 for when to use the keyed form.

### 4.9 Example

```json
{
  "spec": "aer/0.1",
  "chain_id": "3f1c2a9e-7b64-4d0a-9c55-0e6a1b2c3d4e",
  "sequence": 2,
  "record_id": "00000000-0000-4000-8000-000000000002",
  "timestamp": "2026-11-12T10:00:02.000Z",
  "actor": {
    "principal": "user:alice",
    "agent": "agent:refund-worker",
    "parent_agent": "agent:support-bot"
  },
  "event": {
    "type": "tool_call",
    "tool": {
      "name": "http_get",
      "arguments_digest": {
        "alg": "sha-256",
        "value": "10a584f5ab961569e23b6a0fd33e699267b2accc95c15b20c350e7f6e13d5518"
      }
    },
    "correlation_id": "req-1001"
  },
  "decision": {
    "verdict": "block",
    "reason": "destination_not_allowlisted",
    "policy": { "id": "default", "version": "2026-11-01" },
    "enforced_by": "tool-gateway"
  },
  "scope": {
    "requested": ["http_get:attacker.example"],
    "granted": ["http_get:example.com"]
  },
  "prev_hash": "571377535ba9ae6845404f74901e0d054e9b8c4215551dc27c36c934f61c22ec",
  "record_hash": "3d48f3026608f5a1af04298a9d62329e36f3f9511fb8fadb1f640c630d87acec"
}
```

This is record 2 of `test-vectors/valid.jsonl`. Its hash can be reproduced by any conforming implementation.

## 5. Canonical form and hashing

### 5.1 Permitted values

A record MUST contain only objects, arrays, strings, integers, `true`, `false` and `null`.

- Numbers MUST be integers in the range -(2^53 - 1) to 2^53 - 1 and MUST be written without a fraction or an exponent. `1.0` and `1e3` are not permitted.
- Fractional quantities MUST be carried as strings or as scaled integers, for example a confidence of 0.95 as `"0.95"` or as `9500` basis points.
- An object MUST NOT contain two members with the same name.
- Strings MUST NOT contain unpaired surrogate code points.

A parser used for verification MUST reject input that breaks any of these rules. It MUST NOT silently keep the last of two duplicate members or convert a fraction to an integer.

The restriction on numbers is deliberate. Serialising floating-point numbers identically across languages is the main source of disagreement between canonical JSON implementations. Removing them removes the problem.

### 5.2 Canonical form

The canonical form of a value is the output of the JSON Canonicalization Scheme (RFC 8785) applied to it. For the values permitted by 5.1 this reduces to:

1. No whitespace between tokens.
2. Object members sorted by name, comparing names as sequences of UTF-16 code units.
3. Strings written with the escapes `\"` and `\\`, with `\b`, `\t`, `\n`, `\f` and `\r` for those five control characters, and with `\u00xx` in lowercase hexadecimal for every other character below U+0020. No other character is escaped.
4. Integers written in base 10 with no leading zeros and a leading `-` for negative values.
5. The result encoded as UTF-8.

No Unicode normalisation is applied. `"é"` written as one code point and as two are different strings and hash differently.

Because every permitted value is also valid input to RFC 8785, any conforming RFC 8785 implementation produces the canonical form.

### 5.3 Record hash

`record_hash` is computed as follows.

1. Take the record without its `record_hash` member.
2. Produce its canonical form (5.2).
3. Compute SHA-256 over those bytes.
4. Encode the result as 64 lowercase hexadecimal characters.

`prev_hash` is part of the hashed content. A record hash therefore commits to the entire chain before it.

## 6. Chain

A chain is the ordered set of records that share a `chain_id`.

- The first record MUST have `sequence` 0 and `prev_hash` equal to 64 zero characters.
- Every later record MUST have `sequence` one greater than the record before it and `prev_hash` equal to that record's `record_hash`.
- `record_id` MUST be unique within the chain.
- `timestamp` SHOULD NOT be earlier than the timestamp of the preceding record. Clock adjustments make a strict rule impractical, so a verifier reports a regression as a warning.

A chain MUST have exactly one writer at a time. Two writers that append to the same chain independently produce a fork, which fails verification. A system with several writers SHOULD give each its own chain.

A writer SHOULD ensure a record is durably stored before it treats the decision the record describes as final. A decision that takes effect and is then lost from the log is exactly the gap an audit looks for.

## 7. Storage and interchange

The interchange format is JSON Lines: one record per line, in sequence order, encoded as UTF-8, each line terminated by a line feed (U+000A). A record MUST NOT contain a literal line feed outside a string escape, and a file MUST NOT contain blank lines.

A stored line does not have to be in canonical form. A verifier parses each line and recomputes the canonical form itself.

Systems MAY store records in any other way, for example as database rows, provided they can export the chain in this format without loss.

## 8. Checkpoint

A hash chain has two limits. Removing records from the end leaves a shorter chain that is still valid. And whoever holds the log can rewrite all of it and recompute every hash. A checkpoint addresses both when it is held somewhere the log's owner cannot change.

### 8.1 Members

| Member | Type | Required | Description |
|---|---|---|---|
| `spec` | string | yes | The literal `aer-checkpoint/0.1` |
| `chain_id` | string | yes | The chain the checkpoint is for |
| `sequence` | integer | yes | Sequence of the record the checkpoint commits to |
| `record_hash` | string | yes | `record_hash` of that record |
| `issued_at` | string | yes | When the checkpoint was issued, in the form of 4.2 |
| `signature` | object | no | See 8.2 |

### 8.2 Signature

| Member | Type | Description |
|---|---|---|
| `alg` | string | The literal `ed25519` |
| `key_id` | string | Identifies the signing key |
| `value` | string | The signature, base64url without padding (RFC 4648 section 5) |

The signature is Ed25519 (RFC 8032) over the canonical form of the checkpoint without its `signature` member.

This specification does not define how a verifier obtains or trusts a public key. When no other convention applies, `key_id` SHOULD be the first 16 hexadecimal characters of the SHA-256 of the 32-byte public key.

### 8.3 Example

```json
{
  "spec": "aer-checkpoint/0.1",
  "chain_id": "3f1c2a9e-7b64-4d0a-9c55-0e6a1b2c3d4e",
  "sequence": 5,
  "record_hash": "9500630c0bae41b19697b96861ae7d7acc61689476ad3314af95c265fba4e731",
  "issued_at": "2026-11-12T10:01:00.000Z",
  "signature": {
    "alg": "ed25519",
    "key_id": "56475aa75463474c",
    "value": "gDxD9dx_9msDWQQsLmMCZHo17eko3beCgP-aIpPTITG4eLoNUqTH-Bx1AgUzROwgRN-af94Lw8Zm1GWo1Ha3DQ"
  }
}
```

### 8.4 Use

An unsigned checkpoint is only as trustworthy as the place it is kept. A signed checkpoint is only as trustworthy as the custody of the signing key. Writers SHOULD issue checkpoints at regular intervals and SHOULD place them outside the control of whoever administers the log. Suitable places include a separate organisation, a write-once store, a transparency log or a trusted timestamping service (RFC 3161).

The signing key SHOULD NOT be held by the component that writes the log. If it is, a party that compromises the writer can rewrite the log and sign a matching checkpoint.

## 9. Verification

A verifier processes the lines of a log in order and keeps three values: the expected `prev_hash`, initially 64 zeros; the expected `sequence`, initially 0; and the `chain_id` of the first record.

For each line the verifier MUST

1. parse the line under the rules of 5.1, reporting `E_PARSE` on failure,
2. check the structure defined in section 4, reporting `E_SCHEMA` for each fault,
3. check `chain_id` against the first record, reporting `E_CHAIN_ID`,
4. check `sequence` against the expected value, reporting `E_SEQUENCE`,
5. check `prev_hash` against the expected value, reporting `E_PREV_HASH`,
6. recompute the hash as in 5.3 and compare it with `record_hash`, reporting `E_RECORD_HASH`,
7. check that `record_id` has not appeared before, reporting `E_DUPLICATE_ID`, and
8. set the expected `prev_hash` to this record's `record_hash` and the expected `sequence` to this record's `sequence` plus one.

Step 8 uses the values the record claims, not the values that were expected. A single fault is then reported once, at the place it occurs, and does not repeat on every later line.

When a checkpoint is supplied the verifier MUST also

9. check that the checkpoint is well formed and is for the same `chain_id`, reporting `E_CHECKPOINT`,
10. check that the log contains a record at the checkpoint's `sequence`, reporting `E_CHECKPOINT` if the log is shorter,
11. check that this record's `record_hash` equals the checkpoint's, reporting `E_CHECKPOINT`, and
12. if the checkpoint is signed, verify the signature, reporting `E_SIGNATURE` if it is invalid or if no public key is available.

A log MAY extend beyond a checkpoint. Records after the checkpointed sequence are covered by the chain but not by that checkpoint.

A log verifies if no finding with a code beginning `E_` is reported.

### 9.1 Finding codes

| Code | Meaning |
|---|---|
| `E_PARSE` | A line is not valid JSON under 5.1, or is blank |
| `E_SCHEMA` | A record does not have the structure of section 4 |
| `E_CHAIN_ID` | A record belongs to a different chain |
| `E_SEQUENCE` | A record is missing, repeated or out of order |
| `E_PREV_HASH` | A record does not link to the one before it |
| `E_RECORD_HASH` | A record's content does not match its hash |
| `E_DUPLICATE_ID` | A `record_id` is used twice |
| `E_CHECKPOINT` | The log is shorter than, or differs from, a checkpoint |
| `E_SIGNATURE` | A checkpoint signature is invalid or cannot be checked |
| `W_TIMESTAMP_ORDER` | A timestamp is earlier than the preceding record's |
| `W_UNSIGNED_CHECKPOINT` | The checkpoint carries no signature |
| `W_NO_CHECKPOINT` | No checkpoint was supplied, so truncation cannot be detected |

A verifier SHOULD report every finding with the line number at which it occurs.

## 10. Privacy considerations

Records are designed to be shared with auditors, customers and regulators. They SHOULD NOT contain the content that was assessed. They carry a digest of it.

A plain SHA-256 digest does not hide content that can be guessed. Anyone who holds the record can hash candidate values and compare. For short or predictable content, such as a yes or no answer, a postcode or a card number, a plain digest reveals the content in practice. Writers SHOULD use `hmac-sha-256` for such content and keep the key separate from the log. A party that needs to confirm what a record refers to is then given the key, or is given the content and asks the key holder to confirm it.

Identifiers in `actor`, `source` and `correlation_id` can be personal data. Where the law requires that personal data be erasable, writers SHOULD use pseudonymous identifiers and keep the mapping to real identities outside the chain, where it can be deleted. Removing a record from a chain breaks verification from that point on, by design.

Retention periods are outside the scope of this specification.

## 11. Security considerations

**What a chain detects.** Editing, inserting, removing or reordering records anywhere before the head, provided the verifier has a trusted copy of a later hash.

**What a chain alone does not detect.** Removal of records from the end, and replacement of the whole chain by a party able to recompute it. Both are detected with a checkpoint held out of that party's reach (section 8).

**What nothing here detects.** A writer that records a false decision, omits to record an event at all, or is bypassed by a path through the system that does not call it. Completeness of logging is a property of the system's architecture and has to be established by other means.

**Clocks.** `timestamp` is an assertion by the writer and is not verifiable from the chain. Where the time of an event matters as evidence, checkpoints SHOULD be timestamped by an independent service.

**Hash agility.** Version 0.1 fixes SHA-256 for chaining. A later version that changes the algorithm will change the `spec` value, so a verifier never has to guess.

**Canonicalisation attacks.** A verifier that accepts duplicate members, or parses numbers leniently, can be shown one record while hashing another. The parsing rules in 5.1 are a security requirement, not a matter of style.

**Availability.** A writer that cannot append SHOULD fail closed for decisions whose record is the evidence of their being made. Whether a given system can tolerate that is a design decision for its owner.

## 12. Extensions and versioning

The `spec` member identifies the version. Within 0.x, a change to the minor number MAY be incompatible. From 1.0, records valid under 1.n remain valid under 1.n+1.

A verifier MUST reject a record whose `spec` value it does not implement. New data that does not change the meaning of existing members belongs in `ext` and needs no new version.

## 13. Conformance

A **writer** conforms if every chain it produces verifies under section 9.

A **verifier** conforms if, for every case in `test-vectors/expected.json`, it reports exactly the listed error codes at the listed lines, and if it accepts every valid case and rejects every rejected case in `test-vectors/canonicalization.json`.

## 14. References

### Normative

- RFC 2104, HMAC: Keyed-Hashing for Message Authentication
- RFC 2119 and RFC 8174, Key words for use in RFCs to Indicate Requirement Levels
- RFC 3339, Date and Time on the Internet: Timestamps
- RFC 4648, The Base16, Base32, and Base64 Data Encodings
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format
- RFC 8785, JSON Canonicalization Scheme (JCS)
- FIPS 180-4, Secure Hash Standard

### Informative

- RFC 3161, Internet X.509 Public Key Infrastructure Time-Stamp Protocol
- RFC 6962, Certificate Transparency
- Regulation (EU) 2024/1689 (Artificial Intelligence Act), Articles 12, 19 and 26
- MITRE ATLAS, mitigation AML.M0024 (AI Telemetry Logging)
- JSON Lines, jsonlines.org
