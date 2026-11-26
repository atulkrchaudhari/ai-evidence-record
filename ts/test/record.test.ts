import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { CanonicalizationError, strictParse } from "../src/canonical.ts";
import { GENESIS_HASH, computeRecordHash, contentDigest, validateRecord } from "../src/record.ts";

type Members = Record<string, unknown>;

interface ExpectedCase {
  log: string;
  errors: [string, number | null][];
}

const vectorUrl = (name: string): URL => new URL(`../../test-vectors/${name}`, import.meta.url);

function readLog(name: string): Members[] {
  return readFileSync(vectorUrl(name), "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => strictParse(line) as Members);
}

const expected = JSON.parse(readFileSync(vectorUrl("expected.json"), "utf8")) as { cases: ExpectedCase[] };
const logNames = [...new Set(expected.cases.map((item) => item.log))];

function validRecord(): Members {
  const record: Members = {
    spec: "aer/0.1",
    chain_id: "c",
    sequence: 0,
    record_id: "r0",
    timestamp: "2026-01-01T00:00:00Z",
    actor: { principal: "user:alice", agent: "agent:support-bot" },
    event: { type: "input" },
    decision: { verdict: "allow", policy: { id: "default", version: "1" } },
    prev_hash: GENESIS_HASH,
  };
  record["record_hash"] = computeRecordHash(record);
  return record;
}

test("every record in valid.jsonl is well formed and has the hash it states", () => {
  const records = readLog("valid.jsonl");
  assert.ok(records.length >= 5);
  for (const record of records) {
    assert.deepEqual(validateRecord(record), []);
    assert.equal(computeRecordHash(record), record["record_hash"]);
  }
});

test("the hash differs from record_hash on exactly the lines where E_RECORD_HASH is expected", () => {
  assert.ok(logNames.length >= 7);
  let mismatches = 0;
  for (const name of logNames) {
    const wanted = new Set<number>();
    for (const item of expected.cases) {
      if (item.log !== name) continue;
      for (const [code, line] of item.errors) {
        if (code === "E_RECORD_HASH" && line !== null) wanted.add(line);
      }
    }
    const found = new Set<number>();
    readLog(name).forEach((record, index) => {
      if (computeRecordHash(record) !== record["record_hash"]) found.add(index + 1);
    });
    assert.deepEqual([...found], [...wanted], name);
    mismatches += found.size;
  }
  assert.ok(mismatches >= 1);
});

test("every record in every conformance log is well formed", () => {
  for (const name of logNames) {
    for (const record of readLog(name)) assert.deepEqual(validateRecord(record), [], name);
  }
});

test("the first record of valid.jsonl starts from the genesis hash", () => {
  assert.equal(GENESIS_HASH, "0".repeat(64));
  assert.equal(readLog("valid.jsonl")[0]?.["prev_hash"], GENESIS_HASH);
});

test("the hash ignores member order and the stated record_hash, but not content", () => {
  const record = validRecord();
  const reversed = Object.fromEntries(Object.entries(record).reverse());
  assert.equal(computeRecordHash(reversed), record["record_hash"]);
  assert.equal(computeRecordHash({ ...record, record_hash: "f".repeat(64) }), record["record_hash"]);
  const { record_hash: _, ...body } = record;
  assert.equal(computeRecordHash(body), record["record_hash"]);
  const changed = structuredClone(record);
  (changed["decision"] as Members)["verdict"] = "block";
  assert.notEqual(computeRecordHash(changed), record["record_hash"]);
});

test("the hash covers ext", () => {
  const record = validRecord();
  assert.notEqual(computeRecordHash({ ...record, ext: { "acme.ticket_id": "T-1" } }), record["record_hash"]);
});

test("a record with a value outside the permitted types cannot be hashed", () => {
  assert.throws(() => computeRecordHash({ ...validRecord(), ext: { "acme.score": 0.5 } }), CanonicalizationError);
});

test("the SPEC section 4.9 example has the hash it states", () => {
  const spec = readFileSync(new URL("../../SPEC.md", import.meta.url), "utf8");
  const section = spec.slice(spec.indexOf("### 4.9 Example"));
  const block = /```json\n([\s\S]*?)```/.exec(section);
  assert.ok(block?.[1]);
  const record = strictParse(block[1]) as Members;
  assert.deepEqual(validateRecord(record), []);
  assert.equal(computeRecordHash(record), record["record_hash"]);
});

const invalid: [string, (record: Members) => void, string][] = [
  ["missing actor", (r) => delete r["actor"], "record.actor: required member is missing"],
  ["unknown member", (r) => (r["extra"] = 1), "record.extra: unknown member (use ext for extensions)"],
  ["wrong spec", (r) => (r["spec"] = "aer/9"), "record.spec: must be 'aer/0.1'"],
  ["empty chain_id", (r) => (r["chain_id"] = ""), "record.chain_id: must be a non-empty string"],
  ["negative sequence", (r) => (r["sequence"] = -1), "record.sequence: must be a non-negative integer"],
  ["boolean sequence", (r) => (r["sequence"] = true), "record.sequence: must be a non-negative integer"],
  ["string sequence", (r) => (r["sequence"] = "0"), "record.sequence: must be a non-negative integer"],
  [
    "timestamp with an offset",
    (r) => (r["timestamp"] = "2026-01-01T00:00:00+05:30"),
    "record.timestamp: must be RFC 3339 in UTC with a 'Z' suffix",
  ],
  [
    "timestamp with ten fraction digits",
    (r) => (r["timestamp"] = "2026-01-01T00:00:00.0000000001Z"),
    "record.timestamp: must be RFC 3339 in UTC with a 'Z' suffix",
  ],
  [
    "timestamp with a trailing line feed",
    (r) => (r["timestamp"] = "2026-01-01T00:00:00Z\n"),
    "record.timestamp: must be RFC 3339 in UTC with a 'Z' suffix",
  ],
  ["uppercase prev_hash", (r) => (r["prev_hash"] = "A".repeat(64)), "record.prev_hash: must be 64 lowercase hexadecimal characters"],
  ["short record_hash", (r) => (r["record_hash"] = "abc"), "record.record_hash: must be 64 lowercase hexadecimal characters"],
  ["actor is an array", (r) => (r["actor"] = []), "record.actor: must be an object"],
  ["empty principal", (r) => ((r["actor"] as Members)["principal"] = ""), "record.actor.principal: must be a non-empty string"],
  [
    "empty parent_agent",
    (r) => ((r["actor"] as Members)["parent_agent"] = ""),
    "record.actor.parent_agent: must be a non-empty string or null",
  ],
  ["numeric model", (r) => ((r["actor"] as Members)["model"] = 1), "record.actor.model: must be a non-empty string"],
  [
    "unknown event type",
    (r) => ((r["event"] as Members)["type"] = "nope"),
    "record.event.type: must be one of input, context, output, tool_call, memory_write, system",
  ],
  [
    "tool_call without a tool",
    (r) => ((r["event"] as Members)["type"] = "tool_call"),
    "record.event.tool: required when event.type is tool_call",
  ],
  [
    "tool without a name",
    (r) => (r["event"] = { type: "tool_call", tool: {} }),
    "record.event.tool.name: required member is missing",
  ],
  ["empty source", (r) => ((r["event"] as Members)["source"] = ""), "record.event.source: must be a non-empty string"],
  [
    "unknown digest algorithm",
    (r) => ((r["event"] as Members)["content_digest"] = { alg: "md5", value: "0".repeat(64) }),
    "record.event.content_digest.alg: must be one of sha-256, hmac-sha-256",
  ],
  [
    "digest value of the wrong length",
    (r) => ((r["event"] as Members)["content_digest"] = { alg: "sha-256", value: "0".repeat(63) }),
    "record.event.content_digest.value: must be 64 lowercase hexadecimal characters",
  ],
  [
    "keyed digest without key_id",
    (r) => ((r["event"] as Members)["content_digest"] = { alg: "hmac-sha-256", value: "0".repeat(64) }),
    "record.event.content_digest.key_id: required with hmac-sha-256",
  ],
  [
    "plain digest with key_id",
    (r) => ((r["event"] as Members)["content_digest"] = { alg: "sha-256", value: "0".repeat(64), key_id: "k" }),
    "record.event.content_digest.key_id: not permitted with sha-256",
  ],
  [
    "bad arguments digest",
    (r) => (r["event"] = { type: "tool_call", tool: { name: "t", arguments_digest: { alg: "sha-256" } } }),
    "record.event.tool.arguments_digest.value: required member is missing",
  ],
  [
    "unknown verdict",
    (r) => ((r["decision"] as Members)["verdict"] = "maybe"),
    "record.decision.verdict: must be one of allow, block, redact, escalate",
  ],
  ["missing policy", (r) => delete (r["decision"] as Members)["policy"], "record.decision.policy: required member is missing"],
  [
    "empty policy version",
    (r) => ((r["decision"] as Members)["policy"] = { id: "default", version: "" }),
    "record.decision.policy.version: must be a non-empty string",
  ],
  ["empty reason", (r) => ((r["decision"] as Members)["reason"] = ""), "record.decision.reason: must be a non-empty string"],
  [
    "duplicate scope",
    (r) => (r["scope"] = { requested: ["a", "a"], granted: [] }),
    "record.scope.requested: must not contain duplicates",
  ],
  [
    "scope that is not a list",
    (r) => (r["scope"] = { requested: ["a"], granted: "a" }),
    "record.scope.granted: must be an array of non-empty strings",
  ],
  ["ext is an array", (r) => (r["ext"] = []), "record.ext: must be an object"],
  [
    "ext name with a space and capitals",
    (r) => (r["ext"] = { "Bad Key": 1 }),
    "record.ext.Bad Key: extension names use lowercase letters, digits, '.', '_' and '-'",
  ],
];

test("structural errors are reported with the member they concern", () => {
  for (const [name, mutate, message] of invalid) {
    const record = structuredClone(validRecord());
    mutate(record);
    const errors = validateRecord(record);
    assert.ok(errors.includes(message), `${name}: ${JSON.stringify(errors)}`);
  }
});

test("a record that is not an object gives one error", () => {
  for (const value of [null, [], "x", 1, true]) {
    assert.deepEqual(validateRecord(value), ["record: must be an object"]);
  }
});

test("optional members are accepted when well formed", () => {
  const record = validRecord();
  record["actor"] = { principal: "p", agent: "a", parent_agent: null, model: "m" };
  record["event"] = {
    type: "tool_call",
    source: "s",
    correlation_id: "c",
    content_digest: contentDigest("abc"),
    tool: { name: "http_get", arguments_digest: contentDigest("{}", { key: new Uint8Array([1]), keyId: "k1" }) },
  };
  record["decision"] = { verdict: "block", policy: { id: "d", version: "1" }, reason: "r", enforced_by: "e" };
  record["scope"] = { requested: ["orders:read"], granted: [] };
  record["ext"] = { "acme.ticket_id": "T-1", "0": null };
  assert.deepEqual(validateRecord(record), []);
});

test("a record parsed by strictParse validates the same as a plain object", () => {
  const record = validRecord();
  assert.deepEqual(validateRecord(strictParse(JSON.stringify(record))), []);
  assert.deepEqual(validateRecord(strictParse('{"__proto__":{"spec":"aer/0.1"}}')).slice(0, 1), [
    "record.spec: required member is missing",
  ]);
});

test("content digest is SHA-256, or HMAC-SHA-256 with a key", () => {
  const bytes = new TextEncoder().encode("abc");
  const plain = createHash("sha256").update(bytes).digest("hex");
  assert.deepEqual(contentDigest("abc"), { alg: "sha-256", value: plain });
  assert.deepEqual(contentDigest(bytes), { alg: "sha-256", value: plain });
  assert.equal(plain, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  const key = new TextEncoder().encode("k");
  assert.deepEqual(contentDigest("abc", { key, keyId: "k1" }), {
    alg: "hmac-sha-256",
    value: createHmac("sha256", key).update(bytes).digest("hex"),
    key_id: "k1",
  });
  assert.throws(() => contentDigest("abc", { key }), TypeError);
});
