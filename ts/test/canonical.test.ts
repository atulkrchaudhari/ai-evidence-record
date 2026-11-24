import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { CanonicalizationError, canonicalString, canonicalize, strictParse } from "../src/canonical.ts";

interface ValidCase {
  name: string;
  input: string;
  canonical: string;
  sha256: string;
}

interface RejectedCase {
  name: string;
  input: string;
}

const vectors = JSON.parse(
  readFileSync(new URL("../../test-vectors/canonicalization.json", import.meta.url), "utf8"),
) as { valid: ValidCase[]; rejected: RejectedCase[] };

test("every valid conformance vector gives the listed canonical form and hash", () => {
  assert.ok(vectors.valid.length >= 10);
  for (const item of vectors.valid) {
    const bytes = canonicalize(strictParse(item.input));
    assert.equal(new TextDecoder().decode(bytes), item.canonical, item.name);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), item.sha256, item.name);
  }
});

test("every rejected conformance vector is rejected", () => {
  assert.ok(vectors.rejected.length >= 8);
  for (const item of vectors.rejected) {
    assert.throws(() => canonicalize(strictParse(item.input)), CanonicalizationError, item.name);
  }
});

test("members follow the order of the RFC 8785 section 3.2.3 example", () => {
  const value = { "\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\u{1f600}": 5, "\u0080": 6, "\u00f6": 7 };
  // A JavaScript object lists the integer-like key "1" first, so the text is compared, not the key order.
  assert.equal(
    canonicalString(value),
    '{"\\r":2,"1":4,"\u0080":6,"\u00f6":7,"\u20ac":1,"\u{1f600}":5,"\ufb33":3}',
  );
});

test("the canonical form is idempotent", () => {
  const once = canonicalString({ b: [1, { d: null, c: "x" }], a: "\u00e9" });
  assert.equal(once, '{"a":"\u00e9","b":[1,{"c":"x","d":null}]}');
  assert.equal(canonicalString(strictParse(once)), once);
});

test("values outside the AER types are rejected", () => {
  const sparse = [1, 2, 3];
  delete sparse[1];
  const bad: unknown[] = [
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    2 ** 53,
    -(2 ** 53),
    undefined,
    10n,
    Symbol("s"),
    () => 1,
    new Date(0),
    new Map(),
    new Uint8Array(2),
    { a: undefined },
    { [Symbol("k")]: 1 },
    sparse,
    "\ud800",
    { "\udc00": 1 },
  ];
  for (const value of bad) {
    assert.throws(() => canonicalize(value), CanonicalizationError, String(value));
  }
});

test("booleans are not integers and negative zero is written as 0", () => {
  assert.equal(canonicalString([true, 1, false, 0, -0]), "[true,1,false,0,0]");
  assert.equal(canonicalString(strictParse("[-0, -1]")), "[0,-1]");
});

test("integers at the limits are exact and the next ones are rejected", () => {
  assert.equal(strictParse("9007199254740991"), 9007199254740991);
  assert.equal(strictParse("-9007199254740991"), -9007199254740991);
  for (const text of ["9007199254740992", "-9007199254740992", "9007199254740993", "1" + "0".repeat(400)]) {
    assert.throws(() => strictParse(text), /integer outside the range/, text);
  }
});

test("duplicate members are rejected however the name is written", () => {
  for (const text of ['{"a":1,"a":1}', '{"a":1,"\\u0061":2}', '{"x":{"k":1,"k":2}}', '[{"":0,"":0}]']) {
    assert.throws(() => strictParse(text), /duplicate object member/, text);
  }
});

test("a member named __proto__ is kept as an ordinary member", () => {
  const text = '{"__proto__":{"a":1},"constructor":2,"toString":3}';
  assert.equal(canonicalString(strictParse(text)), text);
  assert.throws(() => strictParse('{"__proto__":1,"__proto__":2}'), /duplicate object member/);
  assert.equal(({} as Record<string, unknown>)["a"], undefined);
});

test("numbers with a fraction or an exponent are rejected with the text that was read", () => {
  for (const text of ["1.5", "1.0", "1e3", "1E3", "-0.0", "[1, 2.50]", '{"a":0e0}']) {
    assert.throws(() => strictParse(text), /floating-point number not permitted/, text);
  }
  assert.throws(() => strictParse("12.50"), /not permitted: 12\.50$/);
  assert.throws(() => strictParse("-Infinity"), CanonicalizationError);
});

test("input that is not JSON is rejected", () => {
  const bad = [
    "",
    " ",
    "[1,]",
    "{,}",
    '{"a":1,}',
    "{a:1}",
    "{'a':1}",
    "01",
    "-",
    "+1",
    ".5",
    "1 2",
    "[1 2]",
    '{"a" 1}',
    '"abc',
    '"\\x41"',
    '"\\u12"',
    '"\\u12G4"',
    '"a\tb"',
    '"a\nb"',
    "tru",
    "nulll",
    "[",
    '{"a":',
    "\ufeff{}",
    "/* c */ 1",
    "undefined",
  ];
  for (const text of bad) {
    assert.throws(() => strictParse(text), CanonicalizationError, JSON.stringify(text));
  }
});

test("surrogates are accepted in pairs only", () => {
  assert.equal(strictParse('"\\ud83d\\ude00"'), "\u{1f600}");
  for (const text of ['"\\ud800"', '"\\ude00\\ud83d"', '"\\ud83dx"', '"\ud83d"', '{"\\udc00":1}']) {
    assert.throws(() => strictParse(text), /lone surrogate/, JSON.stringify(text));
  }
});

test("all four JSON whitespace characters are skipped and no others", () => {
  assert.deepEqual(strictParse(' \t\r\n[ 1 ,\n2 ]\r\n'), [1, 2]);
  for (const text of ["\u00a01", "1\u000b", "\u20281", "[1,\u00a02]"]) {
    assert.throws(() => strictParse(text), CanonicalizationError, JSON.stringify(text));
  }
});

test("strictParse agrees with JSON.parse on integer-only documents", () => {
  let seed = 20261124;
  const next = (n: number): number => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed % n;
  };
  const alphabet = ["a", "Z", "0", " ", '"', "\\", "/", "\n", "\u0001", "\u007f", "\u00e9", "\u20ac", "\ufb33", "\u{1f600}"];
  const text = (): string => Array.from({ length: next(6) }, () => alphabet[next(alphabet.length)]).join("");
  const build = (depth: number): unknown => {
    const kind = next(depth > 3 ? 5 : 7);
    if (kind === 0) return null;
    if (kind === 1) return next(2) === 0;
    if (kind === 2) return next(2000) - 1000;
    if (kind === 3) return (next(2) === 0 ? 1 : -1) * (Number.MAX_SAFE_INTEGER - next(1000));
    if (kind === 4) return text();
    if (kind === 5) return Array.from({ length: next(4) }, () => build(depth + 1));
    return Object.fromEntries(Array.from({ length: next(4) }, () => [text(), build(depth + 1)]));
  };
  for (let i = 0; i < 2000; i++) {
    const value = build(0);
    for (const source of [JSON.stringify(value), JSON.stringify(value, null, 2)]) {
      assert.deepEqual(JSON.parse(canonicalString(strictParse(source))), value);
      assert.equal(canonicalString(strictParse(source)), canonicalString(value));
    }
  }
});
