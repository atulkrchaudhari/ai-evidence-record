/**
 * Canonical JSON for hashing and signing.
 *
 * Implements the JSON Canonicalization Scheme (RFC 8785) restricted to the
 * value types AER permits: objects, arrays, strings, integers, booleans and
 * null (SPEC.md, section 5). Floating-point numbers are rejected.
 *
 * JSON.parse cannot be used for verification: it keeps the last of two
 * duplicate members and turns 1.0 into 1 without a trace. strictParse is a
 * small parser that rejects both.
 */

export const MAX_SAFE_INTEGER = 2 ** 53 - 1;

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** The value cannot be represented in AER canonical form. */
export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

function hasLoneSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function serializeString(value: string): string {
  if (hasLoneSurrogate(value)) {
    throw new CanonicalizationError("string contains a lone surrogate");
  }
  // RFC 8785 defines string serialisation as that of ECMAScript's
  // JSON.stringify: the quote, the backslash and U+0000 to U+001F are
  // escaped (short forms where defined, lowercase \u00xx otherwise) and
  // everything else is emitted as is.
  return JSON.stringify(value);
}

function isPlainObject(value: object): boolean {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new CanonicalizationError("floating-point numbers are not permitted");
    }
    if (Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new CanonicalizationError("integer outside the range -(2^53-1) to 2^53-1");
    }
    // Negative zero is written as 0, as RFC 8785 requires.
    return value === 0 ? "0" : String(value);
  }
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) {
    const items: string[] = [];
    // An index loop, so that a hole in a sparse array is seen as undefined and rejected.
    for (let i = 0; i < value.length; i++) items.push(serialize(value[i]));
    return "[" + items.join(",") + "]";
  }
  if (typeof value === "object" && isPlainObject(value)) {
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new CanonicalizationError("object keys must be strings");
    }
    const record = value as Record<string, unknown>;
    // RFC 8785 orders members by the UTF-16 code units of their names,
    // which is how the default sort compares strings.
    const keys = Object.keys(record).sort();
    return "{" + keys.map((key) => serializeString(key) + ":" + serialize(record[key])).join(",") + "}";
  }
  const kind = typeof value === "object" ? (value.constructor?.name ?? "object") : typeof value;
  throw new CanonicalizationError(`unsupported type: ${kind}`);
}

/** Return the canonical form of a JSON value as a string. */
export function canonicalString(value: unknown): string {
  return serialize(value);
}

/** Return the canonical UTF-8 encoding of a JSON value. */
export function canonicalize(value: unknown): Uint8Array {
  return new TextEncoder().encode(serialize(value));
}

const WHITESPACE = new Set([0x20, 0x09, 0x0a, 0x0d]);
const SHORT_ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

class Parser {
  private readonly text: string;
  private pos = 0;

  constructor(text: string) {
    this.text = text;
  }

  parseDocument(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.pos < this.text.length) throw this.invalid("unexpected data after the value");
    return value;
  }

  private invalid(message: string): CanonicalizationError {
    return new CanonicalizationError(`invalid JSON: ${message} at position ${this.pos}`);
  }

  private skipWhitespace(): void {
    while (WHITESPACE.has(this.text.charCodeAt(this.pos))) this.pos++;
  }

  private parseValue(): JsonValue {
    const ch = this.text[this.pos];
    if (ch === undefined) throw this.invalid("unexpected end of input");
    if (ch === "{") return this.parseObject();
    if (ch === "[") return this.parseArray();
    if (ch === '"') return this.parseString();
    if (ch === "-" || (ch >= "0" && ch <= "9")) return this.parseNumber();
    if (this.text.startsWith("true", this.pos)) return this.literal("true", true);
    if (this.text.startsWith("false", this.pos)) return this.literal("false", false);
    if (this.text.startsWith("null", this.pos)) return this.literal("null", null);
    for (const constant of ["NaN", "Infinity"]) {
      if (this.text.startsWith(constant, this.pos)) {
        throw new CanonicalizationError(`floating-point number not permitted: ${constant}`);
      }
    }
    throw this.invalid("unexpected character");
  }

  private literal<T extends JsonValue>(word: string, value: T): T {
    this.pos += word.length;
    return value;
  }

  private parseObject(): JsonValue {
    // A null prototype keeps a member named "__proto__" an ordinary member.
    const result: { [key: string]: JsonValue } = Object.create(null);
    this.pos++;
    this.skipWhitespace();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return result;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.pos] !== '"') throw this.invalid("expected a member name");
      const key = this.parseString();
      if (Object.hasOwn(result, key)) {
        throw new CanonicalizationError(`duplicate object member: ${JSON.stringify(key)}`);
      }
      this.skipWhitespace();
      if (this.text[this.pos] !== ":") throw this.invalid("expected ':'");
      this.pos++;
      this.skipWhitespace();
      result[key] = this.parseValue();
      this.skipWhitespace();
      const ch = this.text[this.pos];
      this.pos++;
      if (ch === "}") return result;
      if (ch !== ",") {
        this.pos--;
        throw this.invalid("expected ',' or '}'");
      }
    }
  }

  private parseArray(): JsonValue {
    const result: JsonValue[] = [];
    this.pos++;
    this.skipWhitespace();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return result;
    }
    for (;;) {
      this.skipWhitespace();
      result.push(this.parseValue());
      this.skipWhitespace();
      const ch = this.text[this.pos];
      this.pos++;
      if (ch === "]") return result;
      if (ch !== ",") {
        this.pos--;
        throw this.invalid("expected ',' or ']'");
      }
    }
  }

  private parseString(): string {
    let out = "";
    this.pos++;
    for (;;) {
      const ch = this.text[this.pos];
      if (ch === undefined) throw this.invalid("unterminated string");
      if (ch === '"') {
        this.pos++;
        break;
      }
      if (ch.charCodeAt(0) < 0x20) throw this.invalid("control character in string");
      if (ch !== "\\") {
        out += ch;
        this.pos++;
        continue;
      }
      const escape = this.text[this.pos + 1];
      if (escape === "u") {
        const hex = this.text.slice(this.pos + 2, this.pos + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw this.invalid("invalid \\u escape");
        out += String.fromCharCode(parseInt(hex, 16));
        this.pos += 6;
      } else if (escape !== undefined && Object.hasOwn(SHORT_ESCAPES, escape)) {
        out += SHORT_ESCAPES[escape];
        this.pos += 2;
      } else {
        throw this.invalid("invalid escape");
      }
    }
    if (hasLoneSurrogate(out)) {
      throw new CanonicalizationError("string contains a lone surrogate");
    }
    return out;
  }

  private parseNumber(): number {
    const match = /-?(?:0|[1-9][0-9]*)/y;
    match.lastIndex = this.pos;
    const found = match.exec(this.text);
    if (found === null) throw this.invalid("invalid number");
    const digits = found[0];
    const next = this.text[this.pos + digits.length];
    if (next === "." || next === "e" || next === "E") {
      const rest = /[-+.0-9eE]*/y;
      rest.lastIndex = this.pos;
      throw new CanonicalizationError(`floating-point number not permitted: ${rest.exec(this.text)?.[0] ?? digits}`);
    }
    if (next !== undefined && next >= "0" && next <= "9") throw this.invalid("leading zero in number");
    const exact = BigInt(digits);
    if (exact > BigInt(MAX_SAFE_INTEGER) || exact < -BigInt(MAX_SAFE_INTEGER)) {
      throw new CanonicalizationError("integer outside the range -(2^53-1) to 2^53-1");
    }
    this.pos += digits.length;
    // "-0" is read as 0, the integer it denotes.
    return Number(exact);
  }
}

/** Parse JSON, rejecting duplicate members, floats, NaN, Infinity and lone surrogates. */
export function strictParse(text: string): JsonValue {
  if (hasLoneSurrogate(text)) {
    throw new CanonicalizationError("input contains a lone surrogate");
  }
  return new Parser(text).parseDocument();
}
