/**
 * Evidence records: structural validation, hashing and content digests.
 *
 * Follows SPEC.md section 4 (record members) and section 5.3 (record hash).
 * The error messages match the Python reference implementation, so the two
 * verifiers can be compared line by line.
 */

import { createHash, createHmac } from "node:crypto";

import { canonicalize } from "./canonical.ts";

export const SPEC = "aer/0.1";
export const GENESIS_HASH = "0".repeat(64);

export const EVENT_TYPES = ["input", "context", "output", "tool_call", "memory_write", "system"] as const;
export const VERDICTS = ["allow", "block", "redact", "escalate"] as const;
export const DIGEST_ALGS = ["sha-256", "hmac-sha-256"] as const;

const HEX64 = /^[0-9a-f]{64}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$/;
const EXT_KEY = /^[a-z0-9][a-z0-9._-]*$/;

const TOP_REQUIRED = [
  "spec",
  "chain_id",
  "sequence",
  "record_id",
  "timestamp",
  "actor",
  "event",
  "decision",
  "prev_hash",
  "record_hash",
];
const TOP_OPTIONAL = ["scope", "ext"];

type Members = Record<string, unknown>;

export interface Digest {
  alg: "sha-256" | "hmac-sha-256";
  value: string;
  key_id?: string;
}

function isObject(value: unknown): value is Members {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function isHex64(value: unknown): boolean {
  return typeof value === "string" && HEX64.test(value);
}

function isOneOf(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === "string" && allowed.includes(value);
}

/**
 * SHA-256 over the canonical form of the record without `record_hash`,
 * as lowercase hexadecimal (SPEC section 5.3).
 *
 * Throws CanonicalizationError when the record holds a value that has no
 * canonical form.
 */
export function computeRecordHash(record: Members): string {
  const body: Members = Object.create(null);
  for (const key of Object.keys(record)) {
    if (key !== "record_hash") body[key] = record[key];
  }
  return createHash("sha256").update(canonicalize(body)).digest("hex");
}

/**
 * Digest content for an evidence record (SPEC section 4.8).
 *
 * Without a key the digest is plain SHA-256. With a key it is HMAC-SHA-256,
 * which stops anyone without the key from confirming a guess at the content.
 */
export function contentDigest(content: string | Uint8Array, options: { key?: Uint8Array; keyId?: string } = {}): Digest {
  const data = typeof content === "string" ? new TextEncoder().encode(content) : content;
  if (options.key === undefined) {
    return { alg: "sha-256", value: createHash("sha256").update(data).digest("hex") };
  }
  if (!options.keyId) {
    throw new TypeError("keyId is required with a keyed digest");
  }
  return {
    alg: "hmac-sha-256",
    value: createHmac("sha256", options.key).update(data).digest("hex"),
    key_id: options.keyId,
  };
}

function checkMembers(
  value: unknown,
  path: string,
  required: readonly string[],
  optional: readonly string[],
  errors: string[],
): value is Members {
  if (!isObject(value)) {
    errors.push(`${path}: must be an object`);
    return false;
  }
  for (const name of required) {
    if (!Object.hasOwn(value, name)) errors.push(`${path}.${name}: required member is missing`);
  }
  for (const name of Object.keys(value)) {
    if (!required.includes(name) && !optional.includes(name)) {
      errors.push(`${path}.${name}: unknown member (use ext for extensions)`);
    }
  }
  return true;
}

function checkDigest(value: unknown, path: string, errors: string[]): void {
  if (!checkMembers(value, path, ["alg", "value"], ["key_id"], errors)) return;
  const alg = value["alg"];
  if (!isOneOf(alg, DIGEST_ALGS)) {
    errors.push(`${path}.alg: must be one of ${DIGEST_ALGS.join(", ")}`);
  }
  if (!isHex64(value["value"])) {
    errors.push(`${path}.value: must be 64 lowercase hexadecimal characters`);
  }
  if (alg === "hmac-sha-256" && !isNonEmptyString(value["key_id"])) {
    errors.push(`${path}.key_id: required with hmac-sha-256`);
  }
  if (alg === "sha-256" && Object.hasOwn(value, "key_id")) {
    errors.push(`${path}.key_id: not permitted with sha-256`);
  }
}

function checkActor(actor: unknown, errors: string[]): void {
  if (!checkMembers(actor, "record.actor", ["principal", "agent"], ["parent_agent", "model"], errors)) return;
  for (const name of ["principal", "agent"]) {
    if (Object.hasOwn(actor, name) && !isNonEmptyString(actor[name])) {
      errors.push(`record.actor.${name}: must be a non-empty string`);
    }
  }
  if (Object.hasOwn(actor, "parent_agent") && !(actor["parent_agent"] === null || isNonEmptyString(actor["parent_agent"]))) {
    errors.push("record.actor.parent_agent: must be a non-empty string or null");
  }
  if (Object.hasOwn(actor, "model") && !isNonEmptyString(actor["model"])) {
    errors.push("record.actor.model: must be a non-empty string");
  }
}

function checkEvent(event: unknown, errors: string[]): void {
  const optional = ["content_digest", "source", "tool", "correlation_id"];
  if (!checkMembers(event, "record.event", ["type"], optional, errors)) return;
  if (!isOneOf(event["type"], EVENT_TYPES)) {
    errors.push(`record.event.type: must be one of ${EVENT_TYPES.join(", ")}`);
  }
  if (Object.hasOwn(event, "content_digest")) {
    checkDigest(event["content_digest"], "record.event.content_digest", errors);
  }
  for (const name of ["source", "correlation_id"]) {
    if (Object.hasOwn(event, name) && !isNonEmptyString(event[name])) {
      errors.push(`record.event.${name}: must be a non-empty string`);
    }
  }
  if (Object.hasOwn(event, "tool")) {
    const tool = event["tool"];
    if (checkMembers(tool, "record.event.tool", ["name"], ["arguments_digest"], errors)) {
      if (!isNonEmptyString(tool["name"])) {
        errors.push("record.event.tool.name: must be a non-empty string");
      }
      if (Object.hasOwn(tool, "arguments_digest")) {
        checkDigest(tool["arguments_digest"], "record.event.tool.arguments_digest", errors);
      }
    }
  }
  if (event["type"] === "tool_call" && !Object.hasOwn(event, "tool")) {
    errors.push("record.event.tool: required when event.type is tool_call");
  }
}

function checkDecision(decision: unknown, errors: string[]): void {
  if (!checkMembers(decision, "record.decision", ["verdict", "policy"], ["reason", "enforced_by"], errors)) return;
  if (!isOneOf(decision["verdict"], VERDICTS)) {
    errors.push(`record.decision.verdict: must be one of ${VERDICTS.join(", ")}`);
  }
  for (const name of ["reason", "enforced_by"]) {
    if (Object.hasOwn(decision, name) && !isNonEmptyString(decision[name])) {
      errors.push(`record.decision.${name}: must be a non-empty string`);
    }
  }
  if (Object.hasOwn(decision, "policy")) {
    const policy = decision["policy"];
    if (checkMembers(policy, "record.decision.policy", ["id", "version"], [], errors)) {
      for (const name of ["id", "version"]) {
        if (!isNonEmptyString(policy[name])) {
          errors.push(`record.decision.policy.${name}: must be a non-empty string`);
        }
      }
    }
  }
}

function checkScope(scope: unknown, errors: string[]): void {
  if (!checkMembers(scope, "record.scope", ["requested", "granted"], [], errors)) return;
  for (const name of ["requested", "granted"]) {
    const items = scope[name];
    if (!(Array.isArray(items) && items.every(isNonEmptyString))) {
      errors.push(`record.scope.${name}: must be an array of non-empty strings`);
    } else if (new Set(items).size !== items.length) {
      errors.push(`record.scope.${name}: must not contain duplicates`);
    }
  }
}

/**
 * Return a list of structural errors. An empty list means the record is well formed.
 *
 * This checks structure only (SPEC section 4). Hashes and chain links are
 * checked by chain verification.
 */
export function validateRecord(record: unknown): string[] {
  const errors: string[] = [];
  if (!checkMembers(record, "record", TOP_REQUIRED, TOP_OPTIONAL, errors)) return errors;
  const has = (name: string): boolean => Object.hasOwn(record, name);

  if (has("spec") && record["spec"] !== SPEC) {
    errors.push(`record.spec: must be '${SPEC}'`);
  }
  for (const name of ["chain_id", "record_id"]) {
    if (has(name) && !isNonEmptyString(record[name])) {
      errors.push(`record.${name}: must be a non-empty string`);
    }
  }
  if (has("sequence")) {
    const sequence = record["sequence"];
    if (!(isInteger(sequence) && sequence >= 0)) {
      errors.push("record.sequence: must be a non-negative integer");
    }
  }
  if (has("timestamp")) {
    const timestamp = record["timestamp"];
    if (!(typeof timestamp === "string" && TIMESTAMP.test(timestamp))) {
      errors.push("record.timestamp: must be RFC 3339 in UTC with a 'Z' suffix");
    }
  }
  for (const name of ["prev_hash", "record_hash"]) {
    if (has(name) && !isHex64(record[name])) {
      errors.push(`record.${name}: must be 64 lowercase hexadecimal characters`);
    }
  }

  if (has("actor")) checkActor(record["actor"], errors);
  if (has("event")) checkEvent(record["event"], errors);
  if (has("decision")) checkDecision(record["decision"], errors);
  if (has("scope")) checkScope(record["scope"], errors);

  if (has("ext")) {
    const ext = record["ext"];
    if (!isObject(ext)) {
      errors.push("record.ext: must be an object");
    } else {
      for (const key of Object.keys(ext)) {
        if (!EXT_KEY.test(key)) {
          errors.push(`record.ext.${key}: extension names use lowercase letters, digits, '.', '_' and '-'`);
        }
      }
    }
  }
  return errors;
}
