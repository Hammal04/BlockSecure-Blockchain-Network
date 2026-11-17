import test from "node:test";
import assert from "node:assert/strict";
import { isValidMessageId, isValidSha256, isValidBase64, validateRecordMessage } from "./validation.js";

test("validates message identifiers", () => {
  assert.equal(isValidMessageId("message_01-v2"), true);
  assert.equal(isValidMessageId("../private"), false);
  assert.equal(isValidMessageId(""), false);
});

test("validates SHA-256 hex digests", () => {
  assert.equal(isValidSha256("a".repeat(64)), true);
  assert.equal(isValidSha256("g".repeat(64)), false);
  assert.equal(isValidSha256("a".repeat(63)), false);
});

test("validates Base64 signatures", () => {
  assert.equal(isValidBase64(Buffer.from("signature").toString("base64")), true);
  assert.equal(isValidBase64("not base64!"), false);
});

test("accepts a valid RecordMessage request", () => {
  const errors = validateRecordMessage({
    messageId: "message_01",
    receiver: "receiver-01",
    messageHash: "a".repeat(64),
    signature: Buffer.from("signature").toString("base64"),
    signatureAlgorithm: "ECDSA-SHA256",
  });
  assert.deepEqual(errors, []);
});

test("rejects invalid and unsupported RecordMessage input", () => {
  const errors = validateRecordMessage({
    messageId: "../bad",
    receiver: "",
    messageHash: "invalid",
    signature: "???",
    signatureAlgorithm: "MD5",
  });
  assert.equal(errors.length, 5);
});
