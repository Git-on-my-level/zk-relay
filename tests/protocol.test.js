import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { decryptContainer, encryptEnvelope, makeEnvelope } from "../public/crypto.js";
import { AAD_TEXT, MAX_PAYLOAD_BYTES, base64UrlToBytes, bytesToBase64Url, decodeCapabilityFragment } from "../public/protocol.js";
import { claimTransition, validateCreatePayload } from "../src/secret-object.js";

const vector = JSON.parse(await readFile(new URL("../protocol/test-vectors.json", import.meta.url), "utf8"));

test("browser Web Crypto produces the shared v1 test vector", async () => {
  const encrypted = await encryptEnvelope(vector.envelope, base64UrlToBytes(vector.key), base64UrlToBytes(vector.nonce));
  assert.equal(bytesToBase64Url(encrypted.ciphertext), vector.ciphertext);
  encrypted.ciphertext.fill(0);
  encrypted.key.fill(0);
  encrypted.nonce.fill(0);
});

test("browser decrypts the shared receiver-compatible v1 vector", async () => {
  const envelope = await decryptContainer({ v: 1, ciphertext: vector.ciphertext, nonce: vector.nonce, aad: AAD_TEXT }, base64UrlToBytes(vector.key));
  assert.deepEqual(
    { v: envelope.v, kind: envelope.kind, name: envelope.name, mediaType: envelope.mediaType, data: envelope.data },
    vector.envelope
  );
  assert.equal(new TextDecoder().decode(envelope.bytes), "zk-relay-interoperability");
  envelope.bytes.fill(0);
});

test("modified encrypted fields fail authentication without plaintext", async () => {
  const badCiphertext = `${vector.ciphertext.slice(0, -1)}${vector.ciphertext.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(
    decryptContainer({ v: 1, ciphertext: badCiphertext, nonce: vector.nonce, aad: AAD_TEXT }, base64UrlToBytes(vector.key)),
    /authenticate/
  );
  await assert.rejects(
    decryptContainer({ v: 1, ciphertext: vector.ciphertext, nonce: vector.nonce, aad: "zk-relay/v1;other" }, base64UrlToBytes(vector.key)),
    /Unsupported/
  );
  const badNonce = `${vector.nonce.slice(0, -1)}${vector.nonce.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(
    decryptContainer({ v: 1, ciphertext: vector.ciphertext, nonce: badNonce, aad: AAD_TEXT }, base64UrlToBytes(vector.key)),
    /authenticate/
  );
});

test("browser decrypts a zero-byte file envelope and enforces the payload limit", async () => {
  const emptyEnvelope = makeEnvelope("file", "empty.bin", "application/octet-stream", new Uint8Array());
  const encrypted = await encryptEnvelope(emptyEnvelope, base64UrlToBytes(vector.key), base64UrlToBytes(vector.nonce));
  const decoded = await decryptContainer({
    v: 1,
    ciphertext: bytesToBase64Url(encrypted.ciphertext),
    nonce: bytesToBase64Url(encrypted.nonce),
    aad: AAD_TEXT
  }, encrypted.key);
  assert.equal(decoded.kind, "file");
  assert.equal(decoded.bytes.length, 0);
  decoded.bytes.fill(0);
  encrypted.ciphertext.fill(0);
  encrypted.nonce.fill(0);
  encrypted.key.fill(0);

  const oversized = new Uint8Array(MAX_PAYLOAD_BYTES + 1);
  const oversizedEncrypted = await encryptEnvelope(
    makeEnvelope("file", "large.bin", "application/octet-stream", oversized),
    base64UrlToBytes(vector.key),
    base64UrlToBytes(vector.nonce)
  );
  oversized.fill(0);
  await assert.rejects(
    decryptContainer({
      v: 1,
      ciphertext: bytesToBase64Url(oversizedEncrypted.ciphertext),
      nonce: bytesToBase64Url(oversizedEncrypted.nonce),
      aad: AAD_TEXT
    }, oversizedEncrypted.key),
    /1 MiB/
  );
  oversizedEncrypted.ciphertext.fill(0);
  oversizedEncrypted.nonce.fill(0);
  oversizedEncrypted.key.fill(0);
});

test("capability fragments require independent 256-bit key and token", () => {
  const parsed = decodeCapabilityFragment(`#v1.${vector.key}.${vector.key}`);
  assert.equal(parsed.key.length, 32);
  assert.equal(parsed.token.length, 32);
  assert.throws(() => decodeCapabilityFragment("#v1.too-short.too-short"));
  assert.deepEqual(base64UrlToBytes(""), new Uint8Array());
});

test("create payload validation allows only v1 limits and encrypted metadata", () => {
  const valid = {
    v: 1,
    ciphertext: vector.ciphertext,
    nonce: vector.nonce,
    accessTokenHash: vector.key,
    expiresInSeconds: 3600,
    expireAfterReveal: true
  };
  assert.equal(validateCreatePayload(valid), true);
  assert.equal(validateCreatePayload({ ...valid, expiresInSeconds: 30 }), false);
  assert.equal(validateCreatePayload({ ...valid, nonce: "AA" }), false);
});

test("strict removing claim has exactly one winner and invalid token is non-mutating", async () => {
  const accessTokenHash = vector.key;
  let record = {
    ciphertext: vector.ciphertext,
    nonce: vector.nonce,
    aad: AAD_TEXT,
    access_token_hash: accessTokenHash,
    expires_at: Date.now() + 60_000,
    expire_after_reveal: 1,
    revealed_at: null
  };
  assert.equal(claimTransition(record, "not-the-token").kind, "invalid");
  assert.equal(record.ciphertext, vector.ciphertext);

  const claim = () => {
    const transition = claimTransition(record, accessTokenHash);
    if (transition.kind === "success" && transition.remove) record = { ...record, ciphertext: null, nonce: null, revealed_at: Date.now() };
    return transition.kind;
  };
  const outcomes = await Promise.all(Array.from({ length: 10 }, () => Promise.resolve().then(claim)));
  assert.equal(outcomes.filter((outcome) => outcome === "success").length, 1);
  assert.equal(outcomes.filter((outcome) => outcome === "gone").length, 9);
});

test("non-removing claim remains available until expiry", () => {
  const record = {
    ciphertext: vector.ciphertext,
    nonce: vector.nonce,
    aad: AAD_TEXT,
    access_token_hash: vector.key,
    expires_at: Date.now() + 60_000,
    expire_after_reveal: 0,
    revealed_at: null
  };
  assert.equal(claimTransition(record, vector.key).kind, "success");
  assert.equal(claimTransition(record, vector.key).kind, "success");
  assert.equal(claimTransition({ ...record, expires_at: Date.now() - 1 }, vector.key).kind, "unavailable");
});
