import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { bytesToBase64Url, base64UrlToBytes } from "../public/protocol.js";
import { SecretObject } from "../src/secret-object.js";

const vector = JSON.parse(await readFile(new URL("../protocol/test-vectors.json", import.meta.url), "utf8"));

class MemorySql {
  record = null;

  exec(statement, ...params) {
    const normalized = statement.replace(/\s+/g, " ").trim();
    if (normalized.startsWith("CREATE TABLE")) return this.cursor();
    if (normalized.startsWith("SELECT * FROM secret")) return this.cursor(this.record ? [{ ...this.record }] : []);
    if (normalized.startsWith("INSERT INTO secret")) {
      const [version, ciphertext, nonce, aad, accessTokenHash, createdAt, expiresAt, expireAfterReveal] = params;
      this.record = {
        singleton: 1,
        version,
        ciphertext,
        nonce,
        aad,
        access_token_hash: accessTokenHash,
        created_at: createdAt,
        expires_at: expiresAt,
        expire_after_reveal: expireAfterReveal,
        revealed_at: null,
        invalid_attempts: 0,
        invalid_window_started_at: 0
      };
      return this.cursor([], 1);
    }
    if (normalized.startsWith("UPDATE secret SET ciphertext = NULL")) {
      if (this.record && this.record.revealed_at === null) {
        this.record.ciphertext = null;
        this.record.nonce = null;
        this.record.revealed_at = params[0];
      }
      return this.cursor([], 1);
    }
    if (normalized.startsWith("UPDATE secret SET invalid_attempts")) {
      this.record.invalid_attempts = params[0];
      this.record.invalid_window_started_at = params[1];
      return this.cursor([], 1);
    }
    if (normalized.startsWith("DELETE FROM secret")) {
      this.record = null;
      return this.cursor([], 1);
    }
    throw new Error(`Unexpected SQL: ${normalized}`);
  }

  cursor(rows = [], rowsWritten = 0) {
    return { toArray: () => rows, rowsWritten };
  }
}

function objectFixture() {
  const sql = new MemorySql();
  const ctx = {
    storage: {
      sql,
      setAlarm: async () => {},
      deleteAlarm: async () => {}
    }
  };
  return { sql, object: new SecretObject(ctx) };
}

async function accessTokenHash(tokenText) {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", base64UrlToBytes(tokenText))));
}

async function create(object, { expireAfterReveal = true, expiresInSeconds = 3600 } = {}) {
  const response = await object.fetch(new Request("https://zk-relay.internal/internal/create", {
    method: "POST",
    body: JSON.stringify({
      v: 1,
      ciphertext: vector.ciphertext,
      nonce: vector.nonce,
      accessTokenHash: await accessTokenHash(vector.key),
      expiresInSeconds,
      expireAfterReveal
    })
  }));
  assert.equal(response.status, 201);
}

test("safe status does not return or remove ciphertext", async () => {
  const { object, sql } = objectFixture();
  await create(object);
  const response = await object.fetch(new Request("https://zk-relay.internal/internal/status"));
  const status = await response.json();
  assert.equal(status.state, "available");
  assert.equal("ciphertext" in status, false);
  assert.equal(sql.record.ciphertext, vector.ciphertext);
});

test("invalid access tokens do not reveal or remove ciphertext", async () => {
  const { object, sql } = objectFixture();
  await create(object);
  const response = await object.fetch(new Request("https://zk-relay.internal/internal/reveal", {
    method: "POST",
    headers: { authorization: "zk-relay AAECAwQFBgcICQoLDA0ODw" }
  }));
  assert.equal(response.status, 404);
  assert.equal(sql.record.ciphertext, vector.ciphertext);
  assert.equal(sql.record.invalid_attempts, 1);
});

test("two simultaneous removing reveals produce one encrypted response", async () => {
  const { object, sql } = objectFixture();
  await create(object, { expireAfterReveal: true });
  const reveal = () => object.fetch(new Request("https://zk-relay.internal/internal/reveal", {
    method: "POST",
    headers: { authorization: `zk-relay ${vector.key}` }
  }));
  const responses = await Promise.all([reveal(), reveal()]);
  const statuses = responses.map((response) => response.status).sort();
  assert.deepEqual(statuses, [200, 410]);
  const winning = responses.find((response) => response.status === 200);
  const container = await winning.json();
  assert.equal(container.ciphertext, vector.ciphertext);
  assert.equal(sql.record.ciphertext, null);
  assert.equal(sql.record.nonce, null);
  assert.ok(sql.record.revealed_at);
});

test("non-removing reveal can return ciphertext repeatedly", async () => {
  const { object, sql } = objectFixture();
  await create(object, { expireAfterReveal: false });
  for (let index = 0; index < 2; index += 1) {
    const response = await object.fetch(new Request("https://zk-relay.internal/internal/reveal", {
      method: "POST",
      headers: { authorization: `zk-relay ${vector.key}` }
    }));
    assert.equal(response.status, 200);
  }
  assert.equal(sql.record.ciphertext, vector.ciphertext);
});

test("expired state is unavailable even before its alarm runs", async () => {
  const { object, sql } = objectFixture();
  await create(object);
  sql.record.expires_at = Date.now() - 1;
  const response = await object.fetch(new Request("https://zk-relay.internal/internal/status"));
  assert.equal(response.status, 410);
  assert.equal(sql.record, null);
});
