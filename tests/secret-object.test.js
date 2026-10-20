import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { bytesToBase64Url, base64UrlToBytes } from "../public/protocol.js";
import { SecretObject } from "../src/secret-object.js";

const vector = JSON.parse(await readFile(new URL("../protocol/test-vectors.json", import.meta.url), "utf8"));

class MemorySql {
  record = null;
  columns = ["singleton", "min_receiver"];

  exec(statement, ...params) {
    const normalized = statement.replace(/\s+/g, " ").trim();
    if (normalized.startsWith("CREATE TABLE")) return this.cursor();
    if (normalized.startsWith("PRAGMA table_info(secret)")) return this.cursor(this.columns.map((name) => ({ name })));
    if (normalized.startsWith("ALTER TABLE secret ADD COLUMN min_receiver")) {
      this.columns.push("min_receiver");
      return this.cursor();
    }
    if (normalized.startsWith("SELECT * FROM secret")) return this.cursor(this.record ? [{ ...this.record }] : []);
    if (normalized.startsWith("INSERT INTO secret")) {
      const [version, ciphertext, nonce, aad, accessTokenHash, createdAt, expiresAt, expireAfterReveal, minReceiver] = params;
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
        invalid_window_started_at: 0,
        min_receiver: minReceiver
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

function objectFixture(columns) {
  const sql = new MemorySql();
  if (columns) sql.columns = columns;
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

async function create(object, { expireAfterReveal = true, expiresInSeconds = 3600, minReceiver } = {}) {
  const response = await object.fetch(new Request("https://zk-relay.internal/internal/create", {
    method: "POST",
    body: JSON.stringify({
      v: 1,
      ciphertext: vector.ciphertext,
      nonce: vector.nonce,
      accessTokenHash: await accessTokenHash(vector.key),
      expiresInSeconds,
      expireAfterReveal,
      minReceiver
    })
  }));
  assert.equal(response.status, 201);
}

function reveal(object, headers = {}) {
  return object.fetch(new Request("https://zk-relay.internal/internal/reveal", {
    method: "POST",
    headers: { authorization: `zk-relay ${vector.key}`, ...headers }
  }));
}

async function status(object) {
  return (await object.fetch(new Request("https://zk-relay.internal/internal/status"))).json();
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

test("older objects gain the min_receiver column", () => {
  const { sql } = objectFixture(["singleton"]);
  assert.ok(sql.columns.includes("min_receiver"));
});

test("level-1 secrets omit minReceiver so older receivers can parse status", async () => {
  const { object } = objectFixture();
  await create(object);
  assert.equal("minReceiver" in await status(object), false);
  assert.equal((await reveal(object)).status, 200);
});

test("an outdated receiver is refused without consuming a one-shot secret", async () => {
  const { object, sql } = objectFixture();
  await create(object, { minReceiver: 2 });
  assert.equal((await status(object)).minReceiver, 2);
  const refused = await reveal(object);
  assert.equal(refused.status, 426);
  assert.deepEqual(await refused.json(), { error: "receiver_upgrade_required", minReceiver: 2 });
  assert.equal(sql.record.ciphertext, vector.ciphertext);
  assert.equal(sql.record.revealed_at, null);
  const accepted = await reveal(object, { "zk-relay-receiver": "2" });
  assert.equal(accepted.status, 200);
  assert.equal(sql.record.ciphertext, null);
});

test("the receiver-level check never bypasses the token check", async () => {
  const { object } = objectFixture();
  await create(object, { minReceiver: 2 });
  const response = await reveal(object, { authorization: "zk-relay AAECAwQFBgcICQoLDA0ODw" });
  assert.equal(response.status, 404);
});

test("create rejects unknown receiver levels", async () => {
  const { object } = objectFixture();
  for (const minReceiver of [0, 3, 1.5, "2"]) {
    const response = await object.fetch(new Request("https://zk-relay.internal/internal/create", {
      method: "POST",
      body: JSON.stringify({ v: 1, ciphertext: vector.ciphertext, nonce: vector.nonce, accessTokenHash: await accessTokenHash(vector.key), expiresInSeconds: 3600, expireAfterReveal: true, minReceiver })
    }));
    assert.equal(response.status, 400);
  }
});
