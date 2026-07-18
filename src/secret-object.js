import {
  ALLOWED_EXPIRIES,
  AAD_TEXT,
  MAX_ENCRYPTED_CONTAINER_BYTES,
  PROTOCOL_VERSION,
  base64UrlToBytes,
  bytesToBase64Url
} from "../public/protocol.js";

const INVALID_ATTEMPT_LIMIT = 12;
const INVALID_ATTEMPT_WINDOW_MS = 60_000;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store, max-age=0" }
  });
}

function empty(status) {
  return new Response(null, { status, headers: { "cache-control": "no-store, max-age=0" } });
}

function timingSafeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index += 1) different |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return different === 0;
}

async function tokenHash(tokenText) {
  const token = base64UrlToBytes(tokenText);
  if (token.length !== 32) throw new Error("Invalid token");
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", token)));
}

export function validateCreatePayload(payload) {
  if (!payload || payload.v !== PROTOCOL_VERSION || !ALLOWED_EXPIRIES.has(payload.expiresInSeconds)) return false;
  if (typeof payload.ciphertext !== "string" || typeof payload.nonce !== "string" || typeof payload.accessTokenHash !== "string") return false;
  if (typeof payload.expireAfterReveal !== "boolean") return false;
  try {
    const ciphertext = base64UrlToBytes(payload.ciphertext);
    const nonce = base64UrlToBytes(payload.nonce);
    const accessTokenHash = base64UrlToBytes(payload.accessTokenHash);
    return ciphertext.length > 0 && ciphertext.length <= MAX_ENCRYPTED_CONTAINER_BYTES && nonce.length === 12 && accessTokenHash.length === 32;
  } catch {
    return false;
  }
}

export function claimTransition(record, suppliedHash, now = Date.now()) {
  if (!record || now >= record.expires_at) return { kind: "unavailable" };
  if (record.revealed_at !== null || record.ciphertext === null || record.nonce === null) return { kind: "gone" };
  if (!timingSafeEqual(record.access_token_hash, suppliedHash)) return { kind: "invalid" };
  return {
    kind: "success",
    remove: record.expire_after_reveal === 1,
    container: { v: PROTOCOL_VERSION, ciphertext: record.ciphertext, nonce: record.nonce, aad: record.aad }
  };
}

export class SecretObject {
  constructor(ctx) {
    this.ctx = ctx;
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS secret (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version INTEGER NOT NULL,
        ciphertext TEXT,
        nonce TEXT,
        aad TEXT NOT NULL,
        access_token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        expire_after_reveal INTEGER NOT NULL,
        revealed_at INTEGER,
        invalid_attempts INTEGER NOT NULL DEFAULT 0,
        invalid_window_started_at INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  getRecord() {
    return this.ctx.storage.sql.exec("SELECT * FROM secret WHERE singleton = 1").toArray()[0] || null;
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (request.method === "POST" && path === "/internal/create") return this.create(request);
    if (request.method === "GET" && path === "/internal/status") return this.status();
    if (request.method === "POST" && path === "/internal/reveal") return this.reveal(request);
    return empty(404);
  }

  async create(request) {
    let payload;
    try {
      payload = await request.json();
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
    if (!validateCreatePayload(payload) || this.getRecord()) return json({ error: "invalid_request" }, 400);

    const now = Date.now();
    const expiresAt = now + payload.expiresInSeconds * 1000;
    this.ctx.storage.sql.exec(
      `INSERT INTO secret (
        singleton, version, ciphertext, nonce, aad, access_token_hash, created_at,
        expires_at, expire_after_reveal, revealed_at, invalid_attempts, invalid_window_started_at
      ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0)`,
      PROTOCOL_VERSION,
      payload.ciphertext,
      payload.nonce,
      AAD_TEXT,
      payload.accessTokenHash,
      now,
      expiresAt,
      payload.expireAfterReveal ? 1 : 0
    );
    await this.ctx.storage.setAlarm(expiresAt);
    return json({ v: PROTOCOL_VERSION, state: "available", expiresAt: new Date(expiresAt).toISOString() }, 201);
  }

  async status() {
    const record = this.getRecord();
    if (!record) return json({ v: PROTOCOL_VERSION, state: "unavailable" }, 410);
    if (Date.now() >= record.expires_at) {
      await this.expire();
      return json({ v: PROTOCOL_VERSION, state: "unavailable" }, 410);
    }
    if (record.revealed_at !== null || record.ciphertext === null) return json({ v: PROTOCOL_VERSION, state: "unavailable" }, 410);
    return json({
      v: PROTOCOL_VERSION,
      state: "available",
      expiresAt: new Date(record.expires_at).toISOString(),
      expireAfterReveal: record.expire_after_reveal === 1
    });
  }

  async reveal(request) {
    const authorization = request.headers.get("authorization") || "";
    const match = /^ZKRelay ([A-Za-z0-9_-]+)$/.exec(authorization);
    let suppliedHash = "";
    try {
      suppliedHash = match ? await tokenHash(match[1]) : "";
    } catch {
      suppliedHash = "";
    }

    const record = this.getRecord();
    const now = Date.now();
    if (!record) return json({ error: "unavailable" }, 410);
    if (now >= record.expires_at) {
      await this.expire();
      return json({ error: "unavailable" }, 410);
    }

    const transition = claimTransition(record, suppliedHash, now);
    if (transition.kind === "gone" || transition.kind === "unavailable") return json({ error: "unavailable" }, 410);
    if (transition.kind === "invalid") {
      if (this.recordInvalidAttempt(record, now)) return json({ error: "unavailable" }, 429);
      return json({ error: "unavailable" }, 404);
    }

    if (transition.remove) {
      // This synchronous read/update sequence is atomic within this Durable Object.
      this.ctx.storage.sql.exec(
        "UPDATE secret SET ciphertext = NULL, nonce = NULL, revealed_at = ? WHERE singleton = 1 AND revealed_at IS NULL",
        now
      );
    }
    return json(transition.container);
  }

  recordInvalidAttempt(record, now) {
    const windowStart = record.invalid_window_started_at;
    const attempts = now - windowStart > INVALID_ATTEMPT_WINDOW_MS ? 1 : record.invalid_attempts + 1;
    const nextWindow = now - windowStart > INVALID_ATTEMPT_WINDOW_MS ? now : windowStart;
    this.ctx.storage.sql.exec(
      "UPDATE secret SET invalid_attempts = ?, invalid_window_started_at = ? WHERE singleton = 1",
      attempts,
      nextWindow
    );
    return attempts > INVALID_ATTEMPT_LIMIT;
  }

  async expire() {
    this.ctx.storage.sql.exec("DELETE FROM secret WHERE singleton = 1");
    await this.ctx.storage.deleteAlarm();
  }

  async alarm() {
    await this.expire();
  }
}
