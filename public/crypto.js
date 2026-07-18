import {
  AAD_TEXT,
  MAX_ENCRYPTED_CONTAINER_BYTES,
  MAX_PAYLOAD_BYTES,
  PROTOCOL_VERSION,
  base64UrlToBytes,
  bytesToBase64Url,
  randomBytes
} from "./protocol.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const BUNDLE_MEDIA_TYPE = "application/vnd.zk-relay.bundle+json";

export function makeEnvelope(kind, name, mediaType, payloadBytes) {
  return {
    v: PROTOCOL_VERSION,
    kind,
    name,
    mediaType,
    data: bytesToBase64Url(payloadBytes)
  };
}

export function makeBundleEnvelope(items) {
  if (!Array.isArray(items) || items.length < 1 || items.length > 2) {
    throw new Error("Bundles must contain one or two items");
  }
  let total = 0;
  const encoded = [];
  for (const item of items) {
    if (!item || (item.kind !== "text" && item.kind !== "file")) throw new Error("Invalid encrypted envelope");
    if (typeof item.name !== "string" || item.name.length === 0) throw new Error("Invalid encrypted envelope");
    if (typeof item.mediaType !== "string" || item.mediaType.length === 0) throw new Error("Invalid encrypted envelope");
    if (!(item.bytes instanceof Uint8Array)) throw new Error("Invalid encrypted envelope");
    total += item.bytes.length;
    if (total > MAX_PAYLOAD_BYTES) throw new Error("Payloads must be 1 MiB or smaller.");
    encoded.push({
      kind: item.kind,
      name: item.name,
      mediaType: item.mediaType,
      data: bytesToBase64Url(item.bytes)
    });
  }
  const payloadBytes = encoder.encode(JSON.stringify({ items: encoded }));
  return makeEnvelope("bundle", "bundle", BUNDLE_MEDIA_TYPE, payloadBytes);
}

export function decodeBundleItems(envelopeOrBytes) {
  const payloadBytes = envelopeOrBytes instanceof Uint8Array ? envelopeOrBytes : envelopeOrBytes.bytes;
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(payloadBytes));
  } catch {
    throw new Error("Invalid encrypted envelope");
  }
  if (!parsed || !Array.isArray(parsed.items) || parsed.items.length < 1 || parsed.items.length > 2) {
    throw new Error("Invalid encrypted envelope");
  }
  let total = 0;
  const items = [];
  for (const item of parsed.items) {
    if (!item || typeof item !== "object") throw new Error("Invalid encrypted envelope");
    const keys = Object.keys(item).sort();
    if (
      keys.join(",") !== "data,kind,mediaType,name" ||
      (item.kind !== "text" && item.kind !== "file") ||
      typeof item.name !== "string" ||
      item.name.length === 0 ||
      typeof item.mediaType !== "string" ||
      item.mediaType.length === 0 ||
      typeof item.data !== "string"
    ) {
      throw new Error("Invalid encrypted envelope");
    }
    const bytes = base64UrlToBytes(item.data);
    total += bytes.length;
    if (total > MAX_PAYLOAD_BYTES) {
      bytes.fill(0);
      throw new Error("Encrypted payload exceeds the 1 MiB limit");
    }
    items.push({ kind: item.kind, name: item.name, mediaType: item.mediaType, bytes });
  }
  return items;
}

export function encodeEnvelope(envelope) {
  return encoder.encode(JSON.stringify(envelope));
}

export async function encryptEnvelope(envelope, keyBytes = randomBytes(32), nonce = randomBytes(12)) {
  if (keyBytes.length !== 32 || nonce.length !== 12) throw new Error("Invalid encryption material");
  const plaintext = encodeEnvelope(envelope);
  try {
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(AAD_TEXT), tagLength: 128 },
      key,
      plaintext
    );
    return { ciphertext: new Uint8Array(encrypted), nonce: new Uint8Array(nonce), key: new Uint8Array(keyBytes) };
  } finally {
    plaintext.fill(0);
  }
}

export async function decryptContainer(container, keyBytes) {
  if (!container || container.v !== PROTOCOL_VERSION || container.aad !== AAD_TEXT || keyBytes.length !== 32) {
    throw new Error("Unsupported encrypted container");
  }
  const ciphertext = base64UrlToBytes(container.ciphertext);
  const nonce = base64UrlToBytes(container.nonce);
  if (ciphertext.length === 0 || ciphertext.length > MAX_ENCRYPTED_CONTAINER_BYTES || nonce.length !== 12) {
    ciphertext.fill(0);
    throw new Error("Invalid encrypted container");
  }
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  let plaintext;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(AAD_TEXT), tagLength: 128 },
      key,
      ciphertext
    ));
  } catch {
    throw new Error("Could not authenticate encrypted content");
  } finally {
    ciphertext.fill(0);
  }
  let payloadBytes = null;
  try {
    const envelope = JSON.parse(decoder.decode(plaintext));
    const keys = Object.keys(envelope).sort();
    if (
      keys.join(",") !== "data,kind,mediaType,name,v" ||
      envelope.v !== PROTOCOL_VERSION ||
      !["text", "file", "bundle"].includes(envelope.kind) ||
      typeof envelope.name !== "string" ||
      envelope.name.length === 0 ||
      typeof envelope.mediaType !== "string" ||
      envelope.mediaType.length === 0 ||
      typeof envelope.data !== "string"
    ) {
      throw new Error("Invalid encrypted envelope");
    }
    if (envelope.kind === "bundle" && envelope.mediaType !== BUNDLE_MEDIA_TYPE) {
      throw new Error("Invalid encrypted envelope");
    }
    payloadBytes = base64UrlToBytes(envelope.data);
    if (envelope.kind === "bundle") {
      if (payloadBytes.length > MAX_ENCRYPTED_CONTAINER_BYTES) throw new Error("Encrypted payload exceeds the 1 MiB limit");
      const items = decodeBundleItems(payloadBytes);
      return { ...envelope, bytes: payloadBytes, items };
    }
    if (payloadBytes.length > MAX_PAYLOAD_BYTES) throw new Error("Encrypted payload exceeds the 1 MiB limit");
    return { ...envelope, bytes: payloadBytes };
  } catch (error) {
    if (payloadBytes) payloadBytes.fill(0);
    if (error instanceof Error && error.message.startsWith("Encrypted payload")) throw error;
    if (error instanceof Error && error.message.startsWith("Payloads must")) throw error;
    throw new Error("Invalid encrypted envelope");
  } finally {
    plaintext.fill(0);
  }
}

export async function hashAccessToken(tokenBytes) {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", tokenBytes)));
}

export function safeDownloadName(name) {
  const candidate = String(name || "secret").replace(/[\\/:*?"<>|\u0000-\u001f]/g, "-").replace(/^\.+/, "").slice(0, 120);
  const reserved = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
  return !candidate || reserved.test(candidate) ? "secret" : candidate;
}
