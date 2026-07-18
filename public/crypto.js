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

export function makeEnvelope(kind, name, mediaType, payloadBytes) {
  return {
    v: PROTOCOL_VERSION,
    kind,
    name,
    mediaType,
    data: bytesToBase64Url(payloadBytes)
  };
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
      !["text", "file"].includes(envelope.kind) ||
      typeof envelope.name !== "string" ||
      envelope.name.length === 0 ||
      typeof envelope.mediaType !== "string" ||
      envelope.mediaType.length === 0 ||
      typeof envelope.data !== "string"
    ) {
      throw new Error("Invalid encrypted envelope");
    }
    payloadBytes = base64UrlToBytes(envelope.data);
    if (payloadBytes.length > MAX_PAYLOAD_BYTES) throw new Error("Encrypted payload exceeds the 1 MiB limit");
    return { ...envelope, bytes: payloadBytes };
  } catch (error) {
    if (payloadBytes) payloadBytes.fill(0);
    if (error instanceof Error && error.message.startsWith("Encrypted payload")) throw error;
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
