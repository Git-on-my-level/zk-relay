import {
  AAD_TEXT,
  PROTOCOL_VERSION,
  base64UrlToBytes,
  bytesToBase64Url,
  randomBytes
} from "./protocol.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
  if (nonce.length !== 12) throw new Error("Invalid nonce");
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
  }
  try {
    const envelope = JSON.parse(decoder.decode(plaintext));
    if (envelope.v !== PROTOCOL_VERSION || !["text", "file"].includes(envelope.kind) || typeof envelope.name !== "string" || typeof envelope.mediaType !== "string" || typeof envelope.data !== "string") {
      throw new Error("Invalid encrypted envelope");
    }
    return { ...envelope, bytes: base64UrlToBytes(envelope.data) };
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
