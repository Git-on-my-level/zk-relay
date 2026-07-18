export const PROTOCOL_VERSION = 1;
export const AAD_TEXT = "relay/v1;envelope";
export const MAX_PAYLOAD_BYTES = 1024 * 1024;
// The encrypted envelope is kept below the Durable Object per-value limit.
// A 1 MiB payload plus its JSON/base64 envelope fits comfortably within this.
export const MAX_ENCRYPTED_CONTAINER_BYTES = 1_450_000;
export const ALLOWED_EXPIRIES = new Set([3600, 86400, 604800]);

export function bytesToBase64Url(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(value) {
  // Empty payload data is valid for a zero-byte attached file. Callers that
  // require non-empty capabilities or ciphertext enforce their own lengths.
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Invalid base64url value");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export function decodeCapabilityFragment(fragment) {
  const pieces = String(fragment || "").replace(/^#/, "").split(".");
  if (pieces.length !== 3 || pieces[0] !== "v1") throw new Error("This link has an unsupported capability format.");
  const key = base64UrlToBytes(pieces[1]);
  const token = base64UrlToBytes(pieces[2]);
  if (key.length !== 32 || token.length !== 32) throw new Error("This link has an invalid capability length.");
  return { key, token, keyText: pieces[1], tokenText: pieces[2] };
}

export function formatDuration(seconds) {
  if (seconds === 3600) return "1 hour";
  if (seconds === 86400) return "1 day";
  if (seconds === 604800) return "7 days";
  return "the selected time";
}
