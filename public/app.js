import { MAX_PAYLOAD_BYTES, base64UrlToBytes, bytesToBase64Url, decodeCapabilityFragment, formatDuration, randomBytes } from "./protocol.js";
import { decryptContainer, encryptEnvelope, hashAccessToken, makeEnvelope, safeDownloadName } from "./crypto.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const el = (id) => document.getElementById(id);
const elements = {
  creationView: el("creation-view"),
  shareView: el("share-view"),
  humanView: el("human-view"),
  creationForm: el("creation-form"),
  secretInput: el("secret-input"),
  secretVisibility: el("secret-visibility"),
  secretState: el("secret-state"),
  fileInput: el("file-input"),
  attachFile: el("attach-file"),
  fileStatus: el("file-status"),
  keepAfterReveal: el("keep-after-reveal"),
  createLinks: el("create-links"),
  creationError: el("creation-error"),
  humanLink: el("human-link"),
  agentLink: el("agent-link"),
  expiryStatus: el("expiry-status"),
  toast: el("toast"),
  humanExplanation: el("human-explanation"),
  revealSecret: el("reveal-secret"),
  humanError: el("human-error"),
  humanResult: el("human-result"),
  revealedText: el("revealed-text"),
  resultVisibility: el("result-visibility"),
  resultCopy: el("result-copy"),
  fileDownload: el("file-download")
};

let secretText = "";
let selectedFile = null;
let secretIsVisible = false;
let selectedDuration = 3600;
let capability = null;
let revealedText = "";
let resultIsVisible = false;
let downloadUrl = null;
let toastTimer = null;

function setAccentColor() {
  const color = document.body.dataset.accentColor;
  if (/^#[0-9a-f]{6}$/i.test(color || "")) document.documentElement.style.setProperty("--green", color);
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("is-visible"), 2200);
}

function maskValue(value) {
  return value.replace(/[^\n]/g, "•");
}

function setSecretInput(value, selectionStart = null) {
  secretText = value;
  const display = secretIsVisible ? secretText : maskValue(secretText);
  elements.secretInput.value = display;
  elements.secretInput.classList.toggle("is-masked", !secretIsVisible);
  elements.secretVisibility.textContent = secretIsVisible ? "Hide" : "Show";
  elements.secretVisibility.setAttribute("aria-pressed", String(secretIsVisible));
  elements.secretVisibility.setAttribute("aria-label", secretIsVisible ? "Hide secret" : "Show secret");
  elements.secretState.textContent = secretIsVisible
    ? "Secret is visible. Use Hide to mask it."
    : `Secret is hidden. ${secretText.length} characters entered. Use Show to reveal it.`;
  elements.secretInput.setAttribute("aria-valuetext", elements.secretState.textContent);
  if (selectionStart !== null) {
    elements.secretInput.setSelectionRange(selectionStart, selectionStart);
  }
  updateCreateButton();
}

function updateCreateButton() {
  elements.createLinks.disabled = !selectedFile && secretText.length === 0;
}

function replaceMaskedSelection(inserted, mode = "insert") {
  const input = elements.secretInput;
  const start = input.selectionStart ?? 0;
  const end = input.selectionEnd ?? start;
  let next = secretText;
  let caret = start;
  if (mode === "backward") {
    const deleteStart = start === end ? Math.max(0, start - 1) : start;
    next = secretText.slice(0, deleteStart) + secretText.slice(end);
    caret = deleteStart;
  } else if (mode === "forward") {
    const deleteEnd = start === end ? Math.min(secretText.length, end + 1) : end;
    next = secretText.slice(0, start) + secretText.slice(deleteEnd);
  } else {
    next = secretText.slice(0, start) + inserted + secretText.slice(end);
    caret = start + inserted.length;
  }
  if (selectedFile) {
    selectedFile = null;
    elements.fileInput.value = "";
    elements.fileStatus.textContent = "";
  }
  setSecretInput(next, caret);
}

function onSecretBeforeInput(event) {
  if (secretIsVisible || event.isComposing) return;
  const type = event.inputType;
  if (type === "insertText" || type === "insertCompositionText" || type === "insertFromPaste") {
    event.preventDefault();
    replaceMaskedSelection(event.data || "");
  } else if (type === "insertLineBreak" || type === "insertParagraph") {
    event.preventDefault();
    replaceMaskedSelection("\n");
  } else if (type === "deleteContentBackward") {
    event.preventDefault();
    replaceMaskedSelection("", "backward");
  } else if (type === "deleteContentForward") {
    event.preventDefault();
    replaceMaskedSelection("", "forward");
  } else if (type.startsWith("delete")) {
    event.preventDefault();
    replaceMaskedSelection("", "forward");
  }
}

function onSecretInput() {
  if (!secretIsVisible) return;
  if (selectedFile) {
    selectedFile = null;
    elements.fileInput.value = "";
    elements.fileStatus.textContent = "";
  }
  setSecretInput(elements.secretInput.value);
}

function activateCreationView() {
  elements.creationView.hidden = false;
  elements.shareView.hidden = true;
  elements.humanView.hidden = true;
  setSecretInput(secretText);
}

function setDuration(seconds) {
  selectedDuration = seconds;
  document.querySelectorAll(".duration-option").forEach((button) => {
    const selected = Number(button.dataset.seconds) === seconds;
    button.classList.toggle("is-selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
}

async function attachFile() {
  elements.fileInput.click();
}

async function chooseFile() {
  const file = elements.fileInput.files?.[0];
  if (!file) return;
  if (file.size > MAX_PAYLOAD_BYTES) {
    elements.creationError.textContent = "Files must be 1 MiB or smaller.";
    elements.fileInput.value = "";
    return;
  }
  if (secretText.length > 0 && !window.confirm("Replace the text with this file?")) {
    elements.fileInput.value = "";
    return;
  }
  secretText = "";
  selectedFile = file;
  elements.creationError.textContent = "";
  elements.fileStatus.textContent = file.name;
  setSecretInput("");
}

async function createLinks(event) {
  event.preventDefault();
  if (!selectedFile && !secretText.length) return;
  elements.creationError.textContent = "";
  elements.createLinks.disabled = true;
  elements.createLinks.querySelector("span").textContent = "Creating secure links";

  let payloadBytes;
  let envelope;
  let key;
  let token;
  try {
    if (selectedFile) {
      payloadBytes = new Uint8Array(await selectedFile.arrayBuffer());
      envelope = makeEnvelope("file", selectedFile.name, selectedFile.type || "application/octet-stream", payloadBytes);
    } else {
      payloadBytes = textEncoder.encode(secretText);
      envelope = makeEnvelope("text", "secret.txt", "text/plain; charset=utf-8", payloadBytes);
    }
    if (payloadBytes.length > MAX_PAYLOAD_BYTES) throw new Error("Payloads must be 1 MiB or smaller.");
    payloadBytes.fill(0);
    const encrypted = await encryptEnvelope(envelope);
    key = encrypted.key;
    token = randomBytes(32);
    const keyText = bytesToBase64Url(key);
    const tokenText = bytesToBase64Url(token);
    const body = {
      v: 1,
      ciphertext: bytesToBase64Url(encrypted.ciphertext),
      nonce: bytesToBase64Url(encrypted.nonce),
      accessTokenHash: await hashAccessToken(token),
      expiresInSeconds: selectedDuration,
      expireAfterReveal: !elements.keepAfterReveal.checked
    };
    encrypted.ciphertext.fill(0);
    encrypted.nonce.fill(0);
    const result = await fetch("/api/v1/secrets", {
      method: "POST",
      headers: { "content-type": "application/json" },
      cache: "no-store",
      body: JSON.stringify(body)
    });
    if (!result.ok) throw new Error("The secure links could not be created. Please try again.");
    const created = await result.json();
    const origin = window.location.origin;
    elements.humanLink.value = `${origin}/h/${created.id}#v1.${keyText}.${tokenText}`;
    elements.agentLink.value = `${origin}/a/${created.id}#v1.${keyText}.${tokenText}`;
    elements.humanLink.type = "password";
    elements.agentLink.type = "password";
    elements.expiryStatus.textContent = `Expires in ${formatDuration(selectedDuration)}`;
    elements.creationView.hidden = true;
    elements.shareView.hidden = false;
    secretText = "";
    selectedFile = null;
    elements.fileInput.value = "";
    elements.fileStatus.textContent = "";
    setSecretInput("");
  } catch (error) {
    elements.creationError.textContent = error instanceof Error ? error.message : "The secure links could not be created. Please try again.";
  } finally {
    if (key) key.fill(0);
    if (token) token.fill(0);
    elements.createLinks.querySelector("span").textContent = "Create secure links";
    updateCreateButton();
  }
}

function toggleLinkVisibility(button) {
  const input = el(button.dataset.target);
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  const label = input.getAttribute("aria-label");
  button.setAttribute("aria-label", `${showing ? "Show" : "Hide"} ${label}`);
}

async function copyValue(value, input) {
  try {
    await navigator.clipboard.writeText(value);
    showToast("Copied");
  } catch {
    input.type = "text";
    input.focus();
    input.select();
    showToast("Copy the selected link.");
  }
}

function setResultText(value) {
  revealedText = value;
  elements.revealedText.value = resultIsVisible ? revealedText : maskValue(revealedText);
  elements.revealedText.classList.toggle("is-masked", !resultIsVisible);
  elements.resultVisibility.textContent = resultIsVisible ? "Hide" : "Show";
  elements.resultVisibility.setAttribute("aria-pressed", String(resultIsVisible));
}

function clearDownload() {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null;
  elements.fileDownload.hidden = true;
  elements.fileDownload.removeAttribute("href");
}

async function loadHumanStatus(id) {
  try {
    const result = await fetch(`/api/v1/secrets/${encodeURIComponent(id)}/status`, { cache: "no-store" });
    const status = await result.json();
    if (!result.ok || status.state !== "available") throw new Error("The secret is no longer available.");
    elements.humanExplanation.textContent = status.expireAfterReveal
      ? "You can look at this page safely. Revealing the secret will make the link stop working."
      : "You can look at this page safely. This link works until it expires.";
    if (capability) elements.revealSecret.disabled = false;
  } catch (error) {
    elements.humanError.textContent = error instanceof Error ? error.message : "The secret is no longer available.";
  }
}

async function revealHumanSecret(id) {
  if (!capability) return;
  elements.revealSecret.disabled = true;
  elements.humanError.textContent = "";
  try {
    const result = await fetch(`/api/v1/secrets/${encodeURIComponent(id)}/reveal`, {
      method: "POST",
      headers: { authorization: `Relay ${capability.tokenText}`, accept: "application/vnd.relay.encrypted+json" },
      cache: "no-store"
    });
    if (!result.ok) throw new Error("The secret is no longer available.");
    const envelope = await decryptContainer(await result.json(), capability.key);
    if (envelope.kind === "text") {
      resultIsVisible = false;
      setResultText(textDecoder.decode(envelope.bytes));
      elements.humanResult.hidden = false;
      clearDownload();
    } else {
      clearDownload();
      downloadUrl = URL.createObjectURL(new Blob([envelope.bytes], { type: envelope.mediaType }));
      elements.fileDownload.href = downloadUrl;
      elements.fileDownload.download = safeDownloadName(envelope.name);
      elements.fileDownload.textContent = "Download file";
      elements.fileDownload.hidden = false;
      elements.humanResult.hidden = true;
    }
    envelope.bytes.fill(0);
    capability.key.fill(0);
    capability.token.fill(0);
    capability = null;
  } catch (error) {
    elements.humanError.textContent = error instanceof Error ? error.message : "The secret could not be revealed.";
  }
}

function setupHumanRoute() {
  const match = /^\/h\/([A-Za-z0-9_-]+)$/.exec(window.location.pathname);
  if (!match) return false;
  elements.creationView.hidden = true;
  elements.shareView.hidden = true;
  elements.humanView.hidden = false;
  try {
    capability = decodeCapabilityFragment(window.location.hash);
    history.replaceState(null, "", window.location.pathname);
  } catch {
    elements.humanError.textContent = "This page needs the original complete link to reveal the secret.";
  }
  loadHumanStatus(match[1]);
  elements.revealSecret.addEventListener("click", () => revealHumanSecret(match[1]));
  return true;
}

function clearSensitiveState() {
  secretText = "";
  revealedText = "";
  selectedFile = null;
  elements.secretInput.value = "";
  elements.humanLink.value = "";
  elements.agentLink.value = "";
  elements.revealedText.value = "";
  if (capability) {
    capability.key.fill(0);
    capability.token.fill(0);
    capability = null;
  }
  clearDownload();
}

function initialize() {
  setAccentColor();
  if (setupHumanRoute()) return;
  activateCreationView();
  elements.secretInput.addEventListener("beforeinput", onSecretBeforeInput);
  elements.secretInput.addEventListener("input", onSecretInput);
  elements.secretInput.addEventListener("paste", (event) => {
    if (!secretIsVisible) {
      event.preventDefault();
      replaceMaskedSelection(event.clipboardData?.getData("text/plain") || "");
    }
  });
  elements.secretVisibility.addEventListener("click", () => {
    secretIsVisible = !secretIsVisible;
    setSecretInput(secretText, elements.secretInput.selectionStart ?? secretText.length);
  });
  elements.attachFile.addEventListener("click", attachFile);
  elements.fileInput.addEventListener("change", chooseFile);
  document.querySelectorAll(".duration-option").forEach((button) => button.addEventListener("click", () => setDuration(Number(button.dataset.seconds))));
  elements.creationForm.addEventListener("submit", createLinks);
  document.querySelectorAll(".link-visibility").forEach((button) => button.addEventListener("click", () => toggleLinkVisibility(button)));
  document.querySelectorAll(".copy-link").forEach((button) => button.addEventListener("click", () => {
    const input = el(button.dataset.target);
    copyValue(input.value, input);
  }));
  elements.resultVisibility.addEventListener("click", () => {
    resultIsVisible = !resultIsVisible;
    setResultText(revealedText);
  });
  elements.resultCopy.addEventListener("click", () => copyValue(revealedText, elements.revealedText));
  window.addEventListener("pagehide", clearSensitiveState, { once: true });
}

initialize();
