import { MAX_PAYLOAD_BYTES, base64UrlToBytes, bytesToBase64Url, decodeCapabilityFragment, formatDuration, randomBytes } from "./protocol.js";
import { decodeBundleItems, decryptContainer, encryptEnvelope, hashAccessToken, makeBundleEnvelope, makeEnvelope, safeDownloadName } from "./crypto.js";

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
  secretCount: el("secret-count"),
  fileInput: el("file-input"),
  attachFile: el("attach-file"),
  fileChip: el("file-chip"),
  fileStatus: el("file-status"),
  fileSize: el("file-size"),
  fileRemove: el("file-remove"),
  fileNote: el("file-note"),
  expireAfterReveal: el("expire-after-reveal"),
  expireLabel: el("expire-label"),
  expireHint: el("expire-hint"),
  ledgerReveal: el("ledger-reveal"),
  ledgerExpiry: el("ledger-expiry"),
  createLinks: el("create-links"),
  creationError: el("creation-error"),
  humanLink: el("human-link"),
  agentLink: el("agent-link"),
  expiryStatus: el("expiry-status"),
  shareRevealStatus: el("share-reveal-status"),
  shareAnother: el("share-another"),
  copyStatus: el("copy-status"),
  humanExplanation: el("human-explanation"),
  humanNotice: el("human-notice"),
  humanNoticeText: el("human-notice-text"),
  spentNote: el("spent-note"),
  revealSecret: el("reveal-secret"),
  humanError: el("human-error"),
  humanResult: el("human-result"),
  resultField: el("result-field"),
  resultActions: el("result-actions"),
  revealedText: el("revealed-text"),
  resultVisibility: el("result-visibility"),
  resultCopy: el("result-copy"),
  fileDownload: el("file-download"),
  imagePreview: el("image-preview"),
  imageFrame: el("image-frame"),
  previewImage: el("preview-image"),
  previewVisibility: el("preview-visibility")
};

const PREFS_KEY = "zk-relay:create-prefs";
const SIZE_WARNING_BYTES = MAX_PAYLOAD_BYTES * 0.75;
// Only raster formats the browser decodes inertly. SVG can carry script, so it
// stays a download.
const PREVIEW_MEDIA_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);

let secretText = "";
let selectedFile = null;
let secretIsVisible = false;
let selectedDuration = 3600;
let capability = null;
let humanExpireAfterReveal = true;
let revealedText = "";
let resultIsVisible = false;
let downloadUrl = null;
let previewUrl = null;
let maskedComposition = null;

function setAccentColor() {
  const color = document.body.dataset.accentColor;
  if (/^#[0-9a-f]{6}$/i.test(color || "")) document.documentElement.style.setProperty("--green", color);
}

function maskValue(value) {
  return value.replace(/[^\n]/g, "•");
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function payloadBytes() {
  return textEncoder.encode(secretText).length + (selectedFile?.size || 0);
}

// Characters are the useful count for a password; bytes only matter as the
// payload nears the limit, so the counter switches over then.
function updatePayloadState() {
  const count = secretText.length;
  const bytes = payloadBytes();
  const over = bytes > MAX_PAYLOAD_BYTES;
  const counter = elements.secretCount;
  if (over) counter.textContent = `Too large · ${formatBytes(bytes)} of 1 MB`;
  else if (bytes > SIZE_WARNING_BYTES) counter.textContent = `${formatBytes(bytes)} of 1 MB`;
  else counter.textContent = count === 0 ? "empty" : `${count} character${count === 1 ? "" : "s"}`;
  counter.classList.toggle("is-live", count > 0);
  counter.classList.toggle("is-warning", !over && bytes > SIZE_WARNING_BYTES);
  counter.classList.toggle("is-over", over);
  counter.setAttribute("aria-hidden", String(!over));
  elements.createLinks.disabled = over || (!selectedFile && count === 0);
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
  updatePayloadState();
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
  if (!secretIsVisible) {
    // Native composition events may mutate the textarea after compositionend.
    // Restore the mirror once the completed value has been kept in memory.
    if (!maskedComposition) setSecretInput(secretText, elements.secretInput.selectionStart ?? secretText.length);
    return;
  }
  setSecretInput(elements.secretInput.value);
}

function onSecretCompositionStart() {
  if (secretIsVisible) return;
  const input = elements.secretInput;
  const start = input.selectionStart ?? 0;
  maskedComposition = { start, end: input.selectionEnd ?? start };
}

function onSecretCompositionEnd(event) {
  if (secretIsVisible || !maskedComposition) return;
  const { start, end } = maskedComposition;
  maskedComposition = null;
  const composedText = event.data || "";
  const next = secretText.slice(0, start) + composedText + secretText.slice(end);
  setSecretInput(next, start + composedText.length);
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
  elements.ledgerExpiry.textContent = `Expires in ${formatDuration(seconds)}`;
}

// Remember the last expiry choices on this device. Storage can be missing or
// blocked; the defaults then stand.
function loadPrefs() {
  try {
    const prefs = JSON.parse(localStorage.getItem(PREFS_KEY) || "{}");
    const durations = Array.from(document.querySelectorAll(".duration-option"), (button) => Number(button.dataset.seconds));
    if (durations.includes(prefs.duration)) selectedDuration = prefs.duration;
    if (typeof prefs.expireAfterReveal === "boolean") elements.expireAfterReveal.checked = prefs.expireAfterReveal;
  } catch {}
}

function savePrefs() {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({ duration: selectedDuration, expireAfterReveal: elements.expireAfterReveal.checked }));
  } catch {}
}

async function attachFile() {
  elements.fileInput.click();
}

function showFileChip(file) {
  selectedFile = file;
  elements.fileStatus.textContent = file.name;
  elements.fileSize.textContent = formatBytes(file.size);
  elements.fileChip.hidden = false;
  elements.attachFile.hidden = true;
  updatePayloadState();
}

function clearFile() {
  selectedFile = null;
  elements.fileInput.value = "";
  elements.fileStatus.textContent = "";
  elements.fileSize.textContent = "";
  elements.fileChip.hidden = true;
  elements.attachFile.hidden = false;
  elements.fileNote.textContent = "";
  updatePayloadState();
}

// One file per secret. When a drop or paste carries more, or replaces the
// file already attached, say so rather than dropping it silently.
function acceptFiles(files) {
  const list = Array.from(files || []);
  const file = list[0];
  if (!file) return;
  const textBytes = textEncoder.encode(secretText).length;
  if (file.size + textBytes > MAX_PAYLOAD_BYTES) {
    elements.creationError.textContent = "Text and file together must be 1 MiB or smaller.";
    elements.fileInput.value = "";
    return;
  }
  const replaced = selectedFile;
  elements.creationError.textContent = "";
  showFileChip(file);
  const notes = [];
  if (list.length > 1) notes.push(`Only one file can be attached, so ${list.length - 1} other${list.length > 2 ? "s were" : " was"} left out.`);
  if (replaced) notes.push(`Replaced ${replaced.name}.`);
  elements.fileNote.textContent = notes.join(" ");
}

// Clipboard screenshots arrive as a generic "image.png" (or with no name), so
// give them a timestamped name the recipient can tell apart from other files.
function namePastedFile(file) {
  if (file.name && !/^image\.\w+$/i.test(file.name)) return file;
  const extension = (file.type.split("/")[1] || "bin").replace(/\W.*$/, "");
  const stamp = new Date().toISOString().slice(0, 19).replace(/[-:]/g, "").replace("T", "-");
  return new File([file], `screenshot-${stamp}.${extension}`, { type: file.type, lastModified: file.lastModified });
}

async function chooseFile() {
  acceptFiles(elements.fileInput.files);
}

// The whole page takes file drops. A file dropped outside a drop zone would
// otherwise make the browser open it and throw away the form.
function bindDropTarget() {
  const wrap = elements.creationForm;
  let depth = 0;
  const carriesFiles = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
  const accepting = () => !elements.creationView.hidden;
  window.addEventListener("dragover", (event) => {
    if (carriesFiles(event)) event.preventDefault();
  });
  window.addEventListener("dragenter", (event) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    if (!accepting()) return;
    depth += 1;
    wrap.classList.add("is-dragging");
  });
  window.addEventListener("dragleave", (event) => {
    if (!carriesFiles(event)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) wrap.classList.remove("is-dragging");
  });
  window.addEventListener("drop", (event) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    depth = 0;
    wrap.classList.remove("is-dragging");
    if (accepting()) acceptFiles(event.dataTransfer.files);
  });
}

async function createLinks(event) {
  event.preventDefault();
  if (!selectedFile && !secretText.length) return;
  elements.creationError.textContent = "";
  elements.createLinks.disabled = true;
  elements.createLinks.querySelector("span").textContent = "Encrypting…";
  elements.createLinks.classList.add("is-working");

  const wipe = [];
  let envelope;
  let key;
  let token;
  try {
    if (selectedFile && secretText.length) {
      const textBytes = textEncoder.encode(secretText);
      const fileBytes = new Uint8Array(await selectedFile.arrayBuffer());
      wipe.push(textBytes, fileBytes);
      if (textBytes.length + fileBytes.length > MAX_PAYLOAD_BYTES) throw new Error("Payloads must be 1 MiB or smaller.");
      envelope = makeBundleEnvelope([
        { kind: "text", name: "secret.txt", mediaType: "text/plain; charset=utf-8", bytes: textBytes },
        { kind: "file", name: selectedFile.name, mediaType: selectedFile.type || "application/octet-stream", bytes: fileBytes }
      ]);
    } else if (selectedFile) {
      const fileBytes = new Uint8Array(await selectedFile.arrayBuffer());
      wipe.push(fileBytes);
      if (fileBytes.length > MAX_PAYLOAD_BYTES) throw new Error("Payloads must be 1 MiB or smaller.");
      envelope = makeEnvelope("file", selectedFile.name, selectedFile.type || "application/octet-stream", fileBytes);
    } else {
      const textBytes = textEncoder.encode(secretText);
      wipe.push(textBytes);
      if (textBytes.length > MAX_PAYLOAD_BYTES) throw new Error("Payloads must be 1 MiB or smaller.");
      envelope = makeEnvelope("text", "secret.txt", "text/plain; charset=utf-8", textBytes);
    }
    for (const bytes of wipe) bytes.fill(0);
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
      expireAfterReveal: elements.expireAfterReveal.checked
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
    document.querySelectorAll(".link-visibility use").forEach((use) => use.setAttribute("href", "/icons.svg#eye-off"));
    document.querySelectorAll(".link-visibility").forEach((button) => {
      const label = el(button.dataset.target).getAttribute("aria-label");
      button.setAttribute("aria-label", `Show ${label}`);
    });
    elements.expiryStatus.textContent = `Expires in ${formatDuration(selectedDuration)}`;
    setRevealLedger(elements.shareRevealStatus, elements.expireAfterReveal.checked);
    elements.creationView.hidden = true;
    elements.shareView.hidden = false;
    secretText = "";
    clearFile();
    setSecretInput("");
  } catch (error) {
    elements.creationError.textContent = error instanceof Error ? error.message : "The secure links could not be created. Please try again.";
  } finally {
    if (key) key.fill(0);
    if (token) token.fill(0);
    elements.createLinks.querySelector("span").textContent = "Create secure links";
    elements.createLinks.classList.remove("is-working");
    updatePayloadState();
  }
}

function shareAnother() {
  elements.humanLink.value = "";
  elements.agentLink.value = "";
  elements.humanLink.type = "password";
  elements.agentLink.type = "password";
  elements.creationError.textContent = "";
  activateCreationView();
  elements.secretInput.focus();
}

function toggleLinkVisibility(button) {
  const input = el(button.dataset.target);
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  const label = input.getAttribute("aria-label");
  button.setAttribute("aria-label", `${showing ? "Show" : "Hide"} ${label}`);
  const use = button.querySelector("use");
  if (use) use.setAttribute("href", showing ? "/icons.svg#eye-off" : "/icons.svg#eye");
}

function flashCopied(button) {
  if (!button) return;
  const use = button.querySelector("use");
  if (!use) return;
  if (!button.dataset.copyLabel) button.dataset.copyLabel = button.getAttribute("aria-label") || "Copy";
  clearTimeout(button._copiedTimer);
  use.setAttribute("href", "/icons.svg#check");
  button.classList.add("is-copied");
  button.setAttribute("aria-label", "Copied");
  button._copiedTimer = setTimeout(() => {
    use.setAttribute("href", "/icons.svg#copy");
    button.classList.remove("is-copied");
    button.setAttribute("aria-label", button.dataset.copyLabel);
  }, 1500);
}

// Copy feedback lives on the button itself (the icon becomes a check). Only a
// failed copy needs words, and those go inline in whichever view is showing.
function copyFallbackTarget() {
  return elements.humanView.hidden ? elements.copyStatus : elements.humanError;
}

async function copyValue(value, input, button = null, revealForFallback = null) {
  const status = copyFallbackTarget();
  try {
    await navigator.clipboard.writeText(value);
    status.textContent = "";
    flashCopied(button);
  } catch {
    if (revealForFallback) revealForFallback();
    else input.type = "text";
    input.focus();
    input.select();
    status.textContent = "This browser blocked the clipboard. The value is selected — copy it manually.";
  }
}

function syncExpireLabel() {
  const once = elements.expireAfterReveal.checked;
  elements.expireLabel.textContent = once
    ? "Expire on: Secret expires after being retrieved"
    : "Expire off: Secret can be retrieved many times";
  elements.expireHint.textContent = once
    ? "The first person to retrieve it is the only one. After that the link is dead."
    : "Anyone with the link can retrieve it repeatedly until it expires.";
  setRevealLedger(elements.ledgerReveal, once);
}

// The ledger states the live plan for this secret, so its icon has to track
// the toggle: a one-shot flame, or a repeatable cycle.
function setRevealLedger(target, once) {
  target.textContent = once ? "Opens once" : "Opens many times";
  const icon = target.parentElement.querySelector("svg");
  if (!icon) return;
  icon.classList.toggle("ink-amber", once);
  icon.querySelector("use")?.setAttribute("href", once ? "/icons.svg#flame" : "/icons.svg#repeat");
}

function setResultText(value) {
  revealedText = value;
  elements.revealedText.value = resultIsVisible ? revealedText : maskValue(revealedText);
  elements.revealedText.classList.toggle("is-masked", !resultIsVisible);
  elements.resultVisibility.textContent = resultIsVisible ? "Hide" : "Show";
  elements.resultVisibility.setAttribute("aria-pressed", String(resultIsVisible));
}

function sealResult() {
  resultIsVisible = false;
  revealedText = "";
  elements.resultField.classList.add("is-sealed");
  elements.revealedText.value = "";
  elements.revealedText.disabled = true;
  elements.revealedText.classList.remove("is-masked");
  elements.resultActions.hidden = true;
  elements.resultVisibility.textContent = "Show";
  elements.resultVisibility.setAttribute("aria-pressed", "false");
}

function unsealResult() {
  elements.resultField.classList.remove("is-sealed");
  elements.revealedText.disabled = false;
  elements.resultActions.hidden = false;
  elements.resultField.classList.add("is-revealing");
  setTimeout(() => elements.resultField.classList.remove("is-revealing"), 600);
}

function setPreviewVisible(visible) {
  elements.imageFrame.classList.toggle("is-veiled", !visible);
  elements.previewVisibility.textContent = visible ? "Hide" : "Show";
  elements.previewVisibility.setAttribute("aria-pressed", String(visible));
  elements.previewVisibility.setAttribute("aria-label", visible ? "Hide image preview" : "Show image preview");
}

function clearPreview() {
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  elements.imagePreview.hidden = true;
  elements.previewImage.removeAttribute("src");
  elements.previewImage.alt = "";
}

function offerPreview(filename, mediaType, bytes) {
  const type = mediaType.split(";")[0].trim().toLowerCase();
  if (!PREVIEW_MEDIA_TYPES.has(type)) return;
  previewUrl = URL.createObjectURL(new Blob([bytes], { type }));
  elements.previewImage.onerror = clearPreview;
  elements.previewImage.src = previewUrl;
  elements.previewImage.alt = `Preview of ${filename}`;
  setPreviewVisible(false);
  elements.imagePreview.hidden = false;
}

function clearDownload() {
  clearPreview();
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null;
  elements.fileDownload.hidden = true;
  elements.fileDownload.removeAttribute("href");
  elements.fileDownload.removeAttribute("download");
  elements.fileDownload.classList.remove("primary-action");
  elements.fileDownload.textContent = "Download file";
}

function wipeCapability() {
  if (!capability) return;
  capability.key.fill(0);
  capability.token.fill(0);
  capability = null;
}

async function loadHumanStatus(id) {
  try {
    const result = await fetch(`/api/v1/secrets/${encodeURIComponent(id)}/status`, { cache: "no-store" });
    const status = await result.json();
    if (!result.ok || status.state !== "available") throw new Error("The secret is no longer available.");
    humanExpireAfterReveal = Boolean(status.expireAfterReveal);
    elements.humanExplanation.textContent = humanExpireAfterReveal
      ? "You can look at this page safely. Retrieving the secret will make the link stop working."
      : "You can look at this page safely. This link works until it expires.";
    elements.humanNotice.hidden = !humanExpireAfterReveal;
    if (capability) {
      elements.revealSecret.hidden = false;
      elements.revealSecret.disabled = false;
      elements.revealSecret.querySelector("span").textContent = "Retrieve secret";
    }
  } catch (error) {
    elements.humanError.textContent = error instanceof Error ? error.message : "The secret is no longer available.";
    elements.humanNotice.hidden = true;
  }
}

function offerDownload(name, mediaType, bytes) {
  clearDownload();
  const filename = safeDownloadName(name);
  downloadUrl = URL.createObjectURL(new Blob([bytes], { type: mediaType }));
  elements.fileDownload.href = downloadUrl;
  elements.fileDownload.download = filename;
  elements.fileDownload.textContent = `Download ${filename}`;
  elements.fileDownload.classList.add("primary-action");
  elements.fileDownload.hidden = false;
  offerPreview(filename, mediaType, bytes);
}

async function revealHumanSecret(id) {
  if (!capability) return;
  elements.revealSecret.disabled = true;
  elements.revealSecret.querySelector("span").textContent = "Decrypting…";
  elements.revealSecret.classList.add("is-working");
  elements.humanError.textContent = "";
  try {
    const result = await fetch(`/api/v1/secrets/${encodeURIComponent(id)}/reveal`, {
      method: "POST",
      headers: { authorization: `zk-relay ${capability.tokenText}`, accept: "application/vnd.zk-relay.encrypted+json" },
      cache: "no-store"
    });
    if (!result.ok) throw new Error("The secret is no longer available.");
    const envelope = await decryptContainer(await result.json(), capability.key);
    clearDownload();
    if (envelope.kind === "text") {
      resultIsVisible = false;
      elements.humanResult.hidden = false;
      unsealResult();
      setResultText(textDecoder.decode(envelope.bytes));
    } else if (envelope.kind === "file") {
      offerDownload(envelope.name, envelope.mediaType, envelope.bytes);
      elements.humanResult.hidden = true;
      sealResult();
    } else {
      const items = envelope.items || decodeBundleItems(envelope);
      const textItem = items.find((item) => item.kind === "text");
      const fileItem = items.find((item) => item.kind === "file");
      if (textItem) {
        resultIsVisible = false;
        elements.humanResult.hidden = false;
        unsealResult();
        setResultText(textDecoder.decode(textItem.bytes));
      } else {
        elements.humanResult.hidden = true;
        sealResult();
      }
      if (fileItem) offerDownload(fileItem.name, fileItem.mediaType, fileItem.bytes);
      for (const item of items) item.bytes.fill(0);
    }
    envelope.bytes.fill(0);
    elements.revealSecret.hidden = true;
    elements.revealSecret.classList.remove("is-working");
    elements.humanNotice.hidden = true;
    elements.spentNote.hidden = !humanExpireAfterReveal;
    if (humanExpireAfterReveal) wipeCapability();
  } catch (error) {
    elements.humanError.textContent = error instanceof Error ? error.message : "The secret could not be retrieved.";
    elements.revealSecret.classList.remove("is-working");
    if (capability) {
      elements.revealSecret.disabled = false;
      elements.revealSecret.querySelector("span").textContent = "Retrieve secret";
    }
  }
}

function setupHumanRoute() {
  const match = /^\/h\/([A-Za-z0-9_-]+)$/.exec(window.location.pathname);
  if (!match) return false;
  elements.creationView.hidden = true;
  elements.shareView.hidden = true;
  elements.humanView.hidden = false;
  sealResult();
  try {
    capability = decodeCapabilityFragment(window.location.hash);
    history.replaceState(null, "", window.location.pathname);
  } catch {
    elements.humanError.textContent = "This page needs the original complete link to retrieve the secret.";
  }
  loadHumanStatus(match[1]);
  elements.revealSecret.addEventListener("click", () => revealHumanSecret(match[1]));
  return true;
}

function clearSensitiveState() {
  secretText = "";
  revealedText = "";
  maskedComposition = null;
  selectedFile = null;
  elements.secretInput.value = "";
  elements.humanLink.value = "";
  elements.agentLink.value = "";
  elements.revealedText.value = "";
  wipeCapability();
  clearDownload();
}

function bindResultActions() {
  elements.previewVisibility.addEventListener("click", () => {
    setPreviewVisible(elements.imageFrame.classList.contains("is-veiled"));
  });
  elements.resultVisibility.addEventListener("click", () => {
    if (!revealedText) return;
    resultIsVisible = !resultIsVisible;
    setResultText(revealedText);
  });
  elements.resultCopy.addEventListener("click", () => {
    if (!revealedText) return;
    copyValue(revealedText, elements.revealedText, elements.resultCopy, () => {
      resultIsVisible = true;
      setResultText(revealedText);
    });
  });
}

function initialize() {
  setAccentColor();
  syncExpireLabel();
  bindResultActions();
  window.addEventListener("pagehide", clearSensitiveState, { once: true });
  if (setupHumanRoute()) return;
  loadPrefs();
  syncExpireLabel();
  activateCreationView();
  elements.expireAfterReveal.addEventListener("change", () => {
    syncExpireLabel();
    savePrefs();
  });
  elements.secretInput.addEventListener("beforeinput", onSecretBeforeInput);
  elements.secretInput.addEventListener("input", onSecretInput);
  elements.secretInput.addEventListener("compositionstart", onSecretCompositionStart);
  elements.secretInput.addEventListener("compositionend", onSecretCompositionEnd);
  elements.secretInput.addEventListener("paste", (event) => {
    const text = event.clipboardData?.getData("text/plain") || "";
    const file = text ? null : event.clipboardData?.files?.[0];
    if (file) {
      event.preventDefault();
      acceptFiles(Array.from(event.clipboardData.files, namePastedFile));
    } else if (!secretIsVisible) {
      event.preventDefault();
      replaceMaskedSelection(text);
    }
  });
  elements.secretInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || !(event.metaKey || event.ctrlKey) || event.isComposing) return;
    event.preventDefault();
    if (!elements.createLinks.disabled) elements.creationForm.requestSubmit();
  });
  elements.secretVisibility.addEventListener("click", () => {
    secretIsVisible = !secretIsVisible;
    setSecretInput(secretText, elements.secretInput.selectionStart ?? secretText.length);
  });
  elements.attachFile.addEventListener("click", attachFile);
  elements.fileInput.addEventListener("change", chooseFile);
  elements.fileRemove.addEventListener("click", clearFile);
  elements.shareAnother.addEventListener("click", shareAnother);
  bindDropTarget();
  setDuration(selectedDuration);
  document.querySelectorAll(".duration-option").forEach((button) => button.addEventListener("click", () => {
    setDuration(Number(button.dataset.seconds));
    savePrefs();
  }));
  elements.creationForm.addEventListener("submit", createLinks);
  document.querySelectorAll(".link-visibility").forEach((button) => button.addEventListener("click", () => toggleLinkVisibility(button)));
  document.querySelectorAll(".copy-link").forEach((button) => button.addEventListener("click", () => {
    const input = el(button.dataset.target);
    copyValue(input.value, input, button);
  }));
}

initialize();
