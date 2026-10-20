import { MAX_BUNDLE_ITEMS, MAX_ENCRYPTED_CONTAINER_BYTES, MAX_PAYLOAD_BYTES, RECEIVER_LEVEL, RECEIVER_LEVEL_HEADER, base64UrlToBytes, bytesToBase64Url, decodeCapabilityFragment, formatDuration, randomBytes } from "./protocol.js";
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
  attachLabel: el("attach-label"),
  fileChips: el("file-chips"),
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
  fileResults: el("file-results")
};

const PREFS_KEY = "zk-relay:create-prefs";
const SIZE_WARNING = 0.75;
// Leave one bundle slot for the typed text.
const MAX_FILES = MAX_BUNDLE_ITEMS - 1;
// Only raster formats the browser decodes inertly. SVG can carry script, so it
// stays a download.
const PREVIEW_MEDIA_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);

let secretText = "";
let selectedFiles = [];
let secretIsVisible = false;
let selectedDuration = 3600;
let capability = null;
let humanExpireAfterReveal = true;
let revealedText = "";
let resultIsVisible = false;
let objectUrls = [];
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

// Two limits apply: 1 MiB of plaintext, and the encrypted container size. A
// bundle base64-encodes each item inside JSON that the envelope base64-encodes
// again, so several items fit in less than one item alone. This estimate
// mirrors makeEnvelope/makeBundleEnvelope; createLinks checks the real size.
function sizeState(textBytes, files) {
  const base64 = (bytes) => Math.ceil(bytes / 3) * 4;
  const raw = textBytes + files.reduce((sum, file) => sum + file.size, 0);
  const items = (textBytes > 0 ? 1 : 0) + files.length;
  let container;
  if (items <= 1) {
    container = base64(raw) + 256;
  } else {
    let inner = 16 + (textBytes > 0 ? base64(textBytes) + 96 : 0);
    for (const file of files) inner += base64(file.size) + 96 + textEncoder.encode(file.name + file.type).length;
    container = base64(inner) + 256;
  }
  const fraction = Math.max(raw / MAX_PAYLOAD_BYTES, container / MAX_ENCRYPTED_CONTAINER_BYTES);
  const limit = container / MAX_ENCRYPTED_CONTAINER_BYTES > raw / MAX_PAYLOAD_BYTES && raw > 0
    ? `~${formatBytes(Math.floor(raw / fraction / 1024) * 1024)}`
    : "1 MB";
  return { raw, fraction, over: fraction > 1, limit };
}

// Characters are the useful count for a password; bytes only matter as the
// payload nears the limit, so the counter switches over then.
function updatePayloadState() {
  const count = secretText.length;
  const size = sizeState(textEncoder.encode(secretText).length, selectedFiles);
  const warn = !size.over && size.fraction > SIZE_WARNING;
  const counter = elements.secretCount;
  if (size.over) counter.textContent = `Too large · ${formatBytes(size.raw)} of ${size.limit}`;
  else if (warn) counter.textContent = `${formatBytes(size.raw)} of ${size.limit}`;
  else counter.textContent = count === 0 ? "empty" : `${count} character${count === 1 ? "" : "s"}`;
  counter.classList.toggle("is-live", count > 0);
  counter.classList.toggle("is-warning", warn);
  counter.classList.toggle("is-over", size.over);
  counter.setAttribute("aria-hidden", String(!size.over));
  elements.createLinks.disabled = size.over || (selectedFiles.length === 0 && count === 0);
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

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `/icons.svg#${name}`);
  svg.append(use);
  return svg;
}

function textSpan(className, text) {
  const span = document.createElement("span");
  span.className = className;
  span.textContent = text;
  return span;
}

function renderFileChips() {
  elements.fileChips.replaceChildren(...selectedFiles.map((file) => {
    const chip = document.createElement("li");
    chip.className = "file-chip";
    const remove = document.createElement("button");
    remove.className = "chip-remove";
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${file.name}`);
    remove.append(icon("close"));
    remove.addEventListener("click", () => removeFile(file));
    chip.append(icon("attachment"), textSpan("file-status", file.name), textSpan("file-size", formatBytes(file.size)), remove);
    return chip;
  }));
  elements.attachLabel.textContent = selectedFiles.length ? "Add another" : "Attach a file";
  elements.attachFile.hidden = selectedFiles.length >= MAX_FILES;
  elements.fileInput.value = "";
  updatePayloadState();
}

function removeFile(file) {
  selectedFiles = selectedFiles.filter((candidate) => candidate !== file);
  elements.fileNote.textContent = "";
  renderFileChips();
  elements.attachFile.focus();
}

function clearFiles() {
  selectedFiles = [];
  elements.fileNote.textContent = "";
  renderFileChips();
}

// Files add up to MAX_FILES and the size limit. Anything that does not fit is
// named in a note rather than dropped silently.
function acceptFiles(files) {
  const incoming = Array.from(files || []);
  if (!incoming.length) return;
  const textBytes = textEncoder.encode(secretText).length;
  let overCount = 0;
  const tooLarge = [];
  for (const file of incoming) {
    if (selectedFiles.length >= MAX_FILES) {
      overCount += 1;
    } else if (sizeState(textBytes, [...selectedFiles, file]).over) {
      tooLarge.push(file.name);
    } else {
      selectedFiles = [...selectedFiles, file];
    }
  }
  const notes = [];
  if (tooLarge.length) notes.push(`Left out ${tooLarge.join(", ")}: too large to send with the rest.`);
  if (overCount) notes.push(`Left out ${overCount} file${overCount === 1 ? "" : "s"}: ${MAX_FILES} files per secret.`);
  elements.creationError.textContent = "";
  elements.fileNote.textContent = notes.join(" ");
  renderFileChips();
}

// Distinct names, so downloads and `zkr receive` never collide. Matches the
// receiver's "name (2).ext" form and ignores case like macOS and Windows.
function uniqueNames(names) {
  const used = new Set();
  return names.map((name) => {
    const dot = name.lastIndexOf(".");
    const stem = dot > 0 ? name.slice(0, dot) : name;
    const extension = dot > 0 ? name.slice(dot) : "";
    let candidate = name;
    for (let index = 2; used.has(candidate.toLowerCase()); index += 1) candidate = `${stem} (${index})${extension}`;
    used.add(candidate.toLowerCase());
    return candidate;
  });
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
  if (!selectedFiles.length && !secretText.length) return;
  elements.creationError.textContent = "";
  elements.createLinks.disabled = true;
  elements.createLinks.querySelector("span").textContent = "Encrypting…";
  elements.createLinks.classList.add("is-working");

  const wipe = [];
  let envelope;
  let key;
  let token;
  try {
    const items = [];
    if (secretText.length) items.push({ kind: "text", name: "secret.txt", mediaType: "text/plain; charset=utf-8", bytes: textEncoder.encode(secretText) });
    const names = uniqueNames([...items.map((item) => item.name), ...selectedFiles.map((file) => file.name)]).slice(items.length);
    for (const [index, file] of selectedFiles.entries()) {
      items.push({ kind: "file", name: names[index], mediaType: file.type || "application/octet-stream", bytes: new Uint8Array(await file.arrayBuffer()) });
    }
    wipe.push(...items.map((item) => item.bytes));
    if (items.reduce((sum, item) => sum + item.bytes.length, 0) > MAX_PAYLOAD_BYTES) throw new Error("Payloads must be 1 MiB or smaller.");
    envelope = items.length === 1
      ? makeEnvelope(items[0].kind, items[0].name, items[0].mediaType, items[0].bytes)
      : makeBundleEnvelope(items);
    for (const bytes of wipe) bytes.fill(0);
    const encrypted = await encryptEnvelope(envelope);
    if (encrypted.ciphertext.length > MAX_ENCRYPTED_CONTAINER_BYTES) {
      encrypted.ciphertext.fill(0);
      encrypted.key.fill(0);
      throw new Error("These are too large to send together. Remove a file or shorten the text.");
    }
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
      expireAfterReveal: elements.expireAfterReveal.checked,
      // Receivers before level 2 read at most two bundle items.
      ...(items.length > 2 ? { minReceiver: RECEIVER_LEVEL } : {})
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
    clearFiles();
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

function objectUrl(bytes, type) {
  // Blob copies the bytes, so callers can wipe their buffers afterwards.
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  objectUrls.push(url);
  return url;
}

// Image previews start veiled, like masked text, until the reader asks.
function imagePreview(filename, mediaType, bytes) {
  const type = mediaType.split(";")[0].trim().toLowerCase();
  if (!PREVIEW_MEDIA_TYPES.has(type)) return null;
  const frame = document.createElement("div");
  frame.className = "image-frame is-veiled";
  const image = document.createElement("img");
  image.alt = `Preview of ${filename}`;
  image.addEventListener("error", () => frame.remove());
  image.src = objectUrl(bytes, type);
  const toggle = document.createElement("button");
  toggle.className = "text-action";
  toggle.type = "button";
  const setVisible = (visible) => {
    frame.classList.toggle("is-veiled", !visible);
    toggle.textContent = visible ? "Hide" : "Show";
    toggle.setAttribute("aria-pressed", String(visible));
    toggle.setAttribute("aria-label", `${visible ? "Hide" : "Show"} preview of ${filename}`);
  };
  toggle.addEventListener("click", () => setVisible(frame.classList.contains("is-veiled")));
  setVisible(false);
  frame.append(image, toggle);
  return frame;
}

function clearDownload() {
  for (const url of objectUrls) URL.revokeObjectURL(url);
  objectUrls = [];
  elements.fileResults.replaceChildren();
  elements.fileResults.hidden = true;
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

// One file gets the primary download button. Several get a row each.
function offerDownloads(files) {
  clearDownload();
  const single = files.length === 1;
  for (const file of files) {
    const filename = safeDownloadName(file.name);
    const item = document.createElement("div");
    item.className = "file-result";
    const preview = imagePreview(filename, file.mediaType, file.bytes);
    if (preview) item.append(preview);
    const link = document.createElement("a");
    link.className = single ? "download-action primary-action" : "download-row";
    link.href = objectUrl(file.bytes, file.mediaType);
    link.download = filename;
    if (single) {
      link.textContent = `Download ${filename}`;
    } else {
      link.append(icon("attachment"), textSpan("file-status", filename), textSpan("file-size", formatBytes(file.bytes.length)), textSpan("download-label", "Download"));
    }
    item.append(link);
    elements.fileResults.append(item);
  }
  elements.fileResults.hidden = files.length === 0;
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
      headers: {
        authorization: `zk-relay ${capability.tokenText}`,
        accept: "application/vnd.zk-relay.encrypted+json",
        [RECEIVER_LEVEL_HEADER]: String(RECEIVER_LEVEL)
      },
      cache: "no-store"
    });
    if (!result.ok) throw new Error("The secret is no longer available.");
    const envelope = await decryptContainer(await result.json(), capability.key);
    const items = envelope.kind === "bundle" ? envelope.items || decodeBundleItems(envelope) : [envelope];
    // The first text item fills the secret box; anything else is a download.
    const textItem = items.find((item) => item.kind === "text");
    if (textItem) {
      resultIsVisible = false;
      elements.humanResult.hidden = false;
      unsealResult();
      setResultText(textDecoder.decode(textItem.bytes));
    } else {
      elements.humanResult.hidden = true;
      sealResult();
    }
    offerDownloads(items.filter((item) => item !== textItem));
    for (const item of items) item.bytes.fill(0);
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
  selectedFiles = [];
  elements.secretInput.value = "";
  elements.humanLink.value = "";
  elements.agentLink.value = "";
  elements.revealedText.value = "";
  wipeCapability();
  clearDownload();
}

function bindResultActions() {
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
