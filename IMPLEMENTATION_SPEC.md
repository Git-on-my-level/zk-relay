# ZK Relay: implementation specification

Status: implementation handoff  
Target: open-source, self-hostable Cloudflare application  
Primary clients: web browsers and tool-using AI agents

## 1. Product outcome

Build a tiny service for passing an encrypted secret between:

- a person and another person;
- a person and an AI agent;
- an AI agent and a person; or
- two AI agents.

The sender creates one encrypted payload. The product returns two links to the
same encrypted payload:

- a **Human friendly link**, which opens a browser reveal experience; and
- an **Agent friendly link**, which first returns safe, machine-readable
  instructions and recommends a verified local receiver tool.

The browser and the receiver tool decrypt locally. The Cloudflare deployment
must store ciphertext only and must never receive the payload decryption key.

The MVP must have no accounts, no analytics, no always-on server, no external
database, and no third-party browser runtime dependencies.

## 2. Source mockups

The four PNG files in `mockups/` are the approved visual reference:

| View | File |
| --- | --- |
| Desktop creation | `mockups/desktop-creation.png` |
| Desktop post-creation | `mockups/desktop-post-creation.png` |
| Mobile creation | `mockups/mobile-creation.png` |
| Mobile post-creation | `mockups/mobile-post-creation.png` |

Use the mockups to preserve hierarchy, density, typography, and tone. Do not
blindly reproduce incidental raster-generation defects. Exact UI copy and
behavior are specified below and take precedence over pixels.

## 3. Non-negotiable product decisions — LOCKED

The implementing agent must not reinterpret these decisions:

1. The post-creation screen always displays both links at once. Do not use
   tabs, a Human/Agent selector, an accordion, a modal, or progressive
   disclosure.
2. Link fields are masked by default. Each field has an eye icon to reveal or
   hide it and a clipboard icon to copy it.
3. Copying does not require revealing. Copy the full underlying link while the
   field remains masked.
4. The link field remains a real selectable input so a user can reveal and
   manually select/copy it.
5. The creation secret is masked after entry by default and has a Show/Hide
   control.
6. The expiry-after-reveal switch is off by default and is labeled exactly
   **Do not expire after revealing**.
7. With that switch off, a successful reveal removes the encrypted payload.
   With it on, the encrypted payload remains available until its time limit.
8. The duration choices are exactly **1 hour**, **1 day**, and **7 days**.
9. Human and agent links point to the same secret, share the same time limit,
   and share reveal state.
10. Opening or inspecting either link must never retrieve or remove the
    payload. Retrieval requires a separate explicit action.
11. The agent path must warn about reveal behavior before retrieval and explain
    how the payload will be delivered.
12. Agents should use the official receiver tool by default. Manual decryption
    remains documented for agents that will not execute it.
13. The receiver tool saves plaintext to a local file by default. It must not
    print plaintext to stdout or return it into an agent transcript by default.
14. Browser encryption and decryption happen locally on device.
15. The service stores ciphertext only. Do not add server-assisted plaintext
    decryption as the default or as a hidden fallback.
16. The initial Cloudflare deployment uses Workers plus SQLite-backed Durable
    Objects and stays inside free-tier limits for ordinary personal/small-team
    usage.
17. Do not add R2, KV, D1, Redis, Memcached, containers, queues, workflows, or
    scheduled infrastructure to the MVP.
18. The web app has no React, Vue, Svelte, Tailwind, component library, web
    font, OpenPGP package, or client SDK dependency. Use semantic HTML, CSS,
    browser JavaScript, and native Web Crypto.
19. The visual direction is light, minimal, editorial, and subtly cypherpunk.
    Do not turn it into a generic dashboard, password manager, or neon hacker
    interface.
20. Mobile must be compact. Do not preserve desktop-sized headings or large
    decorative whitespace on a phone.

## 4. Copy deck — LOCKED

Do not “improve,” expand, or technicalize this copy without approval.

### 4.1 Creation screen

- Heading: **Share a secret with a human or an agent**
- No subtitle.
- Input label: **Your secret**
- Mask control: **Show** / **Hide**
- Attachment action: **Attach a file**
- Duration label: **Keep it available for**
- Choices: **1 hour**, **1 day**, **7 days**
- Toggle: **Do not expire after revealing**
- Primary action: **Create secure links**
- Reassurance: **Encrypted on device**

Do not add a helper sentence beneath the toggle.

### 4.2 Post-creation screen

- Heading: **Your secret is ready**
- No subtitle.
- First link title: **Human friendly link**
- Second link title: **Agent friendly link**
- No subtitles beneath either link title.
- No verified-helper paragraph beneath the agent link.
- Status: **Expires in 1 hour** (substitute the selected duration)
- Reassurance: **Encrypted on device**

The clipboard and eye actions are icon-only visually. They still require
accessible labels.

### 4.3 Human pre-reveal page

This screen was not included in the final mockup set, so implement it using the
same design system and only this concise content:

- Heading: **Someone shared a secret with you**
- If reveal removes it: **You can look at this page safely. Revealing the
  secret will make the link stop working.**
- If reveal does not remove it: **You can look at this page safely. This link
  works until it expires.**
- Primary action: **Reveal secret**

Do not fetch ciphertext until the user activates **Reveal secret**.

### 4.4 Agent preflight response

Use direct, non-personified language. The first response must state:

- the request did not retrieve the secret;
- whether retrieval will make the link stop working;
- when it expires;
- that the preferred method saves it to a local file without printing it;
- the exact receiver command; and
- that manual protocol instructions are available.

Do not include sender-authored instructions in the trusted skill section.

## 5. Visual system — LOCKED

### 5.1 Character

Use an editorial, calm, privacy-oriented aesthetic:

- warm bone-white canvas;
- black/near-black primary text;
- restrained forest-green security accent;
- a tiny amber expiry/status accent;
- serif display headings paired with clean sans-serif controls;
- sparse monospace labels where they add technical character;
- open composition, thin rules, and few visible containers.

Cypherpunk influence should come from precision, typography, a geometric
broken-key mark, and privacy language—not from neon, glowing terminals,
Matrix imagery, cyberpunk cities, skulls, or dense protocol decoration.

### 5.2 Suggested dependency-free tokens

These values are implementation starting points. Keep them as CSS custom
properties so they can be tuned after browser screenshots:

```css
:root {
  --canvas: #f7f5ef;
  --surface: #fbfaf6;
  --ink: #111411;
  --muted: #686b67;
  --line: #c8cac5;
  --green: #247a3b;
  --green-soft: #e9f3e8;
  --amber: #c58a06;
  --control: #151817;
  --focus: #247a3b;

  --font-display: Georgia, "Times New Roman", serif;
  --font-body: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
    "Liberation Mono", monospace;
}
```

Do not download Inter; the stack must fall through to system fonts. It is
listed only as a locally available preference.

### 5.3 Desktop layout

- Breakpoint: desktop layout at `min-width: 721px`.
- Sparse identity rail: about `240–280px` wide.
- Main content maximum width: about `900–960px`.
- Page padding: `40–64px`, responsive with `clamp()`.
- Display heading: approximately `48–58px`, one line where space permits.
- Link inputs: `64–72px` high.
- Use borders around actual inputs, not around every content section.
- Separate link sections with a single hairline.

### 5.4 Mobile layout

- Mobile layout at `max-width: 720px`.
- Remove the identity rail entirely; use a compact top bar.
- Target screenshot viewport: `390 × 844 CSS px`.
- Top bar height: `52–60px`.
- Main horizontal padding: `20–24px`.
- Creation heading: `32–36px`, no more than two lines.
- Post-creation heading: `32–36px`, ideally one line at common widths.
- Input/tap targets: at least `44px` high.
- Secret textarea target height: `112–132px`.
- Link input target height: `56–64px`.
- Use `16–24px` section gaps; avoid the desktop’s large vertical gaps.
- Both links and both status items should be visible without an intentionally
  oversized page. Design for one ordinary phone viewport; allow natural
  scrolling only on unusually small screens or enlarged text.

## 6. Interaction specification

### 6.1 Creating a secret in the browser

1. Start with an empty secret input. Mask characters as the user types.
2. Show and Hide toggle only the visual presentation. Never log the value.
3. Accept either UTF-8 text or one file in the MVP—not both simultaneously.
4. If the user attaches a file while text exists, ask whether to replace the
   text. Do not silently merge payloads or invent a multi-file UI.
5. Default duration is one hour.
6. **Do not expire after revealing** defaults off.
7. Disable **Create secure links** until a payload exists.
8. On activation, assemble the versioned plaintext envelope, encrypt locally,
   upload only ciphertext and non-secret control metadata, and render the two
   masked links.
9. Do not persist the plaintext, encryption key, or completed links in local
   storage, IndexedDB, cookies, analytics, or telemetry.

The encrypted envelope is versioned now so multi-entry bundles can be added
later without changing URL semantics. The MVP carries one payload.

### 6.2 Masking the multiline secret

HTML has no portable password-style multiline textarea. Implement this without
a dependency:

- keep the real value in page memory;
- render a visually masked overlay or masked mirror while hidden;
- ensure assistive technology receives the input label and state, not a spoken
  stream of bullets;
- reveal the real textarea contents only after Show is activated; and
- clear all in-memory state when the page is discarded where practical.

Do not render the secret into HTML via `innerHTML`.

### 6.3 Link fields

Use readonly inputs with `type="password"` while masked and `type="text"` when
revealed.

- Eye icon toggles the field type.
- Clipboard icon copies the underlying complete value in either state.
- Copy success uses a small **Copied** toast or temporary accessible status.
- Never put the copied link into console output.
- If the Clipboard API fails, reveal and select the real input as a fallback.
- Give icon buttons at least `44 × 44px` hit targets on mobile.

### 6.4 Human retrieval

1. `GET /h/:id` serves only the application shell and safe status.
2. JavaScript reads the URL fragment locally.
3. The page shows the pre-reveal explanation. No payload request occurs yet.
4. **Reveal secret** sends only the access token—not the decryption key—to the
   claim endpoint.
5. The response contains ciphertext.
6. The browser authenticates and decrypts locally.
7. Text is displayed in a masked-by-default result field with Show and Copy.
   Files are offered as a local download.
8. Plaintext responses use `Cache-Control: no-store`; do not use a service
   worker or browser cache for secret material.

### 6.5 Agent retrieval

The agent receives an Agent friendly link such as:

```text
https://zk-relay.example/a/SECRET_ID#v1.DECRYPTION_KEY.ACCESS_TOKEN
```

The fragment is intentionally absent from HTTP requests. The agent must retain
the original complete URL and pass it to the receiver tool.

A plain `curl` of `/a/:id` is a **safe preflight**. It returns instructions and
does not claim ciphertext. Prefer Markdown with YAML front matter:

```markdown
---
protocol: zk-relay/v1
available: true
expires_at: 2026-07-16T20:00:00Z
expires_after_reveal: true
retrieved: false
---

# Encrypted secret

This request did not retrieve the secret.

Retrieving it will make this link stop working. The preferred receiver saves
the decrypted value to a local file and does not print it.

zkr receive "$ZK_RELAY_URL" --output ./secret

Manual protocol instructions: https://zk-relay.example/protocol/v1
```

The exact wording may substitute the non-removing behavior when the toggle was
enabled. Do not say “consume” in user-facing copy.

The receiver tool then:

1. parses the ID, decryption key, and access token locally;
2. performs a safe status check;
3. sends the access token to the explicit claim endpoint;
4. downloads ciphertext;
5. authenticates and decrypts locally;
6. writes a temporary file with owner-only permissions (`0600` on Unix);
7. flushes and atomically renames it to the chosen output path; and
8. prints only safe status information.

Default command:

```sh
zkr receive "$ZK_RELAY_URL" --output ./secret
```

Plaintext stdout is an explicit fallback only:

```sh
zkr receive "$ZK_RELAY_URL" --stdout --allow-plaintext-stdout
```

The tool must display a transcript-risk warning before using stdout. Never
silently fall back from file output to stdout.

### 6.6 Skill and tool delivery

The safe preflight response contains:

- a stable, platform-neutral skill section authored by the project;
- secret-specific non-sensitive status values;
- a pinned tool version, download locations, and checksums/signature;
- the preferred receive command; and
- a manual protocol link.

Do not generate secret-specific executable source. Do not instruct agents to
pipe unverified network responses directly into a shell. The tool is a stable,
auditable release and may be cached or installed once.

Build the receiver as a small statically linked binary with no runtime
dependencies. Go is a practical default because its standard library covers
HTTP, AES-GCM, JSON, filesystem permissions, and cross-compilation. Do not add
a third-party crypto package unless native primitives cannot meet the locked
format.

Host versioned binaries under static assets or a configurable release base URL
for:

- Linux x86-64;
- Linux ARM64;
- macOS x86-64;
- macOS ARM64; and
- Windows x86-64 when practical.

Manual decryption is a supported escape hatch, but documentation and responses
must always recommend the verified tool first.

## 7. Cryptographic and link design

### 7.1 Capabilities in the fragment

Generate two independent random 256-bit values in the browser:

- `K`: AES-256-GCM payload decryption key;
- `T`: access token authorizing payload retrieval.

The URL fragment contains both:

```text
#v1.BASE64URL(K).BASE64URL(T)
```

The browser uploads `SHA-256(T)` with the ciphertext. Cloudflare receives `T`
only during an explicit claim and never receives `K`.

This separation is important: link scanners can see the path ID, but cannot
retrieve ciphertext merely from the safe landing URL. Do not collapse the
access token and encryption key into a query parameter or path segment.

### 7.2 Encryption

- Algorithm: AES-256-GCM via native Web Crypto in the browser and standard
  crypto primitives in the receiver tool.
- Key: 32 random bytes from `crypto.getRandomValues`.
- Nonce: unique random 12-byte value per encryption.
- AAD: a canonical UTF-8 encoding of protocol version and envelope type.
- Encoding: unpadded base64url for URL capabilities.
- Never reuse a key/nonce pair.
- Authentication failure is terminal and must not emit partial plaintext.

Publish cross-language test vectors and run them in both browser and tool test
suites.

### 7.3 Plaintext envelope

Use a versioned JSON envelope before encryption:

```json
{
  "v": 1,
  "kind": "text",
  "name": "secret.txt",
  "mediaType": "text/plain; charset=utf-8",
  "data": "base64-encoded payload bytes"
}
```

`kind` is `text` or `file`. Filename, MIME type, and contents remain encrypted.
Treat filenames as untrusted on receipt: remove path components, control
characters, leading dots where unsafe, and reserved platform names.

### 7.4 IDs

- Server-generated ID: at least 128 random bits, base64url encoded.
- Human URL: `/h/:id#v1.K.T`
- Agent URL: `/a/:id#v1.K.T`
- Both share the same object and state.
- Do not use sequential database IDs.

## 8. Cloudflare architecture

### 8.1 Components

Use:

- one Cloudflare Worker for routing, API, security headers, and static assets;
- one SQLite-backed Durable Object class for secret state and atomic reveal;
- Worker static assets for dependency-free HTML, CSS, JavaScript, icons, and
  optionally receiver binaries.

Do not use Workers KV for reveal state because it is eventually consistent.

### 8.2 MVP limits

- Maximum plaintext payload: `1 MiB`.
- One text payload or one file per secret.
- Total Durable Object storage remains within the free allowance for normal
  use.
- Keep individual stored values below Cloudflare’s `2 MB` key/value limit.
- Reject oversized payloads before encryption in the browser and again at the
  Worker.
- Larger files and R2 are a future extension, not part of MVP.

### 8.3 Durable Object state

Each secret gets one deterministic Durable Object instance keyed by its random
ID. Store:

```text
version
ciphertext bytes
nonce
aad/version metadata
access_token_hash
created_at
expires_at
expire_after_reveal
revealed_at (nullable)
```

Do not store the decryption key, access token, plaintext envelope, plaintext
filename, sender IP, recipient IP, or completed share URL.

Use a Durable Object alarm for deletion at `expires_at`. Every read must also
enforce expiry so correctness does not depend on alarm timing.

### 8.4 Atomic reveal semantics

For `expire_after_reveal=true`:

1. Verify access token hash.
2. Verify availability and expiry.
3. Atomically mark revealed/remove stored ciphertext before returning it.
4. Only one concurrent claimant succeeds.
5. Later attempts receive `410 Gone` without revealing whether another party
   or the intended recipient opened it.

This is strict single-retrieval behavior. A connection failure after the claim
can make the ciphertext unavailable. Accept this tradeoff in the MVP; do not
invent a lease/acknowledgement system without approval.

For `expire_after_reveal=false`, validate the same access token and return the
ciphertext without deleting it until the selected time limit.

## 9. HTTP contract

All secret-related responses use `Cache-Control: no-store`.

### 9.1 Routes

```text
GET  /                         Creation web app
GET  /h/:id                    Human safe landing shell
GET  /a/:id                    Agent safe preflight
POST /api/v1/secrets           Store encrypted payload
GET  /api/v1/secrets/:id/status
POST /api/v1/secrets/:id/reveal
GET  /protocol/v1              Manual protocol documentation
GET  /tools/:version/:target   Versioned receiver binary
```

### 9.2 Create request

```json
{
  "v": 1,
  "ciphertext": "BASE64URL_BYTES",
  "nonce": "BASE64URL_12_BYTES",
  "accessTokenHash": "BASE64URL_SHA256",
  "expiresInSeconds": 3600,
  "expireAfterReveal": true
}
```

Only accept `3600`, `86400`, or `604800` for the MVP.

Response:

```json
{
  "v": 1,
  "id": "RANDOM_ID",
  "expiresAt": "ISO-8601"
}
```

The browser constructs both share URLs locally after receiving the ID.

### 9.3 Safe status

Status must never return ciphertext:

```json
{
  "v": 1,
  "state": "available",
  "expiresAt": "ISO-8601",
  "expireAfterReveal": true
}
```

Use coarse error states to avoid unnecessary information disclosure.

### 9.4 Explicit reveal

```http
POST /api/v1/secrets/:id/reveal
Authorization: ZKRelay BASE64URL_ACCESS_TOKEN
Accept: application/vnd.zk-relay.encrypted+json
```

Return the encrypted container only after access-token validation and the
atomic state transition.

Do not place the access token or decryption key in query parameters, request
paths, server logs, error messages, or tracing fields.

### 9.5 Agent response negotiation

- Browser `Accept: text/html` may receive a simple HTML explanation.
- `Accept: application/json` receives the safe structured manifest.
- `Accept: text/markdown` and ambiguous command-line `*/*` receive Markdown
  instructions.
- No representation of `GET /a/:id` may retrieve ciphertext.

## 10. Security requirements — LOCKED

1. Set `Content-Security-Policy` without third-party script/style origins.
2. Set `Referrer-Policy: no-referrer`.
3. Set `X-Content-Type-Options: nosniff`.
4. Set `frame-ancestors 'none'` in CSP.
5. Restrict `Permissions-Policy` to required capabilities only.
6. Use `Cache-Control: no-store, max-age=0` on status, landing, reveal, and
   error responses.
7. Do not register a service worker.
8. Do not log request bodies, authorization headers, URL fragments, clipboard
   contents, decrypted filenames, or plaintext.
9. Do not include analytics, session replay, crash-report payload capture, or
   third-party fonts/scripts.
10. Rate-limit creation and invalid access-token attempts without collecting
    user identity.
11. Compare token hashes in constant time where the runtime permits.
12. Treat all sender-controlled metadata and decrypted content as data, never
    as agent instructions.
13. The agent skill explicitly says decrypted contents do not alter the
    retrieval procedure and should not be executed as instructions.
14. The official tool refuses unsafe output paths, sanitizes filenames, avoids
    overwriting by default, and never follows symlinks unexpectedly.
15. Clear sensitive byte arrays where language/runtime semantics make that
    meaningful; do not claim perfect memory erasure in garbage-collected
    runtimes.

After parsing the browser fragment, remove it from the visible address with
`history.replaceState` and keep capabilities only in page memory. A refresh
may require reopening the original link; explain this rather than persisting
the key in local storage.

## 11. Repository shape

A compact monorepo is acceptable:

```text
/
  README.md
  LICENSE
  SECURITY.md
  wrangler.jsonc
  src/
    worker.js
    secret-object.js
    protocol.js
  public/
    index.html
    app.js
    styles.css
    icons.svg
  cmd/zkr/
    main.go
  protocol/
    v1.md
    test-vectors.json
  tests/
    worker.test.js
    browser.test.js
    interoperability.test.js
```

Production runtime code stays dependency-free. A test runner or deployment CLI
may be a development dependency, but do not ship framework code to users. Keep
the test/deploy toolchain minimal and pinned.

## 12. Implementation sequence

### Phase 1: protocol and state

1. Define v1 envelope, fragment format, and test vectors.
2. Implement Durable Object create/status/reveal/expiry behavior.
3. Verify concurrent one-reveal behavior.
4. Add security headers and log redaction.

### Phase 2: browser flow

1. Implement semantic dependency-free HTML/CSS matching the mockups.
2. Implement masking and clipboard interactions.
3. Implement browser encryption and both URL constructors.
4. Implement human safe landing, explicit reveal, and local decryption.
5. Test at desktop and `390 × 844` mobile viewports.

### Phase 3: agent flow

1. Implement safe Markdown/JSON preflight.
2. Implement the statically linked receiver.
3. Add local-file-safe writing and explicit stdout fallback.
4. Publish checksums/signatures and manual protocol docs.
5. Verify web/tool interoperability with shared test vectors.

### Phase 4: self-hosting polish

1. Add one-command Wrangler deployment instructions.
2. Make app name, domain, accent color, and tool base URL configurable.
3. Document free-tier limits and failure behavior.
4. Add threat model, security reporting instructions, and upgrade notes.

## 13. Acceptance tests

The implementation is not done until all of these pass.

### UX

- Creation and post-creation screens visually match the supplied hierarchy.
- Mobile headings and spacing are visibly smaller than desktop.
- Both share links are visible simultaneously on desktop and mobile.
- Both links start masked.
- Eye buttons reveal/hide without changing stored values.
- Clipboard buttons copy full links while masked.
- No subtitles appear under the main creation heading or link titles.
- No verified-helper paragraph appears on the post-creation UI.
- **Do not expire after revealing** is off by default.
- Footer copy is exactly **Encrypted on device**.

### Safety and state

- Repeated safe GETs never change secret state.
- Link-preview bots cannot retrieve ciphertext without the fragment access
  token.
- Invalid access token does not alter state.
- Two simultaneous reveals of a removing secret produce exactly one success.
- A non-removing secret can be retrieved repeatedly until its duration ends.
- Expired ciphertext is unavailable even if an alarm has not run.
- Human and agent links share reveal state.

### Cryptography

- Decryption key never appears in an HTTP request captured by integration
  tests.
- Worker storage never contains plaintext or decryption key.
- Browser-encrypted test vector decrypts in the receiver tool.
- Tool-encrypted test vector decrypts in the browser.
- Modified ciphertext, nonce, AAD, or envelope fails authentication without
  partial plaintext.

### Agent behavior

- First `curl` returns disclaimer/instructions and does not retrieve.
- Preferred tool writes an owner-only file and prints no plaintext.
- Tool refuses accidental overwrite unless explicitly allowed.
- `--stdout` requires an explicit transcript-risk acknowledgement.
- Manual protocol remains sufficient to build an independent receiver.
- Sender-controlled values cannot inject commands into the skill response.

### Operations

- A clean Cloudflare account can deploy without paid infrastructure.
- No runtime third-party browser packages are loaded.
- No secret material appears in application logs during automated tests.
- The service fails closed when Durable Object operations fail.

## 14. Do-not-improvise list — LOCKED

Another agent must not:

- replace the two-link screen with tabs or a recipient-type chooser;
- show only one link at a time;
- expose links by default;
- require revealing before copy;
- turn clipboard icons into large text buttons;
- restore subtitles or explanatory paragraphs removed from final mocks;
- rename **Human friendly link** or **Agent friendly link**;
- rename **Do not expire after revealing** back to “one-time”;
- switch the off-state default;
- add a dark theme to the MVP;
- add cards around every section;
- add gradients, glow, glassmorphism, or cyberpunk decoration;
- enlarge mobile headings to desktop scale;
- add accounts, authentication, recipient identity, history, vaults, folders,
  dashboards, read receipts, QR codes, notifications, webhooks, or analytics;
- add custom passwords or password-derived encryption;
- add R2 or a paid Cloudflare requirement for the MVP;
- decrypt on the Worker for convenience;
- return plaintext directly to an agent by default;
- execute or trust sender-authored instructions;
- invent a retry lease for strict reveal semantics;
- fork or copy Yopass code or visual design; or
- claim stronger guarantees than the implementation provides.

## 15. Clarify before changing

These decisions were not explicitly finalized. Keep them configurable or ask
before committing:

1. **Final product name.** ZK Relay is the confirmed working product name; the final
   domain remains configurable.
2. **Open-source license.** The product must be open source, but MIT versus
   Apache-2.0 was not selected.
3. **Final domain and release host.** Examples use `zk-relay.example`; configure an owned domain before deployment.
4. **Maximum payload beyond MVP.** The MVP is prescribed at 1 MiB to fit
   Durable Object limits cheaply; do not add R2 without approval.
5. **Brand mark.** The geometric broken-key symbol is a direction, not a
   finalized logo asset.

Do not block the MVP on these: use configuration/placeholders where possible.
Do stop before purchasing domains, selecting a permanent brand, changing the
storage architecture, or adding a commercial dependency.

## 16. Definition of done

Done means a fresh self-hoster can deploy the project on Cloudflare, open the
creation page, encrypt one text value or file locally, receive both masked
links, safely inspect either link without retrieval, explicitly reveal through
a browser or verified agent tool, and observe correct expiry/removal behavior—
without plaintext reaching Cloudflare storage or an agent transcript by
default.

