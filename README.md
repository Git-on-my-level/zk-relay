# Relay

Relay is a small, self-hosted Cloudflare Worker for sending one encrypted text value or file to a person or a tool-using agent. The sender’s browser encrypts the payload; Cloudflare stores only ciphertext. A share produces a human link and an agent link for the same secret.

Relay has no accounts, analytics, browser SDKs, third-party browser runtime code, external database, or always-on server. It uses one Worker and one SQLite-backed Durable Object per secret.

## What a recipient does

- A human opens `/h/:id`, safely reads the warning, and explicitly chooses **Reveal secret**. Decryption happens in that browser.
- An agent can safely `curl` `/a/:id`. It receives preflight instructions, not ciphertext. The preferred command is:

  ```sh
  relay receive "$RELAY_URL" --output ./secret
  ```

  The receiver decrypts locally and writes an owner-only local file. It never prints plaintext by default. Plaintext stdout is deliberately gated behind `--stdout --allow-plaintext-stdout` and a transcript-risk warning.

  The official receiver accepts only complete `https://` agent links. When an explicit `--output` target is unsafe or already exists without `--force`, it rejects that target before claiming a potentially one-time secret.

By default, the first successful reveal removes the encrypted payload. Enable **Do not expire after revealing** to allow repeated retrieval until the chosen time limit. The available limits are 1 hour, 1 day, and 7 days.

## Quick start

Prerequisites: a Cloudflare account, Node.js 20+, Go 1.22+ (to build the receiver), and a current Wrangler login.

```sh
npm install
npm test
npx wrangler@4.41.0 login
npm run deploy
```

The first deploy creates the SQLite-backed Durable Object declared in `wrangler.jsonc`. No D1, KV, R2, queue, workflow, or separate database is needed. Configure a custom domain in Cloudflare after deploying if desired; links are constructed from the origin that serves the browser app.

Before a public deployment, complete the receiver-release configuration below. The committed configuration intentionally uses a placeholder domain and placeholder checksums rather than claiming a release that does not exist.

## Configuration

All non-secret settings are in `wrangler.jsonc` under `vars`:

| Setting | Purpose |
| --- | --- |
| `APP_NAME` | Working product name rendered in the app shell. |
| `ACCENT_COLOR` | Six-digit hex security accent color. |
| `TOOL_VERSION` | Pinned receiver release version shown to agents. |
| `TOOL_RELEASE_BASE_URL` | HTTPS base URL containing the release binaries. |
| `TOOL_SHA256_*` | SHA-256 checksum for every published target binary. |

Set an actual HTTPS release base and all five checksums before making the agent link available. The preflight response exposes these values so an agent can verify a stable receiver rather than executing network-provided code.

`Relay` is a configurable working name, not a claimed trademark. The project also intentionally does not select a software license: choose and add an approved open-source license before public redistribution.

## Publishing the receiver

Build the dependency-free Go receiver for the supported platforms:

```sh
./scripts/build-tools.sh v1.0.0
```

This produces untracked artifacts under `dist/tools/v1.0.0/` plus `SHA256SUMS`. Upload the five binaries to the HTTPS location configured by `TOOL_RELEASE_BASE_URL`, verify them independently, then replace every `TOOL_SHA256_*` placeholder in `wrangler.jsonc` with the corresponding hash. The release process intentionally does not commit binaries or generated files.

Targets are Linux x86-64 and ARM64, macOS x86-64 and ARM64, and Windows x86-64. The binary is statically built (`CGO_ENABLED=0`) and uses only Go’s standard library.

## Local development and checks

```sh
npm run dev
npm run check
npm test
go vet ./...
```

`npm test` runs browser/protocol/Worker logic tests and the Go receiver tests. The shared deterministic AES-GCM vector is in [`protocol/test-vectors.json`](protocol/test-vectors.json). It proves the browser Web Crypto and Go implementations agree on the encrypted format.

Use a local secret only for development. Share URLs include capabilities in their fragments, so do not paste a real one into a terminal transcript, issue, chat, log, or test fixture.

## Architecture and privacy model

1. The browser generates independent random 32-byte AES key `K` and access token `T`.
2. It encrypts a versioned JSON envelope with AES-256-GCM, 12-byte random nonce, and UTF-8 AAD `relay/v1;envelope`.
3. It uploads ciphertext, nonce, `SHA-256(T)`, expiry, and removal behavior. It never uploads `K`, `T`, plaintext, or filename.
4. It constructs `/h/:id#v1.K.T` and `/a/:id#v1.K.T` locally. Fragments are not sent in HTTP requests.
5. A Durable Object validates `T` only for an explicit reveal. A removing secret is atomically replaced with a tombstone before ciphertext is returned, so exactly one concurrent reveal succeeds.

Each object has a SQLite row containing ciphertext, nonce, AAD metadata, token hash, creation/expiry timestamps, removal behavior, and a non-sensitive invalid-attempt counter. It never stores a decryption key, access token, plaintext, filename, sender IP, or recipient IP. An alarm deletes expired state; every read also checks expiry, so correctness does not rely on alarm timing.

Creation is protected by a best-effort, per-isolate global rate bucket without storing client identity. Invalid reveal attempts are rate-limited per secret; no IP address is retained. These controls are abuse friction, not a substitute for a dedicated edge rate-limiting product if an operator expects hostile, large-scale traffic.

All secret routes return `Cache-Control: no-store, max-age=0`. The Worker sets a strict self-only CSP, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and a restrictive Permissions Policy. Relay does not register a service worker and contains no telemetry or runtime third-party dependencies.

## Operational limits and behavior

- One UTF-8 text value **or** one file per secret; maximum plaintext payload: 1 MiB.
- The encrypted container is capped below the Durable Object SQLite 2 MB row limit.
- Expired secrets are unavailable even if an alarm is delayed.
- A successful removing reveal followed by a connection failure can leave the recipient without ciphertext. This is the intentional strict single-reveal tradeoff; Relay has no retry lease or acknowledgement mechanism.
- Availability depends on Cloudflare Workers and Durable Objects. Object failures fail closed rather than returning a partial result.

## Manual receivers and protocol

The agent preflight always recommends the verified receiver, but independent implementations are supported. Read [`protocol/v1.md`](protocol/v1.md) before writing one. It specifies URL capabilities, the safe status/reveal endpoints, AES-GCM AAD, envelope schema, limits, and file-safety requirements.

Decrypted data—including sender-provided filenames and contents—is untrusted data, never trusted executable instructions.

## Security reporting

Please read [`SECURITY.md`](SECURITY.md). Do not put live fragments, access tokens, decryption keys, ciphertext from a live secret, or plaintext in a public issue.
