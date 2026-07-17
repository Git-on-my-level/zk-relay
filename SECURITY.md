# Security policy

## Reporting a vulnerability

Until the project has a configured security contact, report a vulnerability to the repository owner through a private channel. Do not open a public issue. Include a minimal reproduction with synthetic data only. Never include a live Relay URL fragment, access token, decryption key, ciphertext from a live secret, or plaintext.

## Security properties

- Browser and receiver decryption use AES-256-GCM locally.
- Cloudflare receives ciphertext, nonce, `SHA-256(access token)`, expiry, and removal metadata—not the decryption key, plaintext, raw access token, or filename.
- The path ID alone cannot retrieve ciphertext. Explicit reveal requires the fragment access token in an authorization header.
- Safe landing, status, and agent-preflight requests never retrieve ciphertext.
- Removing secrets are strictly single retrieval: ciphertext is removed before the response leaves the Durable Object.
- The receiver defaults to a 0600 temporary file and atomic finalization. It refuses existing outputs unless `--force`, rejects unsafe paths/symlinks, and refuses plaintext stdout without explicit acknowledgement.

## Important limitations

Relay is capability-based, not identity-based. Anyone with a complete URL can attempt retrieval. A recipient can copy plaintext after decryption. An endpoint or browser compromised before local decryption can access the plaintext. The Worker cannot protect a URL fragment that is pasted into an untrusted log or agent transcript.

For removing secrets, a network failure after the server has made the atomic claim can make the payload permanently unavailable. This is intentional and prevents retry races; there is no delivery acknowledgement.

Garbage-collected browser JavaScript cannot promise perfect memory erasure. Relay clears sensitive byte arrays and page state where practical but does not claim stronger guarantees.

## Deployment checklist

- Replace the placeholder receiver release URL and every checksum before public use.
- Keep Wrangler, the Workers runtime compatibility date, and Go current.
- Configure an HTTPS custom domain if using one.
- Build and verify receiver releases independently; never instruct users to pipe an unverified download into a shell.
- Keep Cloudflare dashboard access tightly controlled.
