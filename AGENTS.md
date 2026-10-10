# Shipping the CLI

Users download `zkr` from `TOOL_RELEASE_BASE_URL` on the Worker site. That URL is the release. GitHub Releases are not.

## Where to build

Build on the maintainer Mac that holds the Developer ID private key and the `zkr-notary` keychain profile. `./scripts/build-tools.sh vX.Y.Z` signs and notarizes the darwin binaries, then writes checksums. Do not set `ZKR_SKIP_APPLE_SIGN` for a public build.

The tag workflow runs on Linux. It GPG-signs checksums and cannot Apple-sign. Its darwin binaries stay linker-signed. Do not copy them, or that job's `SHA256SUMS`, into `public/tools/` or `wrangler.jsonc`.

## Publish

1. Pick a new version. Do not replace binaries already published under an old version.
2. Run `./scripts/build-tools.sh vX.Y.Z` on that Mac. Continue only if the log contains `Signed and notarized` and `status: Accepted`.
3. Copy `dist/tools/vX.Y.Z/` to `public/tools/vX.Y.Z/`. Binaries are gitignored. Commit the checksum files.
4. Set `TOOL_VERSION`, `TOOL_RELEASE_BASE_URL`, and every `TOOL_SHA256_*` from that Mac build's `SHA256SUMS`. Deploy the Worker in the same change.

Apple credentials stay in the login keychain. Do not commit a `.p12`, an App Store Connect key, or the notary password.
