#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: ./scripts/build-tools.sh vX.Y.Z" >&2
  exit 2
fi

tool_version="$1"
output_dir="dist/tools/$tool_version"
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/zk-relay-go-cache}"
export GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/zk-relay-go-mod-cache}"
mkdir -p "$output_dir"

build_target() {
  goos="$1"
  goarch="$2"
  filename="$3"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$output_dir/$filename" ./cmd/zkr
}

build_target linux amd64 zkr-linux-amd64
build_target linux arm64 zkr-linux-arm64
build_target darwin amd64 zkr-darwin-amd64
build_target darwin arm64 zkr-darwin-arm64
build_target windows amd64 zkr-windows-amd64.exe

(
  cd "$output_dir"
  shasum -a 256 zkr-* > SHA256SUMS
  cp SHA256SUMS checksums.txt
  if command -v gpg >/dev/null 2>&1; then
    signing_key="${ZK_RELAY_GPG_KEY:-zkr@scalingforever.com}"
    gpg --batch --yes --pinentry-mode loopback --passphrase "${ZK_RELAY_GPG_PASSPHRASE-}" \
      --local-user "$signing_key" --detach-sign --armor -o SHA256SUMS.asc SHA256SUMS
    echo "Signed checksums with $signing_key"
  else
    echo "gpg not found; skipped SHA256SUMS.asc" >&2
  fi
)

echo "Built receiver artifacts in $output_dir"
