#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: ./scripts/build-tools.sh vX.Y.Z" >&2
  exit 2
fi

tool_version="$1"
output_dir="dist/tools/$tool_version"
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/relay-go-cache}"
export GOMODCACHE="${GOMODCACHE:-${TMPDIR:-/tmp}/relay-go-mod-cache}"
mkdir -p "$output_dir"

build_target() {
  goos="$1"
  goarch="$2"
  filename="$3"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags='-s -w' -o "$output_dir/$filename" ./cmd/relay
}

build_target linux amd64 relay-linux-amd64
build_target linux arm64 relay-linux-arm64
build_target darwin amd64 relay-darwin-amd64
build_target darwin arm64 relay-darwin-arm64
build_target windows amd64 relay-windows-amd64.exe

(
  cd "$output_dir"
  shasum -a 256 relay-* > SHA256SUMS
)

echo "Built receiver artifacts in $output_dir"
