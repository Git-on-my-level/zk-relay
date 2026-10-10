#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: ./scripts/build-tools.sh vX.Y.Z" >&2
  exit 2
fi

tool_version="$1"
output_dir="dist/tools/$tool_version"
if [ -n "${GOROOT:-}" ] && [ -x "${GOROOT}/bin/go" ]; then
  path_ver=$(go version 2>/dev/null || true)
  root_ver=$("${GOROOT}/bin/go" version 2>/dev/null || true)
  if [ -n "$path_ver" ] && [ "$path_ver" != "$root_ver" ]; then
    echo "Ignoring GOROOT=$GOROOT ($root_ver); PATH go is $path_ver" >&2
    unset GOROOT
  fi
fi
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

# ponytail: zip-notarize only, no staple. A raw Mach-O cannot hold a ticket;
# Gatekeeper checks Apple online. Ship a signed pkg if offline first-run matters.
# Linux CI cannot codesign; set ZKR_SKIP_APPLE_SIGN=1 to build unsigned on a Mac.
sign_macos() {
  if [ "${ZKR_SKIP_APPLE_SIGN:-}" = "1" ]; then
    echo "ZKR_SKIP_APPLE_SIGN=1; darwin binaries left linker-signed" >&2
    return 0
  fi
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "Darwin binaries are linker-signed on $(uname -s). Publish macOS from the maintainer Mac. See AGENTS.md." >&2
    return 0
  fi

  identity="${ZKR_CODESIGN_IDENTITY:-}"
  if [ -z "$identity" ]; then
    identities=$(security find-identity -v -p codesigning | grep "Developer ID Application:" || true)
    count=$(printf '%s\n' "$identities" | grep -c "Developer ID Application:" || true)
    if [ "$count" -eq 0 ]; then
      echo "No Developer ID Application identity. Refusing to checksum linker-signed darwin binaries." >&2
      exit 1
    fi
    if [ "$count" -eq 1 ]; then
      identity=$(printf '%s\n' "$identities" | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p')
    else
      # Both generations share one name. Prefer the G2 Sub-CA certificate.
      certs=$(mktemp)
      chosen=$(mktemp)
      security find-certificate -a -p -Z > "$certs"
      printf '%s\n' "$identities" | while read -r line; do
        hash=$(printf '%s\n' "$line" | awk '{print $2}')
        issuer=$(awk -v h="$hash" '
          /^SHA-1 hash:/ { ok = ($3 == h); next }
          ok && /BEGIN CERTIFICATE/ { emit = 1 }
          emit { print }
          ok && /END CERTIFICATE/ { exit }
        ' "$certs" | openssl x509 -noout -issuer 2>/dev/null || true)
        case "$issuer" in
          *G2*) printf '%s\n' "$hash" >> "$chosen" ;;
        esac
      done
      chosen_count=$(grep -c . "$chosen" || true)
      if [ "$chosen_count" -ne 1 ]; then
        echo "Set ZKR_CODESIGN_IDENTITY to one Developer ID hash:" >&2
        printf '%s\n' "$identities" >&2
        rm -f "$certs" "$chosen"
        exit 1
      fi
      identity=$(cat "$chosen")
      rm -f "$certs" "$chosen"
    fi
  fi

  case "$identity" in
    *"Developer ID Application:"*)
      issuer=$(security find-certificate -c "$identity" -p 2>/dev/null | openssl x509 -noout -issuer -enddate 2>/dev/null || true)
      ;;
    *)
      issuer=$(security find-certificate -a -p -Z | awk -v h="$identity" '
        /^SHA-1 hash:/ { ok = ($3 == h); next }
        ok && /BEGIN CERTIFICATE/ { emit = 1 }
        emit { print }
        ok && /END CERTIFICATE/ { exit }
      ' | openssl x509 -noout -issuer -enddate 2>/dev/null || true)
      ;;
  esac
  case "$issuer" in
    *G2*) ;;
    *) echo "warning: Developer ID is not from the G2 Sub-CA ($issuer). It cannot sign new releases after 2027-02-01." >&2 ;;
  esac

  profile="${ZKR_NOTARY_PROFILE:-zkr-notary}"
  err=$(mktemp)
  if ! xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>"$err"; then
    cat "$err" >&2
    if grep -q "No Keychain password item found" "$err"; then
      team=$(printf '%s\n' "$identity" | sed -n 's/.*(\([A-Z0-9]\{10\}\)).*/\1/p')
      echo "One-time: xcrun notarytool store-credentials \"$profile\" --team-id ${team:-TEAMID} --apple-id YOUR_APPLE_ID" >&2
    fi
    rm -f "$err"
    exit 1
  fi
  rm -f "$err"

  # codesign --timestamp fails when the local clock and Apple's timestamp server differ by a few minutes.
  skew=$(sntp time.apple.com 2>/dev/null | awk 'NR==1 { v=$1; gsub(/^\+/, "", v); if (v+0 < 0) v = -(v+0); else v = v+0; print v; exit }' || true)
  if [ -n "$skew" ]; then
    too_far=$(awk -v s="$skew" 'BEGIN { print (s > 60) ? 1 : 0 }')
    if [ "$too_far" -eq 1 ]; then
      echo "System clock is ${skew}s from time.apple.com. Sync it before signing." >&2
      exit 1
    fi
  fi

  for binary in "$output_dir"/zkr-darwin-*; do
    codesign --force --options runtime --timestamp --sign "$identity" "$binary"
    codesign --verify --strict --verbose=2 "$binary"
  done

  tmp=$(mktemp -d)
  stage="$tmp/stage"
  mkdir -p "$stage"
  cp "$output_dir"/zkr-darwin-* "$stage/"
  ditto -c -k "$stage" "$tmp/zkr-macos.zip"
  xcrun notarytool submit "$tmp/zkr-macos.zip" --keychain-profile "$profile" --wait
  rm -rf "$tmp"
  echo "Signed and notarized darwin binaries with $identity"
}

sign_macos

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
