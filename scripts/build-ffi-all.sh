#!/usr/bin/env bash
# Build uacryptex-ffi for every supported platform in this checkout.
#
# CI runs one platform per job via the matrix; locally only the host target
# usually succeeds unless cross-toolchains are installed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/platforms.sh
source "${ROOT}/scripts/platforms.sh"

ok=0
fail=0

for entry in "${UACRYPTEX_PLATFORMS[@]}"; do
  read -r goos goarch <<< "$entry"
  echo "=== build-ffi ${goos}/${goarch} ==="
  if "${ROOT}/scripts/build-ffi.sh" "$goos" "$goarch"; then
    ok=$((ok + 1))
  else
    echo "WARN: build failed for ${goos}/${goarch}" >&2
    fail=$((fail + 1))
  fi
done

echo "build-ffi-all: ${ok} succeeded, ${fail} failed"
if [[ "$ok" -eq 0 ]]; then
  exit 1
fi
