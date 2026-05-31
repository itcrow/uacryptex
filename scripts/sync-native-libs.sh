#!/usr/bin/env bash
# Copy canonical native/lib/* into each client binding package.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/native/lib"

if [[ ! -d "$SRC" ]] || [[ -z "$(find "$SRC" -name 'libuacryptex_ffi.*' -o -name 'uacryptex_ffi.*' 2>/dev/null | head -1)" ]]; then
  echo "No built native libraries under ${SRC}." >&2
  echo "Run ./scripts/build-ffi.sh or ./scripts/build-ffi-all.sh first." >&2
  exit 1
fi

DESTS=(
  "${ROOT}/go/native/lib"
  "${ROOT}/python/uacryptex/native/lib"
  "${ROOT}/php/native/lib"
  "${ROOT}/nodejs/native/lib"
)

for dest in "${DESTS[@]}"; do
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  cp -a "$SRC" "$dest"
  touch "${dest}/.gitkeep"
  echo "synced -> ${dest}"
done

echo "Done. Client packages now embed native/lib for all built platforms."
