#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Generating include/uacryptex.h via cbindgen..."
cargo build -p uacryptex-ffi

HEADER_SRC="${ROOT}/include/uacryptex.h"
HEADER_DST="${ROOT}/go/uacryptex/internal/native/uacryptex.h"

if [[ ! -f "$HEADER_SRC" ]]; then
  echo "missing ${HEADER_SRC} — build.rs may have failed" >&2
  exit 1
fi

cp "$HEADER_SRC" "$HEADER_DST"
echo "Synced -> ${HEADER_DST}"
