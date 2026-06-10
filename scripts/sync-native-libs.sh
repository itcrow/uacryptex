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
  "${ROOT}/dart/uacryptex/native/lib"
)

for dest in "${DESTS[@]}"; do
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  cp -a "$SRC" "$dest"
  touch "${dest}/.gitkeep"
  echo "synced -> ${dest}"
done

WIN_STATIC="${ROOT}/native/lib/windows/amd64/libuacryptex_ffi.a"
if [[ -f "$WIN_STATIC" ]]; then
  test -f "${ROOT}/go/native/lib/windows/amd64/libuacryptex_ffi.a" || {
    echo "Go Windows static lib missing after sync" >&2
    exit 1
  }
  # Co-locate for cgo: MinGW on Windows often fails -L/-l search with ${SRCDIR} paths.
  cp "$WIN_STATIC" "${ROOT}/go/uacryptex/internal/native/libuacryptex_ffi.a"
fi

# Optional: Android NDK-built libs under native/lib/android/{abi}/shared/
ANDROID_LIB_ROOT="${ROOT}/native/lib/android"
DART_JNI="${ROOT}/dart/uacryptex/android/src/main/jniLibs"
if [[ -d "$ANDROID_LIB_ROOT" ]]; then
  rm -rf "$DART_JNI"
  for abi_dir in "$ANDROID_LIB_ROOT"/*; do
    [[ -d "$abi_dir" ]] || continue
    abi="$(basename "$abi_dir")"
    so="${abi_dir}/shared/libuacryptex_ffi.so"
    if [[ -f "$so" ]]; then
      mkdir -p "${DART_JNI}/${abi}"
      cp "$so" "${DART_JNI}/${abi}/libuacryptex_ffi.so"
      echo "synced android jniLibs -> ${DART_JNI}/${abi}"
    fi
  done
fi

echo "Done. Client packages now embed native/lib for all built platforms."
