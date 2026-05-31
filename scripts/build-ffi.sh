#!/usr/bin/env bash
# Build static lib for Go cgo. Optional: UACRYPTEX_FEATURES=ct-scalar-mul for hardened DSTU 4145 scalar mul.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GOOS="${1:-$(go env GOOS 2>/dev/null || echo linux)}"
GOARCH="${2:-$(go env GOARCH 2>/dev/null || echo amd64)}"

case "${GOOS}_${GOARCH}" in
  linux_amd64)   TARGET="x86_64-unknown-linux-gnu" ;;
  linux_arm64)   TARGET="aarch64-unknown-linux-gnu" ;;
  darwin_amd64)  TARGET="x86_64-apple-darwin" ;;
  darwin_arm64)  TARGET="aarch64-apple-darwin" ;;
  windows_amd64) TARGET="x86_64-pc-windows-msvc" ;;
  *)
    echo "unsupported platform: ${GOOS}/${GOARCH}" >&2
    exit 1
    ;;
esac

OUT_DIR="${ROOT}/native/lib/${GOOS}/${GOARCH}"
mkdir -p "$OUT_DIR"

# Cross-compile: Rust defaults to the host linker (x86_64 on GitHub ubuntu-latest),
# which fails with "incompatible with elf64-x86-64" for aarch64 object files.
setup_cross_linker() {
  case "$1" in
    aarch64-unknown-linux-gnu)
      if [[ "$(uname -s)" == "Linux" && "$(uname -m)" != "aarch64" ]]; then
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_AR:-aarch64-linux-gnu-ar}"
        if ! command -v "${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER}" >/dev/null; then
          echo "Cross linker not found: ${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER}" >&2
          echo "Install gcc-aarch64-linux-gnu (Debian/Ubuntu) or gcc-aarch64-linux-gnu (Fedora)." >&2
          exit 1
        fi
      fi
      ;;
  esac
}

setup_cross_linker "$TARGET"

echo "Building uacryptex-ffi for ${TARGET} -> ${OUT_DIR}"
FEATURES="${UACRYPTEX_FEATURES:-}"
if [[ -n "$FEATURES" ]]; then
  cargo build -p uacryptex-ffi --release --target "$TARGET" --features "$FEATURES"
else
  cargo build -p uacryptex-ffi --release --target "$TARGET"
fi

SRC="${ROOT}/target/${TARGET}/release"
SHARED_DIR="${OUT_DIR}/shared"
mkdir -p "$SHARED_DIR"
case "$GOOS" in
  windows)
    cp "${SRC}/uacryptex_ffi.lib" "${OUT_DIR}/"
    cp "${SRC}/uacryptex_ffi.dll" "${SHARED_DIR}/"
    ;;
  darwin)
    cp "${SRC}/libuacryptex_ffi.a" "${OUT_DIR}/"
    cp "${SRC}/libuacryptex_ffi.dylib" "${SHARED_DIR}/"
    ;;
  *)
    cp "${SRC}/libuacryptex_ffi.a" "${OUT_DIR}/"
    cp "${SRC}/libuacryptex_ffi.so" "${SHARED_DIR}/"
    ;;
esac

echo "Done."
