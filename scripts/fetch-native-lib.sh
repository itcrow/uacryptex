#!/usr/bin/env bash
# Download a prebuilt uacryptex-ffi static library from GitHub Releases.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

go_version() {
  grep 'const Version' "${ROOT}/go/uacryptex/doc.go" | sed -E 's/.*"(.*)".*/\1/'
}

VERSION="${UACRYPTEX_VERSION:-${1:-$(go_version)}}"
GOOS="${GOOS:-$(go env GOOS 2>/dev/null || echo linux)}"
GOARCH="${GOARCH:-$(go env GOARCH 2>/dev/null || echo amd64)}"
REPO="${UACRYPTEX_GITHUB_REPO:-itcrow/uacryptex}"

TAG="v${VERSION}"
ARCHIVE="uacryptex-native-${VERSION}-${GOOS}-${GOARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
OUT_DIR="${ROOT}/native/lib/${GOOS}/${GOARCH}"

if [[ -f "${OUT_DIR}/libuacryptex_ffi.a" ]] || [[ -f "${OUT_DIR}/uacryptex_ffi.lib" ]]; then
  echo "Native lib already present in ${OUT_DIR} (remove to re-fetch)"
  exit 0
fi

mkdir -p "$OUT_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Fetching ${URL}"
if ! curl -fsSL -o "${TMP}/${ARCHIVE}" "$URL"; then
  echo "Download failed. Build from source instead:" >&2
  echo "  ./scripts/build-ffi.sh ${GOOS} ${GOARCH}" >&2
  exit 1
fi

tar xzf "${TMP}/${ARCHIVE}" -C "$OUT_DIR"
"${ROOT}/scripts/sync-native-libs.sh"
echo "Installed native lib -> ${OUT_DIR} (synced to client packages)"
