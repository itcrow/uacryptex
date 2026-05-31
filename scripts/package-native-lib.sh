#!/usr/bin/env bash
# Package native/lib/{goos}/{goarch} into dist/uacryptex-native-{version}-{goos}-{goarch}.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:?usage: package-native-lib.sh VERSION GOOS GOARCH}"
GOOS="${2:?usage: package-native-lib.sh VERSION GOOS GOARCH}"
GOARCH="${3:?usage: package-native-lib.sh VERSION GOOS GOARCH}"

SRC="${ROOT}/native/lib/${GOOS}/${GOARCH}"
if [[ ! -d "$SRC" ]] || [[ -z "$(ls -A "$SRC" 2>/dev/null)" ]]; then
  echo "missing native lib in ${SRC}" >&2
  exit 1
fi

mkdir -p "${ROOT}/dist"
ARCHIVE="${ROOT}/dist/uacryptex-native-${VERSION}-${GOOS}-${GOARCH}.tar.gz"
tar czf "$ARCHIVE" -C "$SRC" .
echo "Created ${ARCHIVE}"
