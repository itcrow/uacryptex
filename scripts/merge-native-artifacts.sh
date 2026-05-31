#!/usr/bin/env bash
# Merge CI matrix artifacts (native-{goos}-{goarch}/) into native/lib/.
# Usage: merge-native-artifacts.sh ARTIFACTS_DIR
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS="${1:?usage: merge-native-artifacts.sh ARTIFACTS_DIR}"

mkdir -p "${ROOT}/native/lib"

shopt -s nullglob
for dir in "${ARTIFACTS}"/native-*; do
  base="$(basename "$dir")"
  # native-linux-amd64 -> linux amd64
  rest="${base#native-}"
  goos="${rest%%-*}"
  goarch="${rest#*-}"
  dest="${ROOT}/native/lib/${goos}/${goarch}"
  mkdir -p "$dest"
  cp -a "${dir}/." "$dest/"
  echo "merged ${base} -> ${dest}"
done

"${ROOT}/scripts/sync-native-libs.sh"
