#!/usr/bin/env bash
# Pre-release checklist: sync versions, run tests, build host native lib into client packages.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$("${ROOT}/scripts/read-version.sh")"
echo "Preparing release v${VERSION}"

"${ROOT}/scripts/sync-version.sh"
"${ROOT}/scripts/verify-version.sh"

echo "Running Rust tests..."
cargo test --workspace

echo "Building native library (host)..."
"${ROOT}/scripts/build-ffi.sh"
"${ROOT}/scripts/sync-native-libs.sh"

echo "Binding smoke tests..."
make python-test node-test
if command -v go >/dev/null; then
  make go-test
fi

echo ""
echo "Ready to tag: git tag v${VERSION}"
echo "Push tag to trigger .github/workflows/release.yml"
echo "See docs/PUBLISHING.md for registry uploads (PyPI, npm, Packagist, crates.io)."
