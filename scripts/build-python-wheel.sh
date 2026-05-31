#!/usr/bin/env bash
# Build a platform-specific Python wheel with embedded shared library for current host.
# CI runs this once per matrix row; upload all wheels + sdist to PyPI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/python"

pip install -q build wheel 2>/dev/null || python -m pip install -q build wheel

# Ensure only this platform's native lib is present (wheel must not mix platforms).
GOOS="${1:-$(go env GOOS 2>/dev/null || echo linux)}"
GOARCH="${2:-$(go env GOARCH 2>/dev/null || echo amd64)}"

"${ROOT}/scripts/build-ffi.sh" "$GOOS" "$GOARCH"
"${ROOT}/scripts/sync-native-libs.sh"

python -m build --wheel --outdir "${ROOT}/dist"
echo "Wheel(s) in ${ROOT}/dist/"
