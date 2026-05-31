#!/usr/bin/env bash
# Run libFuzzer targets (requires nightly + cargo-fuzz: cargo install cargo-fuzz).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/fuzz"

TARGET="${1:-cms_decode}"
shift || true

MAX_TIME="${FUZZ_MAX_TIME:-60}"
echo "Fuzzing ${TARGET} (max ${MAX_TIME}s)..."
cargo fuzz run "$TARGET" -- -max_total_time="${MAX_TIME}" "$@"
