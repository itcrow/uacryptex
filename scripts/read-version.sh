#!/usr/bin/env bash
# Print workspace semver from Cargo.toml (single source of truth).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grep -E '^version = ' "${ROOT}/Cargo.toml" | head -1 | sed -E 's/version = "(.*)"/\1/'
