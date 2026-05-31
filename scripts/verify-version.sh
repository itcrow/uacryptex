#!/usr/bin/env bash
# Fail if binding package versions diverge from Cargo.toml workspace version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$("${ROOT}/scripts/read-version.sh")"
fail=0

check() {
  local name="$1"
  local got="$2"
  if [[ "$got" != "$VERSION" ]]; then
    echo "FAIL ${name}: expected ${VERSION}, got ${got}" >&2
    fail=1
  else
    echo "OK   ${name}: ${got}"
  fi
}

check "Cargo.toml" "$VERSION"
check "Go doc.go" "$(grep 'const Version' "${ROOT}/go/uacryptex/doc.go" | sed -E 's/.*"(.*)".*/\1/')"
check "Python pyproject" "$(grep '^version' "${ROOT}/python/pyproject.toml" | sed -E 's/version = "(.*)"/\1/')"
check "Python __init__" "$(grep '^__version__' "${ROOT}/python/uacryptex/__init__.py" | sed -E 's/__version__ = "(.*)"/\1/')"
check "PHP Uacryptex" "$(grep 'const VERSION' "${ROOT}/php/src/Uacryptex.php" | sed -E "s/.*'(.*)'.*/\1/")"
check "npm package.json" "$(node -p "require('${ROOT}/nodejs/package.json').version")"

if [[ "$fail" -ne 0 ]]; then
  echo "Run ./scripts/sync-version.sh" >&2
  exit 1
fi

echo "All versions match ${VERSION}"
