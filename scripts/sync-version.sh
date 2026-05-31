#!/usr/bin/env bash
# Propagate Cargo.toml workspace version to Go / Python / PHP / Node bindings.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$("${ROOT}/scripts/read-version.sh")"

echo "Syncing version ${VERSION}..."

# Go
sed -i "s/^const Version = \".*\"/const Version = \"${VERSION}\"/" "${ROOT}/go/uacryptex/doc.go"

# Python
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" "${ROOT}/python/pyproject.toml"
sed -i "s/^__version__ = \".*\"/__version__ = \"${VERSION}\"/" "${ROOT}/python/uacryptex/__init__.py"

# PHP
sed -i "s/public const VERSION = '.*';/public const VERSION = '${VERSION}';/" "${ROOT}/php/src/Uacryptex.php"

# Node.js
node -e "
const fs = require('fs');
const p = '${ROOT}/nodejs/package.json';
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
j.version = '${VERSION}';
fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
"

echo "Done. Run ./scripts/verify-version.sh to confirm."
