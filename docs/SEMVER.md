# Semver policy

> **Languages:** English · [Українська](uk/SEMVER.md)

uacryptex uses [Semantic Versioning 2.0.0](https://semver.org/) across Rust crates, Go modules, and Git tags.

## Version sync

| Artifact | Source of truth |
|----------|-----------------|
| Rust workspace | `Cargo.toml` → `[workspace.package] version` |
| Go package | `go/uacryptex/doc.go` → `const Version` |
| Python | `python/pyproject.toml`, `uacryptex/__init__.py` |
| PHP | `php/src/Uacryptex.php` → `VERSION` |
| Node.js | `nodejs/package.json` |
| Git tag | `v{major}.{minor}.{patch}` (e.g. `v0.1.0`) |
| GitHub Release assets | `uacryptex-native-{version}-{goos}-{goarch}.tar.gz` |

Sync all binding versions: `./scripts/sync-version.sh` (see [PUBLISHING.md](PUBLISHING.md)).

Release tags must match the workspace version. CI reads the tag when packaging native libraries.

## Bump rules

| Change | Bump | Examples |
|--------|------|----------|
| Breaking FFI (C ABI, struct layout, function removal/rename) | **major** | Remove `uacryptex_*`, change `UacryptexError` layout |
| Breaking Go public API | **major** | Rename exported funcs, change `PrivateKey` methods |
| New algorithm or PKI feature (backward compatible) | **minor** | Add TSP profile, new curve |
| Bug fix, performance, docs | **patch** | Fix CMS verify, KAT correction |

## Pre-1.0

While `0.x.y`, minor releases may include breaking changes to FFI and Go API. Document breaking changes in release notes.

## Native library artifacts

Native static libraries are versioned with the same semver as the Rust/Go release they were built from. Use `./scripts/fetch-native-lib.sh [version]` to install matching binaries for your platform.
