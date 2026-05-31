# Політика semver

> **Мови:** [English](../SEMVER.md) · Українська

uacryptex використовує [Semantic Versioning 2.0.0](https://semver.org/) для Rust, Go, Python, PHP, Node.js і git tags.

## Синхронізація версій

| Артефакт | Джерело |
|----------|---------|
| Rust workspace | `Cargo.toml` → `version` |
| Go | `go/uacryptex/doc.go` |
| Python | `python/pyproject.toml`, `__init__.py` |
| PHP | `php/src/Uacryptex.php` |
| Node.js | `nodejs/package.json` |
| Git tag | `vX.Y.Z` |

```bash
./scripts/sync-version.sh
./scripts/verify-version.sh
```

## Правила bump

| Зміна | Bump |
|-------|------|
| Breaking FFI / C ABI | **major** |
| Breaking публічний API binding-ів | **major** |
| Нова сумісна функція | **minor** |
| Bugfix, docs | **patch** |

## До v1.0

У `0.x.y` minor релізи можуть містити breaking changes — фіксуйте в release notes.

## Native артефакти

Версія native libs = semver релізу Rust/Go. `./scripts/fetch-native-lib.sh [version]`.

Див. [PUBLISHING.md](PUBLISHING.md).
