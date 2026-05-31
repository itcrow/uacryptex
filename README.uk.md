# uacryptex

> **Languages:** English · [Українська](README.uk.md)

Українська криптографічна бібліотека: **pure Rust core** з мовними binding-ами поверх стабільного C ABI.

Натхненна [Cryptonite](https://github.com/privat-it/cryptonite) — алгоритми DSTU/GOST, PKI (CMS, OCSP, TSP), PKCS#12.

## Архітектура

```
Застосунок (Go / Python / PHP / Node.js)
    │  idiomatic API
    ▼
go/ | python/ | php/ | nodejs/
    │  cgo | ctypes | FFI | koffi
    ▼
uacryptex-ffi  (cbindgen → uacryptex.h)
    ▼
uacryptex-core (primitives, pki, storage)
```

Rust — єдине джерело істини. Legacy C Cryptonite не використовується в runtime.

## Структура репозиторію

| Шлях | Роль |
|------|------|
| `crates/uacryptex-core/` | Pure Rust crypto + PKI |
| `crates/uacryptex-ffi/` | C ABI |
| `go/uacryptex/` | Go package |
| `python/uacryptex/` | Python (ctypes) |
| `php/src/` | PHP (FFI) |
| `nodejs/lib/` | Node.js (koffi) |
| `native/lib/` | canonical build output |
| `docs/` | документація (EN + `docs/uk/`) |

## Швидкий старт

```bash
git clone https://github.com/itcrow/uacryptex.git
cd uacryptex
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh
```

**Go:** `cd go && CGO_ENABLED=1 go test ./...`

**Python:** `cd python && pip install -e . && python tests/test_version.py`

**PHP:** `cd php && php -d ffi.enable=1 tests/VersionTest.php`

**Node.js:** `cd nodejs && npm install && npm test`

## Алгоритми

DSTU 4145, Kupyna (7564), Kalyna (7624), GOST 28147/34.311, legacy GOST 34.10-94 (`legacy-gost3410`), AES/RSA/ECDSA/SHA (RustCrypto).

## Ліцензія

MIT — [LICENSE](LICENSE).

## Документація

Повний індекс: [docs/uk/README.md](docs/uk/README.md)

| Українська | English |
|------------|---------|
| [Архітектура](docs/uk/ARCHITECTURE.md) | [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| [Binding-и](docs/uk/BINDINGS.md) | [BINDINGS.md](docs/BINDINGS.md) |
| [Клієнтські бібліотеки](docs/uk/CLIENT_LIBRARIES.md) | [CLIENT_LIBRARIES.md](docs/CLIENT_LIBRARIES.md) |
| [Безпека](docs/uk/SECURITY.md) | [SECURITY.md](docs/SECURITY.md) |
| [Публікація](docs/uk/PUBLISHING.md) | [PUBLISHING.md](docs/PUBLISHING.md) |
| [Сертифікація](docs/uk/CERTIFICATION.md) | [CERTIFICATION.md](docs/CERTIFICATION.md) |

Довідники лише англійською: [API_INVENTORY.md](docs/API_INVENTORY.md), [REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md).
