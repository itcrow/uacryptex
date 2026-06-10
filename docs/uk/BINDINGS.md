# Мовні binding-и

> **Мови:** [English](../BINDINGS.md) · Українська

uacryptex надає **стабільний C ABI** (`crates/uacryptex-ffi`, заголовок `include/uacryptex.h`). Мовні пакети — тонкі обгортки; криптологіка лише в Rust.

**Розробникам застосунків:** [CLIENT_LIBRARIES.md](CLIENT_LIBRARIES.md) (встановлення, приклади API, CAdES, troubleshooting). Цей документ — збірка та підтримка binding-ів.

## Структура

| Мова | Шлях | Механізм | Документація |
|------|------|----------|--------------|
| Go | `go/uacryptex/` | cgo (static `.a`) | [README.md](../../README.md) |
| Python | `python/uacryptex/` | ctypes (shared `.so`) | [python/README.md](../../python/README.md) |
| PHP | `php/src/` | `ext-ffi` (shared) | [php/README.md](../../php/README.md) |
| Node.js | `nodejs/lib/` | koffi (shared) | [nodejs/README.md](../../nodejs/README.md) |
| Dart / Flutter | `dart/uacryptex/` | `dart:ffi` (shared) | [dart/uacryptex/README.md](../../dart/uacryptex/README.md) |

## Збірка native-бібліотеки

З кореня репозиторію — **платформа хоста**:

```bash
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh   # копіювання в go/python/php/nodejs/dart
```

**Усі підтримувані платформи** (CI matrix):

```bash
./scripts/build-ffi-all.sh
./scripts/sync-native-libs.sh
```

Підтримка: `linux`/`darwin`/`windows` × `amd64`/`arm64` (`scripts/platforms.sh`).

Кожен client-пакет містить дерево `native/lib/`:

| Пакет | Шлях |
|-------|------|
| Go | `go/native/lib/{os}/{arch}/` (static `.a`) |
| Python | `python/uacryptex/native/lib/.../shared/` |
| PHP | `php/native/lib/.../shared/` |
| Node.js | `nodejs/native/lib/.../shared/` |

Перевизначення: `UACRYPTEX_LIB=/path/to/libuacryptex_ffi.so`

Після змін FFI: `./scripts/sync-header.sh` (Go header; інші мови — `include/uacryptex.h`).

## Публічний API (паритет)

| Операція | Go | Python | PHP | Node.js |
|----------|-----|--------|-----|---------|
| Версія | `LibraryVersion()` | `library_version()` | `Uacryptex::libraryVersion()` | `libraryVersion()` |
| Ключ + cert | `OpenPrivateKey` | `open_private_key` | `openPrivateKey` | `openPrivateKey` |
| PKCS#12 | `OpenPKCS12` | `open_pkcs12` | `openPkcs12` | `openPkcs12` |
| Підпис digest | `PrivateKey.SignHash` | `sign_hash` | `signHash` | `signHash` |
| CMS sign | `SignCMS` | `sign_cms` | `signCms` | `signCms` |
| CMS CAdES-T | `SignCmsCadesT` | `sign_cms_cades_t` | `signCmsCadesT` | `signCmsCadesT` |
| CMS CAdES-C | `SignCmsCadesC` | `sign_cms_cades_c` | `signCmsCadesC` | `signCmsCadesC` |
| CMS CAdES-X | `SignCmsCadesX` | `sign_cms_cades_x` | `signCmsCadesX` | `signCmsCadesX` |
| CMS CAdES-LT | `SignCmsCadesLT` | `sign_cms_cades_lt` | `signCmsCadesLt` | `signCmsCadesLt` |
| CMS CAdES-X-L Type 1 | `SignCmsCadesXLType1` | — | — | — |
| CMS CAdES-X-L Type 2 | `SignCmsCadesXLType2` | — | — | — |
| CMS CAdES-A | `SignCmsCadesA` | `sign_cms_cades_a` | `signCmsCadesA` | `signCmsCadesA` |
| CMS verify | `VerifyCMS` | `verify_cms` | `verifyCms` | `verifyCms` |
| Envelop | `EnvelopCMS` | `envelop_cms` | `envelopCms` | `envelopCms` |
| Envelop (cipher) | `EnvelopCMSWithCipher` | — | — | — |
| Decrypt envelop | `DecryptCMS` | `decrypt_cms` | `decryptCms` | `decryptCms` |
| Digest | `Digest` | `digest` | `digest` | `digest` |
| Підпис data | `SignData` | `sign_data` | `signData` | `signData` |
| PKCS#8 | `OpenPKCS8` | `open_pkcs8` | `openPkcs8` | `openPkcs8` |
| Verify hash/data | `VerifyHash` / `VerifyData` | `verify_*` | same | same |
| Cert / CRL | `VerifyCertificate` … | `verify_certificate` … | same | same |
| CRL issue / OCSP signed | `GenerateCRL` / `OcspRequestGenerate` | `generate_crl` / `ocsp_request_generate` | same | same |
| DSTU4145 PB | `VerifyDstu4145PB` | `verify_dstu4145_pb` | same | same |

Повна таблиця FFI: [API_INVENTORY.md](../API_INVENTORY.md).

Handles потрібно закривати (`Close()` / `close()`). Вихідні буфери FFI копіюються і одразу звільняються.

## Тести

```bash
make go-test
make python-test
make php-test      # PHP 8.1+, ffi.enable=1
make node-test
```

Див. [FFI.md](FFI.md), [ARCHITECTURE.md](ARCHITECTURE.md).
