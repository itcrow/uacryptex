# Контракт FFI uacryptex

> **Мови:** [English](../FFI.md) · Українська

Стабільний C ABI між `uacryptex-ffi` (Rust) і мовними binding-ами.

**Повна специфікація (англійською):** [FFI.md](../FFI.md)

## Типи

```c
typedef struct { uint8_t *ptr; size_t len; } UacryptexBuf;
typedef struct { int32_t code; char message[256]; } UacryptexError;
typedef struct UacryptexHandle UacryptexHandle;
```

## Коди помилок

| Code | Значення |
|------|----------|
| 0 | OK |
| 1 | MEMORY |
| 2 | INVALID_PARAM |
| 3 | VERIFY_FAILED |

## Життєвий цикл

- `uacryptex_error_init` — ініціалізація помилки
- `uacryptex_buf_free` — звільнення вихідного буфера Rust
- `uacryptex_handle_free` — звільнення opaque handle

## Основні функції

| Функція | Призначення |
|---------|-------------|
| `uacryptex_version` | версія core |
| `uacryptex_dstu4145_verify_pb` | verify DSTU4145 (PB) |
| `uacryptex_pkcs12_open` | відкрити PKCS#12 |
| `uacryptex_sign_open` | ключ + cert → handle |
| `uacryptex_sign_hash` | підпис digest |
| `uacryptex_cms_sign` / `cms_verify` | CMS SignedData |
| `uacryptex_cms_envelop_encrypt` / `decrypt` | EnvelopedData |
| `uacryptex_digest` | GOST3411 / cert-selected hash |
| `uacryptex_sign_data` | підпис сирих даних |
| `uacryptex_verify_hash` / `verify_data` | detached verify |
| `uacryptex_pkcs8_open` | PKCS#8 → handle |
| `uacryptex_cert_*` | verify chain, validity, SPKI |
| `uacryptex_crl_*` | verify CRL, revocation, **issue CRL** |
| `uacryptex_pkcs12_certificate_*` | перелік cert у PKCS#12 |
| `uacryptex_ocsp_*` | OCSP request/response (**signed request**) |
| `uacryptex_tsp_*` | TSP request/response |
| `uacryptex_csr_*` | PKCS#10 CSR generate/verify |
| `uacryptex_cert_generate` | видача X.509 з CSR |
| `uacryptex_cms_sign_cades_t` | CMS CAdES-T |
| `uacryptex_cms_sign_cades_c` | CMS CAdES-C |
| `uacryptex_cms_sign_cades_x` | CMS CAdES-X |
| `uacryptex_cms_sign_cades_lt` | CMS CAdES-LT |
| `uacryptex_cms_sign_cades_a` | CMS CAdES-A |

**~43 entry points** — повна таблиця: [API_INVENTORY.md](../API_INVENTORY.md).

## Binding-и

| Мова | Шар |
|------|-----|
| Go | `go/uacryptex/internal/native` (cgo) |
| Python | `python/uacryptex/_native.py` (ctypes) |
| PHP | `php/src/Native.php` (FFI) |
| Node.js | `nodejs/lib/native.js` (koffi) |

Регенерація заголовка: `./scripts/sync-header.sh` → `include/uacryptex.h`.

Див. [BINDINGS.md](BINDINGS.md), [ARCHITECTURE.md](ARCHITECTURE.md).
