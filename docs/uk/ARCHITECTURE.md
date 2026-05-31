# uacryptex — архітектура

> **Мови:** [English](../ARCHITECTURE.md) · Українська

## Цілі

1. **Pure Rust core** — безпечна реалізація українських криптостандартів і PKI.
2. **Мовні binding-и** — Go, Python, PHP, Node.js.
3. **Стабільний C ABI** — `uacryptex-ffi` для всіх binding-ів.
4. **Крос-платформеність** — CI matrix (linux/darwin/windows × amd64/arm64).

Cryptonite C у `../cryptonite/` — **KAT oracle** під час міграції, не runtime-залежність.

## Шари

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

Діаграма Mermaid — у [англійській версії](../ARCHITECTURE.md).

## Crates

### `uacryptex-core`

Вся бізнес-логіка: `primitives/` (DSTU, GOST, intl), `pki/`, `storage/`.

### `uacryptex-ffi`

Тонкий C ABI: marshalling, `UacryptexBuf`, `UacryptexError`, handles.

### Binding-и

| Мова | Шлях | FFI |
|------|------|-----|
| Go | `go/uacryptex/` | cgo |
| Python | `python/uacryptex/` | ctypes |
| PHP | `php/src/` | ext-ffi |
| Node.js | `nodejs/lib/` | koffi |

## Пам'ять (FFI)

| Напрям | Правило |
|--------|---------|
| Rust → client | `UacryptexBuf`; client викликає `uacryptex_buf_free` |
| Client → Rust | borrowed slices на час виклику |
| Handles | `uacryptex_handle_free` |

## Збірка

```bash
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh
```

| Артефакт | Споживачі |
|----------|-----------|
| `.a` / `.lib` | Go cgo |
| `.so` / `.dylib` / `.dll` у `shared/` | Python, PHP, Node.js |

## Сертифікація

Заміна Cryptonite C на Rust потребує нового циклу державної експертизи (ДССЗЗІ). Див. [CERTIFICATION.md](CERTIFICATION.md).
