# uacryptex

> **Languages:** English · [Українська](README.uk.md)

Ukrainian cryptographic library: **pure Rust core** with language bindings over a stable C ABI.

Inspired by [Cryptonite](https://github.com/privat-it/cryptonite) — DSTU/GOST algorithms, PKI (CMS, OCSP, TSP), and PKCS#12 keystores.

## Architecture

```
Application (Go / Python / PHP / Node.js)
    │  idiomatic API
    ▼
go/uacryptex/ | python/uacryptex/ | php/src/ | nodejs/lib/
    │  cgo | ctypes | FFI | koffi
    ▼
crates/uacryptex-ffi/  stable C ABI (cbindgen → uacryptex.h)
    │
    ▼
crates/uacryptex-core/ pure Rust (primitives, pki, storage)
```

Rust is the single source of truth. Go never calls legacy C Cryptonite.

## Repository layout

| Path | Role |
|------|------|
| `crates/uacryptex-core/` | Pure Rust crypto + PKI |
| `crates/uacryptex-ffi/` | `cdylib` / `staticlib`, C headers |
| `crates/uacryptex-cli/` | Dev CLI, KAT runner |
| `go/uacryptex/` | Public Go package (`github.com/itcrow/uacryptex/uacryptex`) |
| `go/uacryptex/internal/native/` | cgo + generated header |
| `python/uacryptex/` | Python package (ctypes) |
| `php/src/` | PHP 8.1+ bindings (FFI extension) |
| `nodejs/lib/` | Node.js 18+ bindings (koffi) |
| `native/lib/` | Canonical build output (CI merges all platforms here) |
| `go/native/lib/` | Go cgo static libs (synced from `native/lib/`) |
| `python/uacryptex/native/lib/` | Python wheel/sdist bundled shared libs |
| `php/native/lib/` | PHP package bundled shared libs |
| `nodejs/native/lib/` | npm package bundled shared libs |
| `fuzz/` | libFuzzer targets (CMS, PKCS#12, certificate decode) |
| `scripts/` | Build, header sync, release packaging, native lib fetch, fuzz runner |
| `docs/` | Architecture, FFI contract, roadmap |
| `testdata/` | KAT vectors (from Cryptonite tests) |

## Quick start (Go)

Requires **CGO** and a **prebuilt native library** for your platform (`linux`/`darwin`/`windows` × `amd64`/`arm64`).

```bash
# Clone (or use an existing checkout — native libs are not vendored in the module)
git clone https://github.com/itcrow/uacryptex.git
cd uacryptex

# Option A: build for host + embed into client packages
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh

# Option B: all platforms (CI/release matrix)
# ./scripts/build-ffi-all.sh && ./scripts/sync-native-libs.sh

# Option C: download release tarball for current platform
# ./scripts/fetch-native-lib.sh [version]

cd go
CGO_ENABLED=1 go test ./...
```

In your module:

```bash
go get github.com/itcrow/uacryptex/uacryptex
```

The Go package links against `go/native/lib/{GOOS}/{GOARCH}/` (synced from `native/lib/`). Run `./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh` or `./scripts/fetch-native-lib.sh` before building or testing.

**Full demo:** [go/README.md](go/README.md) · `cd go && CGO_ENABLED=1 go run ./examples/demo/`

## Quick start (Python)

Requires Python 3.9+ and a built shared library (`libuacryptex_ffi.so` / `.dylib` / `.dll`).

```bash
./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh
cd python && pip install -e . && python tests/test_version.py
```

```python
import uacryptex
print(uacryptex.library_version())
```

See [python/README.md](python/README.md). Override library path with `UACRYPTEX_LIB`.

## Quick start (PHP)

Requires PHP 8.1+ with **FFI** enabled (`ffi.enable=true` for CLI).

```bash
./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh
cd php && php -d ffi.enable=1 tests/VersionTest.php
```

See [php/README.md](php/README.md).

## Quick start (Node.js)

Requires Node.js 18+.

```bash
./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh
cd nodejs && npm install && npm test
```

See [nodejs/README.md](nodejs/README.md).

See [Semver policy](docs/SEMVER.md) and [FFI contract](docs/FFI.md).

## Hardening (developers)

```bash
# Benchmarks (DSTU4145, Kupyna, CMS verify)
cargo bench -p uacryptex-core

# Fuzz parsers (requires nightly + cargo-fuzz)
cargo install cargo-fuzz
./scripts/fuzz.sh cms_decode

# Miri (undefined behaviour)
rustup +nightly component add miri
cargo +nightly miri test -p uacryptex-core
```

See [Security notes](docs/SECURITY.md).

## Quick start (Rust)

```bash
cargo test --workspace
cargo build -p uacryptex-ffi --release

# Sync C header into Go binding
./scripts/sync-header.sh
```

## Supported algorithms (target)

| Algorithm | Standard | Core crate |
|-----------|----------|------------|
| DSTU 4145-2002 | Digital signature | `uacryptex-core::primitives::dstu4145` |
| DSTU 7564 | Kupyna hash | `kupyna` + wrapper |
| DSTU 7624 | Kalyna cipher | port |
| GOST 28147-89 | Magma | `gost-crypto` |
| GOST 34.10-94 / 34.11-94 | Legacy GOST | `gost3410` (`--features legacy-gost3410`; params 1–2 KAT; deprecated) / `gost-crypto` |
| AES, RSA, ECDSA, SHA* | International | RustCrypto |

## License

MIT — see [LICENSE](LICENSE).

## Documentation

Full index: [docs/README.md](docs/README.md) · [docs/uk/README.md](docs/uk/README.md) (Ukrainian)

| English | Ukrainian |
|---------|-----------|
| [Architecture](docs/ARCHITECTURE.md) | [Архітектура](docs/uk/ARCHITECTURE.md) |
| [Language bindings](docs/BINDINGS.md) | [Binding-и](docs/uk/BINDINGS.md) |
| [Client libraries guide](docs/CLIENT_LIBRARIES.md) | [Клієнтські бібліотеки](docs/uk/CLIENT_LIBRARIES.md) |
| [FFI contract](docs/FFI.md) | [FFI](docs/uk/FFI.md) |
| [Security](docs/SECURITY.md) | [Безпека](docs/uk/SECURITY.md) |
| [Publishing](docs/PUBLISHING.md) | [Публікація](docs/uk/PUBLISHING.md) |
| [Certification](docs/CERTIFICATION.md) | [Сертифікація](docs/uk/CERTIFICATION.md) |
| [Semver](docs/SEMVER.md) | [Semver (UK)](docs/uk/SEMVER.md) |
| [Roadmap](docs/ROADMAP.md) | [Roadmap (UK)](docs/uk/ROADMAP.md) |

Reference (English only): [API inventory](docs/API_INVENTORY.md), [Reproducible builds](docs/REPRODUCIBLE_BUILD.md), [Package map](docs/PACKAGE_MAP.md).
