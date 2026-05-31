# Reproducible build environment

Instructions for building auditable uacryptex release artefacts (Rust core, FFI static library, Go binding). Intended for ДССЗЗІ submission packages and internal release engineering.

## Pinned toolchain

| Component | Version / source |
|-----------|------------------|
| Rust | `1.85+` (`rust-version` in workspace `Cargo.toml`; `rust-toolchain.toml` → stable) |
| Cargo lockfile | `Cargo.lock` at repository root (commit with release tag) |
| Go | `1.22` (see `.github/workflows/go.yml`) |
| cbindgen | Pulled by `uacryptex-ffi/build.rs` at build time |

Install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup component add rustfmt clippy
```

Cross-compilation targets (release matrix):

```bash
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add aarch64-apple-darwin
rustup target add x86_64-pc-windows-msvc
# Linux arm64 cross-linker (Debian/Fedora):
# sudo dnf install gcc-aarch64-linux-gnu   # or gcc-aarch64-linux-gnu on Ubuntu
```

## Clean checkout

```bash
git clone https://github.com/itcrow/uacryptex.git
cd uacryptex
git checkout v0.1.0   # replace with release tag
```

Record source identity:

```bash
git rev-parse HEAD
git describe --tags --always
```

## Build steps (release artefact)

### 1. Rust workspace — tests

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### 2. FFI static library

```bash
./scripts/build-ffi.sh linux amd64
# Outputs: native/lib/linux/amd64/libuacryptex_ffi.a
```

Other platforms:

```bash
./scripts/build-ffi.sh linux arm64
./scripts/build-ffi.sh darwin arm64
./scripts/build-ffi.sh windows amd64   # → uacryptex_ffi.lib
```

### 3. Release tarball (same as CI)

```bash
VERSION=0.1.0
./scripts/package-native-lib.sh "$VERSION" linux amd64
# → dist/uacryptex-native-${VERSION}-linux-amd64.tar.gz
```

### 4. C header sync

```bash
./scripts/sync-header.sh
# Updates include/uacryptex.h and go/uacryptex/internal/native/uacryptex.h
diff -q include/uacryptex.h go/uacryptex/internal/native/uacryptex.h
```

### 5. Go binding

```bash
make go-test
# or:
./scripts/build-ffi.sh
cd go && CGO_ENABLED=1 go test ./...
```

## Integrity records

For each release, archive:

```bash
sha256sum Cargo.lock
sha256sum dist/uacryptex-native-*.tar.gz
sha256sum native/lib/linux/amd64/libuacryptex_ffi.a
git log -1 --format='%H %ci %s'
```

Store hashes in GitHub Release notes alongside uploaded `uacryptex-native-*` assets.

## CI parity

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/rust.yml` | fmt, clippy, `cargo test --workspace` |
| `.github/workflows/build-ffi.yml` | native lib matrix |
| `.github/workflows/go.yml` | build-ffi + `go test` |
| `.github/workflows/release.yml` | tag `v*` → packaged native libs |
| `.github/workflows/miri.yml` | optional UB check (nightly) |

Reproduce CI locally:

```bash
make test
make build-ffi
make go-test
```

## Environment variables

| Variable | Effect |
|----------|--------|
| `CGO_ENABLED=1` | Required for Go tests |
| `UACRYPTEX_VERSION` | Override for `scripts/fetch-native-lib.sh` |
| `UACRYPTEX_GITHUB_REPO` | Default `itcrow/uacryptex` |

## Submission checklist (ДССЗЗІ draft)

- [ ] Tag `vX.Y.Z` on main with matching `Cargo.toml` / Go `Version`
- [ ] `Cargo.lock` committed
- [ ] Full test log attached (`cargo test --workspace 2>&1 | tee test.log`)
- [ ] `pki_example` integration pass
- [ ] Native lib SHA-256 for each target platform
- [ ] [CERTIFICATION.md](CERTIFICATION.md) snapshot at tag
- [ ] [SECURITY.md](SECURITY.md) snapshot at tag
- [ ] Source archive: `git archive -o uacryptex-X.Y.Z.tar.gz vX.Y.Z`

## Limitations

- **cbindgen** version is not pinned in `Cargo.toml`; record `cargo tree -p uacryptex-ffi -i cbindgen` in release notes for strict reproducibility.
- **Cross-build** on Linux for `aarch64-unknown-linux-gnu` requires the same linker package as CI.
- Windows artefacts require building on Windows or a matching cross toolchain; CI uses `windows-latest`.
