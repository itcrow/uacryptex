# Publishing uacryptex to package registries

> **Languages:** English · [Українська](uk/PUBLISHING.md)

Release strategy for Rust, Go, Python, PHP, Node.js, and GitHub Releases (native FFI).

## Version source

| Field | File |
|-------|------|
| **Source of truth** | `Cargo.toml` → `[workspace.package] version` |
| Go | `go/uacryptex/doc.go` → `const Version` |
| Python | `python/pyproject.toml`, `uacryptex/__init__.py` |
| PHP | `php/src/Uacryptex.php` → `VERSION` |
| Node.js | `nodejs/package.json` |
| Git tag | `v{semver}` (e.g. `v0.1.0`) |

Before release:

```bash
./scripts/sync-version.sh
./scripts/verify-version.sh
./scripts/prepare-release.sh   # sync + test + build host libs
git tag v0.1.0 && git push origin v0.1.0
```

Semver rules: [SEMVER.md](SEMVER.md).

---

## Channel overview

| Channel | Artifact | Native FFI | CI |
|---------|----------|------------|-----|
| **GitHub Releases** | `uacryptex-native-{v}-{os}-{arch}.tar.gz` | static + shared | `release.yml` ✅ |
| **Go module** | `go get github.com/itcrow/uacryptex/uacryptex@vX.Y.Z` | `go/native/lib/` in checkout | tag* |
| **crates.io** | `uacryptex-core`, `uacryptex-ffi` | — (Rust only) | planned |
| **PyPI** | `pip install uacryptex` | per-platform wheel | planned |
| **npm** | `npm install @itcrow/uacryptex` | `nodejs/native/lib/` | planned |
| **Packagist** | `composer require itcrow/uacryptex` | `php/native/lib/` | webhook + tag |

\* See [Native libraries in git](#native-libraries-in-git).

---

## GitHub Releases (native FFI)

**Implemented:** push tag `v*` → 5-platform matrix → tarballs on Release.

```bash
./scripts/package-native-lib.sh 0.1.0 linux amd64
# → dist/uacryptex-native-0.1.0-linux-amd64.tar.gz
```

Tarball contains `libuacryptex_ffi.a` / `.lib` and `shared/libuacryptex_ffi.so` (or `.dylib` / `.dll`).

Without Rust toolchain:

```bash
./scripts/fetch-native-lib.sh 0.1.0
./scripts/sync-native-libs.sh   # optional in monorepo checkout
```

---

## Go (`github.com/itcrow/uacryptex`)

| Parameter | Value |
|-----------|-------|
| Module path | `github.com/itcrow/uacryptex` |
| Import | `github.com/itcrow/uacryptex/uacryptex` |
| Native link | `go/native/lib/{GOOS}/{GOARCH}/` (static `.a`) |
| CGO | required |

**Publish:** git tag `vX.Y.Z` on `main`; `proxy.golang.org` picks up the module.

**Limitation:** `.gitignore` excludes binaries. Options without local build:

1. **Recommended (v0.x):** after `go get` run `./scripts/fetch-native-lib.sh` + `./scripts/sync-native-libs.sh`.
2. **Release branch:** `release/v0.1.0` with force-added `go/native/lib/**`.
3. **Future:** separate Go modules with `embed` (v1+).

---

## Rust (crates.io)

| Crate | Publish | Notes |
|-------|---------|-------|
| `uacryptex-core` | ✅ yes | core logic |
| `uacryptex-ffi` | 🟡 optional | C ABI; usually via GitHub tarballs |
| `uacryptex-cli` | 🟡 optional | dev tool |

```bash
cargo publish -p uacryptex-core --dry-run
# requires CRATES_IO_TOKEN
```

Default features exclude `legacy-gost3410` and `ct-scalar-mul` — document in crate README.

---

## Python (PyPI)

| Parameter | Value |
|-----------|-------|
| Package name | `uacryptex` |
| Root | `python/` |
| Native | `uacryptex/native/lib/{os}/{arch}/shared/` |

One wheel **per platform** (do not mix OS `.so` files in one wheel).

```bash
./scripts/build-python-wheel.sh linux amd64
python -m build --sdist --outdir dist
twine upload dist/uacryptex-*
```

Dependencies: stdlib + ctypes; `requires-python >= 3.9`.

---

## Node.js (npm)

| Parameter | Value |
|-----------|-------|
| Scope | `@itcrow/uacryptex` |
| Root | `nodejs/` |
| Native | all platforms in one package |

After CI merge: `./scripts/sync-native-libs.sh` → `cd nodejs && npm publish --access public`.

Requires `NPM_TOKEN`. Runtime: Node ≥ 18, `koffi`.

---

## PHP (Packagist)

| Parameter | Value |
|-----------|-------|
| Package | `itcrow/uacryptex` |
| Root | root `composer.json` → `php/src/` |
| Native | `php/native/lib/.../shared/` |
| PHP | ≥ 8.1, `ext-ffi` |

Connect GitHub repo on [packagist.org](https://packagist.org); auto-update on tag `v*`.

---

## Native libraries in git

| Approach | Pros | Cons |
|----------|------|------|
| **Do not commit** (current) | clean git | `go get` / Composer need fetch/build |
| **GitHub Releases only** | reproducible tarballs | extra user step |
| **Release tag with binaries** | `go get` works immediately | large tags |
| **Git LFS** | versioned binaries | complex CI, quotas |

**v0.1 recommendation:** GitHub Releases + document `fetch-native-lib.sh` in each binding quick start.

---

## CI secrets

| Secret | Registry |
|--------|----------|
| `CRATES_IO_TOKEN` | crates.io |
| `PYPI_API_TOKEN` | PyPI |
| `NPM_TOKEN` | npm |
| Packagist | GitHub OAuth (no repo secret) |
| Go | none (`proxy.golang.org`) |

---

## Release checklist `vX.Y.Z`

1. [ ] Bump `[workspace.package] version` in `Cargo.toml`
2. [ ] `./scripts/sync-version.sh && ./scripts/verify-version.sh`
3. [ ] `cargo test --workspace`, `make mvp`
4. [ ] CHANGELOG / release notes
5. [ ] `git tag vX.Y.Z`, `git push --tags`
6. [ ] Verify GitHub Release artifacts
7. [ ] PyPI / npm / crates.io (when jobs enabled)
8. [ ] Update [CERTIFICATION.md](CERTIFICATION.md) frozen matrix for tag

See also: [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md), [BINDINGS.md](BINDINGS.md), [SEMVER.md](SEMVER.md).
