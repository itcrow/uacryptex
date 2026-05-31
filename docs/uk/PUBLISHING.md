# Публікація uacryptex у реєстрах пакетів

> **Мови:** [English](../PUBLISHING.md) · Українська

Стратегія релізів для Rust, Go, Python, PHP, Node.js і GitHub Releases (native FFI).

## Джерело версії

| Поле | Файл |
|------|------|
| **Source of truth** | `Cargo.toml` → `[workspace.package] version` |
| Go | `go/uacryptex/doc.go` → `const Version` |
| Python | `python/pyproject.toml`, `uacryptex/__init__.py` |
| PHP | `php/src/Uacryptex.php` → `VERSION` |
| Node.js | `nodejs/package.json` |
| Git tag | `v{semver}` (наприклад `v0.1.0`) |

Синхронізація перед релізом:

```bash
./scripts/sync-version.sh
./scripts/verify-version.sh
./scripts/prepare-release.sh   # sync + test + build host libs
git tag v0.1.0 && git push origin v0.1.0
```

Детальні правила semver: [SEMVER.md](SEMVER.md).

---

## Огляд каналів

| Канал | Артефакт | Native FFI | CI job |
|-------|----------|------------|--------|
| **GitHub Releases** | `uacryptex-native-{v}-{os}-{arch}.tar.gz` | static + shared | `release.yml` ✅ |
| **Go module** | `go get github.com/itcrow/uacryptex/uacryptex@vX.Y.Z` | `go/native/lib/` у checkout | tag + embedded libs* |
| **crates.io** | `uacryptex-core`, `uacryptex-ffi` | — (Rust only) | `release.yml` (planned) |
| **PyPI** | `pip install uacryptex` | wheel per platform | `release.yml` (planned) |
| **npm** | `npm install @itcrow/uacryptex` | `nodejs/native/lib/` | `release.yml` (planned) |
| **Packagist** | `composer require itcrow/uacryptex` | `php/native/lib/` | webhook + tag |

\* Див. [Native libraries у git](#native-libraries-у-git).

---

## GitHub Releases (native FFI)

**Вже реалізовано:** push тега `v*` → matrix 5 платформ → tarballs на Release.

```bash
./scripts/package-native-lib.sh 0.1.0 linux amd64
# → dist/uacryptex-native-0.1.0-linux-amd64.tar.gz
```

Tarball містить `libuacryptex_ffi.a` / `.lib` і `shared/libuacryptex_ffi.so` (або `.dylib` / `.dll`).

Споживач без Rust:

```bash
./scripts/fetch-native-lib.sh 0.1.0
./scripts/sync-native-libs.sh   # опційно, якщо клонували monorepo
```

---

## Go (`github.com/itcrow/uacryptex`)

| Параметр | Значення |
|----------|----------|
| Module path | `github.com/itcrow/uacryptex` |
| Import | `github.com/itcrow/uacryptex/uacryptex` |
| Native link | `go/native/lib/{GOOS}/{GOARCH}/` (static `.a`) |
| CGO | обов'язково |

**Публікація:** достатньо git tag `vX.Y.Z` на `main`. Proxy `proxy.golang.org` підхоплює модуль автоматично.

**Обмеження:** `.gitignore` не комітить бінарники. Варіанти для `go get` без локальної збірки:

1. **Рекомендовано (v0.x):** після `go get` — `./scripts/fetch-native-lib.sh` + `./scripts/sync-native-libs.sh` (або `make build-client-libs`).
2. **Release branch:** гілка `release/v0.1.0` з force-added `go/native/lib/**` (лише для тегів; не в `main`).
3. **Майбутнє:** окремі Go-модулі `@itcrow/uacryptex-native-linux-amd64` з embed (v1+).

---

## Rust (crates.io)

| Crate | Публікувати | Примітка |
|-------|-------------|----------|
| `uacryptex-core` | ✅ так | основна логіка |
| `uacryptex-ffi` | 🟡 опційно | C ABI; зазвичай через GitHub native tarballs |
| `uacryptex-cli` | 🟡 опційно | dev tool |

```bash
cargo publish -p uacryptex-core --dry-run
# потрібен API token crates.io у CRATES_IO_TOKEN
```

Features за замовчуванням **без** `legacy-gost3410` / `ct-scalar-mul` — документувати в README crate.

---

## Python (PyPI)

| Параметр | Значення |
|----------|----------|
| Package name | `uacryptex` |
| Root | `python/` |
| Native | `uacryptex/native/lib/{os}/{arch}/shared/` |

**Стратегія wheel:** один wheel **на платформу** (не змішувати `.so` різних OS у одному wheel).

```bash
./scripts/build-python-wheel.sh linux amd64
python -m build --sdist --outdir dist
twine upload dist/uacryptex-*
```

CI (planned): matrix ×5 → PyPI (`PYPI_API_TOKEN`).

---

## Node.js (npm)

| Параметр | Значення |
|----------|----------|
| Scope | `@itcrow/uacryptex` |
| Root | `nodejs/` |
| Native | `native/lib/**` (усі платформи в одному пакеті) |

Після merge CI artifacts: `./scripts/sync-native-libs.sh` → `cd nodejs && npm publish --access public`.

Потрібен `NPM_TOKEN`. Runtime: Node ≥ 18, dependency `koffi`.

---

## PHP (Packagist)

| Параметр | Значення |
|----------|----------|
| Package | `itcrow/uacryptex` |
| Root | root `composer.json` → `php/src/` |
| Native | `php/native/lib/.../shared/` |
| PHP | ≥ 8.1, `ext-ffi` |

Підключити GitHub repo на [packagist.org](https://packagist.org), auto-update по tag `v*`.

---

## Native libraries у git

| Підхід | Плюси | Мінуси |
|--------|-------|--------|
| **Не комітити** (зараз) | чистий git | `go get` / Packagist потребують fetch/build |
| **GitHub Releases only** | reproducible tarballs | додатковий крок |
| **Release tag з бінарниками** | `go get` одразу | великі tags |
| **Git LFS** | версіоновані бінарники | складніший CI |

**Рекомендація v0.1:** GitHub Releases + `fetch-native-lib.sh` у Quick start кожного binding.

---

## Checklist релізу `vX.Y.Z`

1. [ ] Bump version у `Cargo.toml`
2. [ ] `./scripts/sync-version.sh && ./scripts/verify-version.sh`
3. [ ] `cargo test --workspace`, `make mvp`
4. [ ] CHANGELOG / release notes
5. [ ] `git tag vX.Y.Z`, `git push --tags`
6. [ ] Перевірити GitHub Release
7. [ ] PyPI / npm / crates.io (коли jobs увімкнені)
8. [ ] Оновити [CERTIFICATION.md](CERTIFICATION.md) для tag

Див. також: [REPRODUCIBLE_BUILD.md](../REPRODUCIBLE_BUILD.md), [BINDINGS.md](BINDINGS.md), [SEMVER.md](SEMVER.md).
