# Roadmap uacryptex

> **Мови:** [English](../ROADMAP.md) · Українська

Високорівневий timeline. Міграція з Cryptonite C (~146K LOC) на pure Rust core + мовні binding-и.

**Покриття:** [CRYPTONITE_PARITY.md](CRYPTONITE_PARITY.md) · [API_INVENTORY.md](../API_INVENTORY.md)

KAT oracle: `../cryptonite/src/cryptoniteAtest`, `*Utest`, `pkiExample`.

## Фаза 0 — Scaffold ✅

Monorepo, Cargo workspace, Go module, FFI version, API inventory.

## Фаза 1 — Rust primitives ✅

DSTU 4145, Kupyna, Kalyna, GOST, international (RustCrypto), KAT.

## Фаза 2 — PKI + storage ✅

X.509, CMS (BES + CAdES-T), OCSP, TSP, CRL, PKCS#12. **~39 символів C ABI** — [API_INVENTORY.md](../API_INVENTORY.md).

## Фаза 3 — Go + binding-и ✅

`OpenPKCS12`, `SignCMS`, `SignCmsCadesT`, OCSP/TSP/CSR, cert/CRL issue, `VerifyDstu4145PB`. Паритет: Go, Python, PHP, Node.js — [BINDINGS.md](BINDINGS.md).

## Фаза 4 — Distribution 🟡

GitHub Releases, semver sync, PyPI/npm/Packagist (planned).

## Фаза 5 — Hardening 🟡

Fuzz, Miri, benchmarks, CT review (`ct-scalar-mul`).

**Залишилось:** → [TODO](#todo).

## Фаза 6 — Certification prep ✅

[CERTIFICATION.md](CERTIFICATION.md), [REPRODUCIBLE_BUILD.md](../REPRODUCIBLE_BUILD.md), `make mvp`.

## MVP vertical slice ✅

```
DSTU4145 keygen → sign → CMS → verify → PKCS#12
```

## Оцінка

| Scope | Тривалість | FTE |
|-------|------------|-----|
| MVP | 4–5 міс | 2 |
| Повний паритет Cryptonite | 12–15 міс | 2–3 |

Детальний статус KAT — [CERTIFICATION.md](CERTIFICATION.md).

## TODO

- [x] **CAdES-X-L Type 1/2** — `uacryptex_cms_sign_cades_xl_type1` / `_type2`
