# uacryptex roadmap

> **Languages:** English · [Українська](uk/ROADMAP.md)

High-level timeline. Detailed step-by-step agent plan: see repository history / porting notes.

Migration from Cryptonite C (~146K LOC) to pure Rust core + multi-language bindings.

KAT oracle: `../cryptonite/src/cryptoniteAtest`, `cryptoniteUtest`, `pkixUtest`, `storageUtest`.

## Phase 0 — Scaffold (2–3 weeks)

- [x] Monorepo `uacryptex/*` layout
- [x] Cargo workspace (`uacryptex-core`, `uacryptex-ffi`)
- [x] Go module `github.com/itcrow/uacryptex`
- [x] FFI: `uacryptex_version`
- [x] API inventory: `docs/API_INVENTORY.md` (`scripts/generate-api-inventory.sh`)
- [x] CI: rust test + build-ffi matrix + go test (`.github/workflows/{rust,build-ffi,go}.yml`)

**Exit:** `go test` passes `TestVersion` on linux/amd64.

## Phase 1 — Rust primitives (2–3 months)

| Task | Source | Validation |
|------|--------|------------|
| **DSTU 4145 verify (PB m=163)** | `atest_dstu4145.c` | `tests/dstu4145_kat.rs` |
| Core errors, OID registry | new | unit |
| AES, SHA*, RSA, ECDSA | RustCrypto | `atest_*` |
| Kupyna (7564) | `kupyna` crate | `atest_dstu7564` |
| Kalyna (7624) | port `dstu7624.c` | `atest_dstu7624` |
| DSTU 4145 sign + curves | port `dstu4145*.c` | `utest_dstu4145` |
| GOST 28147 / 34.311 | `gost-crypto` | `atest_gost*` |

FFI: `uacryptex_dstu4145_verify`.

**Exit:** `verify_pn_kat_matches_cryptonite` passes without `--ignored`.

## Phase 2 — PKI + storage (2–3 months)

- `x509-cert`, `cms`, `x509-ocsp`, `pkcs12` + DSTU extensions
- Port engines: cert, signed_data, ocsp, tsp, crl (priority order)
- PKCS#12 DSTU MAC/PBE

FFI (MVP): `pkcs12_open`, `cms_sign`, `cms_verify`.

**Expanded FFI (2026):** ~43 entry points in `include/uacryptex.h` — digest/sign/verify, PKCS#8, cert/CRL/CSR, OCSP/TSP engines, CAdES-C/T/X/LT/A, enveloped CMS, CRL generation, `dstu4145_verify_pb`. Full table: [API_INVENTORY.md](API_INVENTORY.md). Bindings: Go, Python, PHP, Node.js.

**Exit:** `pkiExample` scenario runs in Rust integration test; `cargo test -p uacryptex-ffi --test ffi_pki` (17 tests).

## Phase 3 — Go public API (1–2 months, parallel with Phase 2)

- `OpenPKCS12`, `VerifyCMS`, `SignCMS`, `SignCmsCadesT`
- PKI helpers: OCSP/TSP/CSR, cert/CRL issue, `VerifyDstu4145PB`
- `PrivateKey` implements `crypto.Signer`
- Typed errors, examples, pkg.go.dev docs
- Python / PHP / Node.js parity (ctypes / FFI / koffi)

**Exit:** Go integration test against Cryptonite test vectors; `make go-test python-test node-test`.

## Phase 4 — Distribution (2–4 weeks)

- GitHub Releases: prebuilt `native/lib/*`
- Semver sync Rust ↔ Go
- `go install` / module publish

## Phase 5 — Hardening

- `cargo fuzz` on ASN.1/CMS parsers
- `cargo miri` on core
- Criterion benchmarks vs Cryptonite `ptest`
- Side-channel review on EC2M math

### PKI profiles (remaining)

→ see [TODO](#todo).

## Phase 6 — Certification prep

- [x] Compliance matrix — [CERTIFICATION.md](CERTIFICATION.md)
- [x] Reproducible build doc — [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md)
- [x] MVP demo — `make mvp`

## MVP vertical slice (target: month 4–5)

```
DSTU4145 keygen → sign digest → CMS SignedData → Go VerifyCMS → PKCS#12 read key
```

## Team estimate

| Scope | Duration | FTE |
|-------|----------|-----|
| MVP slice | 4–5 months | 2 |
| Full Cryptonite parity | 12–15 months | 2–3 |

## TODO

- [ ] **CAdES-X-L Type 1/2** — timestamps on certificate/revocation refs (Phase 5; planned in [FFI.md](FFI.md))
