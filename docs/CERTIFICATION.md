# Certification compliance matrix

> **Languages:** English · [Українська](uk/CERTIFICATION.md)

This document maps Cryptonite certified functionality to the uacryptex port. It supports **re-expertise preparation** for ДССЗЗІ / stakeholder review — **uacryptex is not a certified product** until an accredited evaluation is completed on a frozen release.

**Reference baseline:** Cryptonite (C library, IIT test vectors).  
**Evidence oracle:** `../cryptonite/src/cryptoniteAtest`, `pkixUtest`, `storageUtest`, `pkiExample`.

## Status legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Ported; KAT or integration test passes |
| 🟡 | Partial port or subset of Cryptonite API |
| ⏳ | Planned / not started |
| ❌ | Out of scope or not applicable |

## Cryptographic primitives

| Requirement | Standard | Cryptonite | uacryptex | Evidence |
|-------------|----------|------------|-----------|----------|
| DSTU 4145 sign | DSTU 4145-2002 | ✅ certified | ✅ port | `primitives/dstu4145/`; `tests/dstu4145_kat.rs`; `sign.rs` unit tests (M257 PB/ONB) |
| DSTU 4145 verify | DSTU 4145-2002 | ✅ certified | ✅ port | `verify_pn_kat_matches_cryptonite`; FFI `uacryptex_dstu4145_verify_pb` |
| DSTU 4145 keygen / DH | DSTU 4145-2002 | ✅ certified | ✅ port | `generate_private_key`, `dstu4145_dh`; curve params M163…M431 |
| Kupyna (DSTU 7564) | DSTU 7564:2014 | ✅ certified | ✅ port | `primitives/dstu7564/`; `tests/dstu7564_kat.rs` |
| Kalyna (DSTU 7624) | DSTU 7624:2014 | ✅ certified | ✅ port | `tests/dstu7624_kat.rs` |
| GOST 28147-89 (Magma) | GOST 28147-89 | ✅ certified | ✅ port | `tests/gost_kat.rs` |
| GOST 34.311 PRNG | GOST 34.311-95 | ✅ certified | ✅ port | `gost_kat.rs`; `MasterPrng` in adapters |
| GOST R 34.10-94 sign/verify | legacy GOST | ✅ certified | 🟡 legacy | `primitives/gost3410/`; `--features legacy-gost3410`; `tests/gost3410_kat.rs` + `tests/gost3410_compress_kat.rs` (params ID 1 and 2). **Deprecated** — not for new UA PKI |
| AES / SHA / RSA / ECDSA | international | ✅ certified | ✅ port | `primitives/intl/`; `tests/intl_kat/` (30 tests) |
| Constant-time EC math | side-channel | evaluated in C | 🟡 optional | `--features ct-scalar-mul`; see [SECURITY.md](SECURITY.md), [CT_REVIEW.md](CT_REVIEW.md) |

## PKI and protocols

| Requirement | Cryptonite | uacryptex | Evidence |
|-------------|------------|-----------|----------|
| X.509 certificate parse/verify | ✅ | ✅ | `pki/cert/`; `tests/cert_kat.rs` |
| DSTU extensions (QC, SKI, …) | ✅ | 🟡 | `pki/ext/`; `tests/ext_kat.rs` (24 tests); some attrs deferred |
| Digest / sign / verify adapters | ✅ | ✅ | `pki/crypto/`; `tests/adapter_kat.rs` |
| CMS SignedData (CAdES-BES subset) | ✅ | ✅ | `pki/cms/`; `tests/cms_kat.rs`; Go `SignCMS`/`VerifyCMS` |
| CRL verify | ✅ | ✅ | `pki/crl.rs`; `tests/crl_kat.rs` |
| OCSP request/response | ✅ | ✅ | `pki/ocsp/` + engines; `ocsp_*_kat.rs` |
| TSP request/response | ✅ | ✅ | `pki/tsp/` + engines; `tsp_*_kat.rs` |
| Certificate request (CSR) | ✅ | 🟡 | `pki/creq/`; PKCS#12 ECDSA CSR in `pkcs12_ecdsa_kat.rs` |
| Enveloped / encrypted data | ✅ | ✅ | `pki/cms/enveloped_data.rs`; `tests/enveloped_data_kat.rs` |
| Cert issuance engines | ✅ | ✅ | `pki/engine/cert.rs`, `crl.rs`; KAT `cert_engine_kat`, `crl_engine_kat` |

## Storage

| Requirement | Cryptonite | uacryptex | Evidence |
|-------------|------------|-----------|----------|
| PKCS#12 decode/encode (DSTU) | ✅ | ✅ | `storage/pkcs12/`; `tests/pkcs12_kat.rs` |
| PKCS#12 ECDSA (OpenSSL interop) | ✅ | ✅ | `tests/pkcs12_ecdsa_kat.rs` |
| PKCS#8 private keys | ✅ | ✅ | `storage/pkcs8.rs` (DSTU, ECDSA; GOST3410 with `legacy-gost3410`) |
| External cert attach | ✅ | ✅ | `pkcs12_set_certificates`; Go `Keystore.SetCertificate` |

## Integration scenarios

| Scenario | Cryptonite | uacryptex | Evidence |
|----------|------------|-----------|----------|
| `pkiExample` main path (M257 PB) | ✅ | ✅ | `tests/pki_example.rs` |
| MVP vertical slice | demo | ✅ | `cargo test --test pki_example`; Go `TestMVP` |
| Go CMS + PKCS#12 | — | ✅ | `go/uacryptex/cms_test.go`, `pkcs12_test.go`, `enveloped_test.go`, `mvp_test.go` |
| Python / PHP / Node.js CMS + PKCS#12 | — | 🟡 | `python/`, `php/`, `nodejs/` — version + CMS/PKCS#12 surface over same FFI |
| C FFI (Phase 0–2) | N/A | ✅ | `uacryptex-ffi`; `tests/ffi_pki.rs`; [FFI.md](FFI.md) |

## Hardening (pre-certification engineering)

| Activity | uacryptex | Evidence |
|----------|-----------|----------|
| libFuzzer (CMS, PKCS#12, cert) | ✅ | `fuzz/`; [SECURITY.md](SECURITY.md) |
| Miri (UB) | ✅ | `.github/workflows/miri.yml` |
| Benchmarks | ✅ | `benches/crypto.rs` |
| Side-channel audit | 🟡 documented | [SECURITY.md](SECURITY.md) |

## Known gaps for formal certification

1. **No accredited evaluation** of uacryptex itself — only functional parity evidence vs Cryptonite KATs.
2. **Constant-time** private-key operations: optional `ct-scalar-mul` feature; external timing review still required ([CT_REVIEW.md](CT_REVIEW.md)).
3. **Full API surface** — ~1039 Cryptonite symbols in [API_INVENTORY.md](API_INVENTORY.md); many PKI helpers still Phase 2/TBD.
4. **Legacy GOST 34.10-94** — optional `--features legacy-gost3410` (off by default); params ID 1 and 2 KAT (`gost3410_kat`, `gost3410_compress_kat`); deprecated for new deployments (see [SECURITY.md](SECURITY.md)).
5. **Reproducible build** process documented in [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md); artifact hashes must be recorded per release tag.

## Recommended submission bundle (draft)

For ДССЗЗІ re-expertise, prepare per release tag `vX.Y.Z`:

| Artefact | Path / command |
|----------|----------------|
| Source tarball | Git tag `vX.Y.Z` |
| `Cargo.lock` | repository root |
| Test log | `cargo test --workspace` (full) |
| KAT summary | `cargo test -p uacryptex-core --tests` |
| Integration | `cargo test --test pki_example` |
| Native libs | GitHub Release `uacryptex-native-X.Y.Z-*.tar.gz` |
| Build recipe | [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md) |
| This matrix | `docs/CERTIFICATION.md` (frozen with tag) |
| Security notes | `docs/SECURITY.md` |

## Maintenance

Update this matrix when:

- A new KAT suite passes or a gap is closed
- FFI or Go API reaches parity with a Cryptonite module
- Security audit findings change
