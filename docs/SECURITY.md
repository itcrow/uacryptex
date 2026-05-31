# Security notes

> **Languages:** English · [Українська](uk/SECURITY.md)

This document records hardening findings for uacryptex. It is not a formal certification artefact.

## Constant-time audit (Phase 5.4)

**Scope:** DSTU 4145 field/curve arithmetic in `crates/uacryptex-core/src/math/gf2m.rs` and `ec2m.rs`, used by signing and verification.

**Method:** Manual review of the Cryptonite C port. No automated timing analysis or side-channel lab testing has been performed yet.

### Findings

| Area | Location | Status | Notes |
|------|----------|--------|-------|
| Scalar multiplication | `ec2m_mul` | CT optional (`ct-scalar-mul`) | Default: legacy branch-on-bit double-and-add. Feature: fixed `m`-bit loop + cmov conditional add |
| Dual scalar multiplication | `ec2m_dual_mul` | CT optional (`ct-scalar-mul`) | Same as `ec2m_mul` when feature enabled |
| Field multiplication | `gf2m_mod_mul` | Not audited as CT | Word-array loops; inherits Cryptonite structure |
| Signature comparison | `int_equals` | Constant-time | `int_ct_equals` XORs all words without early exit; `int_cmp` still not CT |
| Rust `unsafe` | workspace | Forbidden | `#![forbid(unsafe_code)]` in `uacryptex-core` |

Enable CT scalar mul at build time: `cargo build -p uacryptex-core --features ct-scalar-mul`.

uacryptex does **not** use the `subtle` crate; CT helpers are hand-rolled (`wa_cmov_u32`, `int_ct_equals`).

### Implications

- **Remote attackers** verifying or parsing CMS/PKCS#12/ASN.1 are not directly exposed to scalar-multiplication timing through these code paths alone.
- **Local side-channel** against **private-key signing** is mitigated only when built with `--features ct-scalar-mul` (scalar loop); field multiply (`gf2m_mod_mul`) and default (legacy) builds remain vulnerable on shared hardware.
- For ДССЗЗІ / certified deployment: enable `ct-scalar-mul` for software keys, complete external review per [CT_REVIEW.md](CT_REVIEW.md), and prefer HSM for high-assurance settings.

### Recommendations

1. Document deployment threat model (HSM vs software key on shared host).
2. Prefer hardware security modules for private keys in high-assurance settings.
3. For software-only deployment on shared hosts: build with `ct-scalar-mul` (`uacryptex-ffi` feature forwards to core).
4. Re-run the [CT_REVIEW.md](CT_REVIEW.md) checklist after any change to `math/gf2m.rs` or `math/ec2m.rs`.

## Legacy GOST R 34.10-94 (`legacy-gost3410`)

**Status:** Deprecated. **Off by default.** Do not use for new Ukrainian PKI — use DSTU 4145.

| Item | Detail |
|------|--------|
| Enable | `cargo build -p uacryptex-core --features legacy-gost3410` |
| Code | `crates/uacryptex-core/src/primitives/gost3410/`, `math/gfp.rs`, `math/ecp.rs`, `math/int_arith.rs` |
| Use case | Old certificates and Kazakhstan variant (`OID_GOST3410_KZ`) interop only |
| Coverage | Params sets ID 1 and 2 KAT-tested (`get_pubkey`, sign/verify, compress/decompress); sets 3–5 constants only |
| Tests | `cargo test -p uacryptex-core --features legacy-gost3410 --test gost3410_kat --test gost3410_compress_kat` |
| CT audit | **Not audited** — GF(p) scalar mul uses branch-on-bit loops like Cryptonite C |
| Certification | Optional legacy module; not on the default certified path — see [CERTIFICATION.md](CERTIFICATION.md) |

Params ID selection and PKCS#8 algorithm parameters are not fully parsed yet (defaults to params set 1). Treat as compatibility shim, not a greenfield signing API.

## Fuzzing

libFuzzer targets live under `fuzz/`:

| Target | Entry point |
|--------|-------------|
| `cms_decode` | `SignedDataContainer::decode` |
| `pkcs12_decode` | `pkcs12_decode` |
| `cert_decode` | `Cert::decode` |

Run: `./scripts/fuzz.sh [target]` (requires `cargo install cargo-fuzz` and nightly Rust).

## Miri

Run undefined-behaviour checks on the core crate:

```bash
rustup +nightly component add miri
cargo +nightly miri test -p uacryptex-core
```

CI: `.github/workflows/miri.yml` (scheduled + manual).

## Reporting vulnerabilities

Report security issues privately to repository maintainers before public disclosure.
