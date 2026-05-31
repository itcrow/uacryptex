# Constant-time review checklist (Phase 7.3c)

This document supports **external security review** of DSTU 4145 side-channel hardening in uacryptex. It is not a substitute for accredited evaluation or lab timing analysis.

## Scope

| In scope | Out of scope (today) |
|----------|----------------------|
| `ec2m_mul` / `ec2m_dual_mul` with `--features ct-scalar-mul` | `gf2m_mod_mul` data-dependent loops |
| `int_equals` → `int_ct_equals` on signature compare | GOST 34.10-94 GF(p) (`legacy-gost3410`) |
| DSTU 4145 sign (private scalar) and verify (public scalars) | PRNG / key storage / HSM integration |
| Build flag propagation: `uacryptex-ffi/ct-scalar-mul` | Compiler/runtime guaranteed constant-time |

## Evidence bundle

1. **Functional KATs** (must pass with and without feature):
   ```bash
   cargo test -p uacryptex-core --test math_ec2m_kat --test dstu4145_kat
   cargo test -p uacryptex-core --features ct-scalar-mul --test math_ec2m_kat --test dstu4145_kat
   ```
2. **Performance** (7.3b gate, manual):
   ```bash
   ./scripts/bench-ct-scalar-mul.sh
   ```
   Record median verify/sign times; CT verify regression should stay below ~20%.
3. **Design notes:** [SECURITY.md](SECURITY.md) § Constant-time audit
4. **Source:** `crates/uacryptex-core/src/math/ec2m.rs` (`ec2m_mul_ct`, `wa_cmov_u32`)

## Recommended lab work (reviewer)

- [ ] **Threat model** agreed: co-tenant / shared-core attacker vs remote-only
- [ ] **dudect** or equivalent on `dstu4145_sign` / `dstu4145_verify` with `ct-scalar-mul` enabled (M257 PB fixture)
- [ ] Confirm no secret-dependent branches remain in scalar loop (static review + disassembly spot-check)
- [ ] Confirm `gf2m_mod_mul` risk accepted or scheduled for follow-up
- [ ] Deployment guidance: enable `ct-scalar-mul` for software private keys on shared hosts; HSM still preferred

## Sign-off template

| Field | Value |
|-------|-------|
| Reviewer / org | |
| Date | |
| uacryptex tag / commit | |
| Feature tested | `ct-scalar-mul` ☐ enabled |
| Functional KATs | ☐ pass |
| Timing analysis | ☐ dudect ☐ manual lab ☐ deferred |
| Residual risks | |
| Approved for production software keys | ☐ yes ☐ no ☐ with conditions |

Conditions example: “CT scalar mul only; field mul and non-DSTU algorithms out of scope.”

## Maintenance

Re-run this checklist when `math/ec2m.rs`, `math/gf2m.rs`, or DSTU 4145 sign/verify changes.
