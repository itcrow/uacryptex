# KAT vectors (Cryptonite oracle)

Vectors extracted from Cryptonite acceptance/unit tests for cross-validation during Rust port.

| File | Cryptonite source | Status |
|------|-------------------|--------|
| `dstu4145/verify_pn.json` | `cryptoniteAtest/c/atest_dstu4145.c` | Phase 1 |

Run Rust KAT tests:

```bash
cargo test -p uacryptex-core --test dstu4145_kat
cargo test -p uacryptex-core --test dstu4145_kat verify_pn_kat_matches_cryptonite -- --ignored
```

Hex encoding matches Cryptonite test helpers:

- **big-endian** (`ba_alloc_from_be_hex_string`): reverse of naive hex decode
- **little-endian** (`ba_alloc_from_le_hex_string`): sequential hex decode
