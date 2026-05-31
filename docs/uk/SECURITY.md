# Нотатки з безпеки

> **Мови:** [English](../SECURITY.md) · Українська

Цей документ фіксує результати hardening-а. Це **не** формальний сертифікаційний артефакт.

## Constant-time аудит

**Область:** DSTU 4145 у `math/gf2m.rs`, `ec2m.rs`.

**Метод:** ручний огляд порту Cryptonite C. Автоматичний timing-аналіз не проводився.

| Область | Статус | Примітка |
|---------|--------|----------|
| `ec2m_mul` | CT опційно (`ct-scalar-mul`) | за замовч. — branch-on-bit |
| `ec2m_dual_mul` | CT опційно | як `ec2m_mul` |
| `gf2m_mod_mul` | не CT | як у Cryptonite |
| `int_ct_equals` | CT | порівняння підписів |
| `unsafe` | заборонено | `#![forbid(unsafe_code)]` у core |

Увімкнення: `cargo build -p uacryptex-core --features ct-scalar-mul`.

### Рекомендації

1. Документуйте threat model (HSM vs software key).
2. Для високих вимог — HSM.
3. На shared host — збірка з `ct-scalar-mul`.
4. Після змін у `gf2m.rs` / `ec2m.rs` — [CT_REVIEW.md](../CT_REVIEW.md).

## Legacy GOST R 34.10-94

**Deprecated.** Feature `legacy-gost3410` — **off by default**. Для нового UA PKI — DSTU 4145.

| | |
|--|--|
| Увімкнення | `--features legacy-gost3410` |
| KAT | params ID 1 і 2 |
| CT | **не аудитовано** |

## Fuzzing

`fuzz/`: `cms_decode`, `pkcs12_decode`, `cert_decode` — `./scripts/fuzz.sh [target]`.

## Miri

```bash
cargo +nightly miri test -p uacryptex-core
```

## Вразливості

Повідомляйте maintainers приватно до публічного розкриття.
