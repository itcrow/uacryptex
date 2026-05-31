# Матриця сертифікаційної відповідності

> **Мови:** [English](../CERTIFICATION.md) · Українська

Мапінг сертифікованої функціональності Cryptonite на порт uacryptex. Підготовка до **повторної експертизи** ДССЗЗІ — **uacryptex не є сертифікованим продуктом** до завершення акредитованої оцінки на frozen release.

**Baseline:** Cryptonite (C, IIT test vectors).

## Легенда

| Символ | Значення |
|--------|----------|
| ✅ | Портовано; KAT / integration test OK |
| 🟡 | Частковий порт |
| ⏳ | Заплановано |
| ❌ | Поза scope |

## Криптопримітиви (стисло)

| Вимога | uacryptex | Evidence |
|--------|-----------|----------|
| DSTU 4145 sign/verify/DH | ✅ | `dstu4145_kat`, FFI |
| Kupyna, Kalyna | ✅ | `dstu7564_kat`, `dstu7624_kat` |
| GOST 28147, 34.311 | ✅ | `gost_kat` |
| GOST 34.10-94 | 🟡 legacy | `--features legacy-gost3410`; deprecated |
| AES/RSA/ECDSA/SHA | ✅ | `intl_kat` |
| Constant-time EC | 🟡 | `--features ct-scalar-mul` |

## PKI (стисло)

| Вимога | uacryptex |
|--------|-----------|
| X.509, CMS, CRL, OCSP, TSP | ✅ |
| EnvelopedData | ✅ |
| Cert/CRL engines | ✅ |
| DSTU extensions | 🟡 |

## Storage

PKCS#12 DSTU, PKCS#8 — ✅.

## Інтеграція

`pki_example`, Go/Python/PHP/Node binding-и — ✅ / 🟡.

## Прогалини для формальної сертифікації

1. Немає акредитованої оцінки uacryptex — лише KAT parity з Cryptonite.
2. Constant-time — optional feature; потрібен зовнішній аудит.
3. Не весь API Cryptonite (~1039 символів) — [API_INVENTORY.md](../API_INVENTORY.md).
4. Legacy GOST 34.10-94 — optional, deprecated.

**Повна таблиця** — [англійська версія](../CERTIFICATION.md).

Див. [SECURITY.md](SECURITY.md), [REPRODUCIBLE_BUILD.md](../REPRODUCIBLE_BUILD.md).
