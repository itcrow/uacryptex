# Покриття функціоналу Cryptonite

> **Мови:** [English](../CRYPTONITE_PARITY.md) · Українська

Наскільки uacryptex покриває функціонал [Cryptonite](https://github.com/privat-it/cryptonite) сьогодні і що залишилось.

**Пов’язано:** [API_INVENTORY.md](../API_INVENTORY.md) (мапінг символів), [CERTIFICATION.md](../CERTIFICATION.md) (матриця відповідності), [ROADMAP.md](../ROADMAP.md) (терміни).

Джерела Cryptonite C у `../cryptonite/` — **KAT oracle** під час міграції; uacryptex **не лінкує** Cryptonite під час виконання.

## Стислий висновок

uacryptex покриває **більшість практичного функціоналу Cryptonite для українського PKI**, але **не є drop-in заміною** C SDK Cryptonite (~1039 експортованих символів). Архітектура інша: Rust core + невеликий стабільний C ABI (~44 entry points) і high-level binding-и (Go, Python, PHP, Node.js).

| Рівень покриття | Орієнтовно | Зміст |
|-----------------|------------|-------|
| **Публічний C / FFI API** | ~4% символів Cryptonite | Навмисно: `SignCMS`, `EnvelopCMS`, `OpenPKCS12`, … — не 1:1 порт `cert_*`, `sdata_*`, `aid_*` |
| **Сертифікована криптографія + типові PKI-сценарії** | ~85–95% | Те, що зазвичай потрібно продакшен UA PKI |
| **Повна паритетність Cryptonite C SDK** | ~30–40% (оцінка) | Сотні низькорівневих pkix-хелперів і менеджерів об’єктів |

**Терміни:** повна паритетність — **12–15 місяців** (2–3 FTE), див. [ROADMAP.md](../ROADMAP.md). MVP vertical slice (підпис → CMS → verify → PKCS#12) уже працює.

## Розбивка інвентаря символів

Автогенерація з `../cryptonite/src/**/*.h` — [API_INVENTORY.md](../API_INVENTORY.md).

| Метрика | Значення |
|---------|--------:|
| Експортовані символи Cryptonite | 1039 |
| Стабільні entry points uacryptex C ABI | ~44 |
| Go module | `github.com/itcrow/uacryptex` |

### За модулями Cryptonite

| Модуль | Символів | Ціль uacryptex | Примітки |
|--------|--------:|----------------|----------|
| `pkix/` | 602 | `uacryptex-core::pki` | Engines + high-level API |
| `cryptonite/` | 217 | `uacryptex-core::primitives` | UA — порт; intl → RustCrypto |
| `asn1/` | 153 | `der` / `x509-*` | **Не портується 1:1** |
| `storage/` | 57 | `uacryptex-core::storage` | PKCS#8 / PKCS#12 — переважно готово |
| `pthread/` | 10 | — | Замінено `std::sync` |

### За стратегією міграції

| Стратегія | Символів | Статус |
|-----------|--------:|--------|
| skip — `der` crate | 378 | N/A |
| Phase 2 — pkix | 319 | Частково |
| TBD | 123 | Ще не перенесено |
| RustCrypto | 88 | Міжнародні примітиви |
| Phase 1 — UA примітиви | 82 | Переважно готово (KAT) |
| internal | 39 | Rust idioms |
| N/A — `std::sync` | 10 | — |

## Що покрито добре

Докази: KAT у `crates/uacryptex-core/tests/`, `pki_example`, [CERTIFICATION.md](../CERTIFICATION.md).

### Криптопримітиви

| Область | Статус |
|---------|--------|
| DSTU 4145 sign / verify / DH / keygen | ✅ |
| Kupyna (7564), Kalyna (7624) | ✅ (усі основні режими Kalyna в KAT) |
| GOST 28147, GOST 34.311 | ✅ |
| AES / SHA / RSA / ECDSA | ✅ (RustCrypto) |
| GOST R 34.10-94 | 🟡 опційно, deprecated |

### PKI і протоколи

| Область | Статус |
|---------|--------|
| X.509, SPKI | ✅ |
| CMS SignedData, CAdES-BES | ✅ |
| CAdES-T / C / X / LT / A | ✅ |
| EnvelopedData | ✅ GOST28147-CFB + Kalyna-GCM 128/256/512 |
| OCSP, TSP | ✅ |
| CRL verify + issue | ✅ |
| CSR, видача сертифікатів | ✅ (CSR 🟡 для частини типів ключів) |
| PKCS#12, PKCS#8 | ✅ |

### Інтеграційні сценарії

| Сценарій | Cryptonite | uacryptex |
|----------|------------|-----------|
| `pkiExample` (M257 PB) | ✅ | ✅ |
| MVP vertical slice | demo | ✅ |
| Go / Python / PHP / Node | N/A | ✅ |

## Переваги над Cryptonite

uacryptex **не є універсально кращою заміною** Cryptonite — див. [Часткове покриття](#часткове-покриття-і-прогалини) і [Де Cryptonite сильніший](#де-cryptonite-залишається-сильнішим). Але в окремих вимірах uacryptex **випереджає** або **зручніший**.

### Протоколи

| Функція | Cryptonite | uacryptex |
|---------|------------|-----------|
| **Kalyna-GCM у CMS EnvelopedData** | лише GOST28147-CFB у pkix | GOST28147-CFB + Kalyna-128/256/512-GCM (AEAD) |
| **CAdES-T / LT / A одним викликом** | TSP engines є; `pkiExample` — BES/C/X | `SignCmsCadesT/LT/A` через FFI і всі binding-и |

Kalyna як **примітив** є в обох бібліотеках; нове в uacryptex — **шифрування контенту CMS** з Kalyna-GCM OID.

### Інтеграція та DX

| Область | Перевага uacryptex |
|---------|-------------------|
| Binding-и | Go, Python, PHP, Node.js на одному FFI — [BINDINGS.md](../BINDINGS.md) |
| API | ~44 high-level entry points замість ~1039 C-символів |
| Go | `PrivateKey` implements `crypto.Signer` |
| Приклади | `go/examples/sign-document/`, `demo/` |
| Дистрибуція | Prebuilt `native/lib/{os}/{arch}/`, CI matrix |

### Інженерія та безпека

| Область | Перевага uacryptex |
|---------|-------------------|
| Memory safety | Pure Rust core |
| ASN.1 / PKI | `der`, `x509-cert`, `cms` замість asn1c |
| Hardening | fuzz, Miri, benchmarks — [SECURITY.md](../SECURITY.md) |
| Reproducible build | [REPRODUCIBLE_BUILD.md](../REPRODUCIBLE_BUILD.md) |
| GOST 34.10-94 | вимкнено за замовчуванням, deprecated |
| CT (опційно) | `--features ct-scalar-mul` |

CT і формальний side-channel аудит **ще не завершені** — опційний feature не замінює акредитовану історію Cryptonite.

### Коли обрати uacryptex

- інтеграція в **Go / Python / PHP / Node.js**;
- **Kalyna-GCM** для enveloped data;
- **CAdES-T / LT / A** без ручної збірки CMS;
- cross-platform FFI + binding-и «з коробки»;
- memory-safe core і сучасний CI/fuzz workflow.

### Де Cryptonite залишається сильнішим

| Область | Cryptonite | uacryptex |
|---------|------------|-----------|
| **Сертифікація ДССЗЗІ** | ✅ | ❌ лише KAT parity |
| **Low-level C SDK** | повний `cert_*`, `sdata_*`, … | engines + high-level FFI |
| **Production maturity** | довгий track record | молодший проєкт |
| **Екзотичний PKIX/CMS** | fine-grained accessors | багато pkix-хелперів TBD |

Оберіть Cryptonite для **сертифікованого drop-in C SDK** або **максимального low-level контролю** без переписування інтеграції.

## Часткове покриття і прогалини

### Навмисно не портується

- **ASN.1** (378 символів) → `der`, `x509-cert`, `cms`, …
- **Утиліти** (`ba_*`) і **pthread** → стандартна бібліотека Rust

### Низькорівневий pkix API

Cryptonite: `aid_*`, `cert_*`, `sdata_*`, `cinfo_*`, … uacryptex: **engines** + FFI з [FFI.md](../FFI.md). Прямі виклики менеджерів Cryptonite потребують переписування інтеграції.

### TBD (~123 символи)

`sdata_*`, `cinfo_*`, `ocspresp_*`, `crypto_cache_*`, окремі legacy-хелпери.

### Відомі функціональні прогалини

| Прогалина | Статус |
|-----------|--------|
| CAdES-X-L Type 1/2 | ✅ |
| DSTU X.509 extensions (повний набір) | ✅ |
| ONB DSTU4145 verify (low-level) | 🟡 PB через FFI |
| Constant-time EC | 🟡 опційний feature |
| Формальна сертифікація uacryptex | ❌ |

## Практичні рекомендації

**Типовий UA PKI** (підпис, CMS/CAdES, PKCS#12, OCSP/TSP, enveloped) — uacryptex **готовий до оцінки**; `pkiExample` проходить.

**Drop-in заміна C SDK Cryptonite** — покриття **низьке**; потрібен новий API ([CLIENT_LIBRARIES.md](../CLIENT_LIBRARIES.md)).

**Формальна сертифікація ДССЗЗІ** — алгоритмічна база є, але акредитована оцінка frozen release ще не пройдена ([CERTIFICATION.md](../CERTIFICATION.md)).

## Підтримка документа

Оновлюйте при закритті великих модулів, появі нових переваг над Cryptonite (розділ [Переваги над Cryptonite](#переваги-над-cryptonite)), розширенні FFI (`./scripts/generate-api-inventory.sh`) або зміні milestone у roadmap / certification.
