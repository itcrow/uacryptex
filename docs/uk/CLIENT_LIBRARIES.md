# Посібник з клієнтських бібліотек

> **Мови:** [English](../CLIENT_LIBRARIES.md) · Українська

Цей документ для розробників застосунків на **Go**, **Python**, **PHP** або **Node.js**. Усі пакети викликають одну й ту саму Rust-реалізацію через стабільний C ABI (`uacryptex-ffi`). Криптологіка в binding-шарах відсутня.

Збірка та підтримка FFI: [BINDINGS.md](BINDINGS.md). C-контракт: [FFI.md](../FFI.md).

---

## Пакети

| Мова | Встановлення (ціль) | Import / namespace | Мін. runtime |
|------|---------------------|--------------------|--------------|
| **Go** | `go get github.com/itcrow/uacryptex/uacryptex@v0.1.0` | `github.com/itcrow/uacryptex/uacryptex` | Go 1.22+, **CGO** |
| **Python** | `pip install uacryptex` (planned) / `pip install -e python/` | `import uacryptex` | Python 3.9+ |
| **PHP** | `composer require itcrow/uacryptex` | `Itcrow\Uacryptex\Uacryptex` | PHP 8.1+, **ext-ffi** |
| **Node.js** | `npm install @itcrow/uacryptex` (planned) / `npm install` у `nodejs/` | `require('@itcrow/uacryptex')` | Node.js 18+ |

Реєстри та релізи: [PUBLISHING.md](../PUBLISHING.md).

---

## Native-бібліотека

Кожному client-пакету потрібен зібраний **`uacryptex-ffi`** для вашої ОС і архітектури:

| Платформа | Shared (Python / PHP / Node) | Static (Go cgo) |
|-----------|------------------------------|-----------------|
| Linux amd64/arm64 | `libuacryptex_ffi.so` | `libuacryptex_ffi.a` |
| macOS | `libuacryptex_ffi.dylib` | `libuacryptex_ffi.a` |
| Windows | `uacryptex_ffi.dll` | `uacryptex_ffi.lib` |

**З git checkout:**

```bash
./scripts/build-ffi.sh
./scripts/sync-native-libs.sh

# або tarball з релізу:
./scripts/fetch-native-lib.sh 0.1.0
./scripts/sync-native-libs.sh
```

**Перевизначення шляху** (усі мови):

```bash
export UACRYPTEX_LIB=/absolute/path/to/libuacryptex_ffi.so
```

Порядок пошуку: `UACRYPTEX_LIB` → bundled `native/lib/{os}/{arch}/` → `../native/lib/...`.

Підтримувані triple: `scripts/platforms.sh`.

---

## Спільні поняття

### Handles і життєвий цикл

| Тип | Відкрити | Закрити |
|-----|----------|---------|
| `PrivateKey` | `OpenPrivateKey`, `OpenPKCS8`, `Keystore.PrivateKey()` | `Close()` / `close()` |
| `Keystore` | `OpenPKCS12` | `Close()` / `close()` |

Правила:

1. Завжди викликайте **`Close()`** — це `uacryptex_handle_free`.
2. `PrivateKey` з `Keystore.PrivateKey()` **ділить** handle keystore. Закривайте keystore, а не окремо key (у Python: `with open_pkcs12(...) as ks:`).
3. Вихідні буфери FFI копіюються в пам'ять мови і одразу звільняються.

### Помилки

| Код | Значення | Go | Python | PHP | Node.js |
|-----|----------|-----|--------|-----|---------|
| `0` | OK | `nil` | — | — | — |
| `1` | Помилка алокації | `ErrMemory` | `AllocationError` | `AllocationError` | `AllocationError` |
| `2` | Невалідний аргумент | `ErrInvalidParam` | `InvalidParamError` | `InvalidParamError` | `InvalidParamError` |
| `3` | Verify failed | `ErrVerifyFailed` | `VerifyFailedError` | `VerifyFailedError` | `VerifyFailedError` |
| інше | Повідомлення core | `*Error` | `UacryptexError` | `UacryptexException` | `UacryptexError` |

### Потокобезпека

Handles **не потокобезпечні** — створюйте окремий handle на goroutine/thread або захищайте mutex.

### Версія

Поточна semver core: **0.1.0** — `uacryptex.Version` / `library_version()` / `Uacryptex::VERSION` / `libraryVersion()`.

---

## Швидкий старт — CMS sign/verify

### Go

```go
key, err := uacryptex.OpenPrivateKey(keyDER, certDER)
defer key.Close()

cms, err := uacryptex.SignCMS(payload, key)
err = uacryptex.VerifyCMS(payload, cms)
```

`PrivateKey` реалізує `crypto.Signer` — digest має бути **32 байти GOST3411**.

### Python

```python
with uacryptex.open_private_key(key_der, cert_der) as key:
    cms = uacryptex.sign_cms(payload, key)
    uacryptex.verify_cms(payload, cms)
```

### PHP

```php
$key = Uacryptex::openPrivateKey($keyDer, $certDer);
try {
    $cms = Uacryptex::signCms($payload, $key);
    Uacryptex::verifyCms($payload, $cms);
} finally {
    $key->close();
}
```

CLI: `php -d ffi.enable=1 script.php`.

### Node.js

```javascript
const key = uacryptex.openPrivateKey(keyBuf, certBuf);
try {
  const cms = uacryptex.signCms(Buffer.from(payload), key);
  uacryptex.verifyCms(Buffer.from(payload), cms);
} finally {
  key.close();
}
```

---

## PKCS#12

| Go | Python | PHP | Node.js |
|----|--------|-----|---------|
| `OpenPKCS12` | `open_pkcs12` | `openPkcs12` | `openPkcs12` |
| `PrivateKey()` | `private_key()` | `privateKey()` | `privateKey()` |
| `CertificateCount()` | `certificate_count()` | `certificateCount()` | `certificateCount()` |
| `GetCertificate(i)` | `get_certificate(i)` | `getCertificate(i)` | `getCertificate(i)` |

---

## Ключі та підписи

| Операція | Go | Python | PHP | Node.js |
|----------|-----|--------|-----|---------|
| Raw key + cert | `OpenPrivateKey` | `open_private_key` | `openPrivateKey` | `openPrivateKey` |
| PKCS#8 | `OpenPKCS8` | `open_pkcs8` | `openPkcs8` | `openPkcs8` |
| Підпис digest | `SignHash` | `sign_hash` | `signHash` | `signHash` |
| Підпис data | `SignData` | `sign_data` | `signData` | `signData` |
| Verify digest/data | `VerifyHash` / `VerifyData` | `verify_hash` / `verify_data` | same | same |
| Digest | `Digest` | `digest` | `digest` | `digest` |

---

## CMS і профілі CAdES

| Профіль | Опис | API підпису |
|---------|------|-------------|
| **BES** | Базовий CMS SignedData | `SignCMS` / `sign_cms` / `signCms` |
| **T** | BES + timestamp підпису | `SignCmsCadesT` |
| **C** | BES + refs cert/CRL | `SignCmsCadesC` |
| **X** | BES + values cert/OCSP | `SignCmsCadesX` |
| **LT** | X + validation data в SignedData | `SignCmsCadesLT` |
| **A** | LT + archive timestamp | `SignCmsCadesA` |

Перевірка всіх профілів: **`VerifyCMS`** над **оригінальними** підписаними байтами.

### Параметри CAdES-T / A

- `signKey`, `tsaKey` — ключі підписанта та TSA.
- `serial` — серійний номер TST (bytes).
- `currentTime` — Unix seconds.
- `policyOID` — опційний OID політики TSP.

### Матеріали валідації (C / X / LT / A)

| Параметр | Профілі | Призначення |
|----------|---------|-------------|
| `refCert` | C, X, LT, A | Cert DER емітента |
| `refCrl` | C | CRL для refs |
| `fullCrl` | LT, A | Повний CRL |
| `deltaCrl` | LT, A | Delta CRL (порожній якщо немає) |
| `ocspResponse` | X, LT, A | OCSP response |

### Enveloped CMS

| Go | Python | PHP | Node.js |
|----|--------|-----|---------|
| `EnvelopCMS` | `envelop_cms` | `envelopCms` | `envelopCms` |
| `DecryptCMS` | `decrypt_cms` | `decryptCms` | `decryptCms` |

Шифрування: DSTU4145 DH + GOST28147-CFB.

---

## Сертифікати та CRL

| Операція | Go | Python | PHP | Node.js |
|----------|-----|--------|-----|---------|
| Verify cert | `VerifyCertificate` | `verify_certificate` | `verifyCertificate` | `verifyCertificate` |
| Validity | `CheckCertificateValidity` | `check_certificate_validity` | `checkCertificateValidity` | `checkCertificateValidity` |
| SPKI | `CertificateSPKI` | `certificate_spki` | `certificateSpki` | `certificateSpki` |
| Verify CRL | `VerifyCRL` | `verify_crl` | `verifyCrl` | `verifyCrl` |
| Revoked? | `IsCertificateRevoked` | `is_certificate_revoked` | `isCertificateRevoked` | `isCertificateRevoked` |
| Issue CRL | `GenerateCRL` | `generate_crl` | `generateCrl` | `generateCrl` |

Типи CRL: `CRL_TYPE_FULL` (1), `CRL_TYPE_DELTA` (0).

---

## OCSP, TSP, CSR, видача cert

| Операція | Go | Python | PHP | Node.js |
|----------|-----|--------|-----|---------|
| OCSP request | `OcspRequestFromCert` | `ocsp_request_from_cert` | `ocspRequestFromCert` | `ocspRequestFromCert` |
| Signed OCSP request | `OcspRequestGenerate` | `ocsp_request_generate` | `ocspRequestGenerate` | `ocspRequestGenerate` |
| Verify OCSP response | `OcspResponseVerify` | `ocsp_response_verify` | `ocspResponseVerify` | `ocspResponseVerify` |
| Validate OCSP | `OcspResponseValidate` | — | `ocspResponseValidate` | `ocspResponseValidate` |
| Generate OCSP | `OcspResponseGenerate` | — | `ocspResponseGenerate` | `ocspResponseGenerate` |
| TSP request | `TspRequestFromData` | `tsp_request_from_data` | `tspRequestFromData` | `tspRequestFromData` |
| Verify TSP | `TspResponseVerify` | `tsp_response_verify` | `tspResponseVerify` | `tspResponseVerify` |
| Generate TSP | `TspResponseGenerate` | `tsp_response_generate` | `tspResponseGenerate` | `tspResponseGenerate` |
| CSR | `CsrGenerate` / `CsrVerify` | `csr_generate` / `csr_verify` | same | same |
| Issue cert | `GenerateCertificate` | `generate_certificate` | `generateCertificate` | `generateCertificate` |

---

## DSTU 4145 (polynomial basis)

`VerifyDstu4145PB` — низькорівнева верифікація з явними параметрами поля. Для застосунків зазвичай достатньо `OpenPrivateKey` + `SignHash`.

---

## Особливості мов

### Go

- `CGO_ENABLED=1`, static lib у `go/native/lib/{GOOS}/{GOARCH}/`.
- `crypto.Signer`, digest 32 байти GOST3411.
- Приклади: `go/uacryptex/example_test.go`.

### Python

- Context managers: `with open_pkcs12(...) as ks:`.
- Експорт API: `python/uacryptex/__init__.py`.

### PHP

- `ext-ffi`, `php -d ffi.enable=1`.
- `try` / `finally` + `close()`.

### Node.js

- [koffi](https://github.com/Koromix/koffi), дані як `Buffer`.

---

## Troubleshooting

| Симптом | Причина | Рішення |
|---------|---------|---------|
| `cannot load shared library` | Немає native lib або невірна arch | `build-ffi.sh` + `sync-native-libs.sh` або `UACRYPTEX_LIB` |
| Go: CGO excluded | CGO вимкнено | `export CGO_ENABLED=1` |
| PHP: FFI restricted | `ffi.enable` off | `php -d ffi.enable=1` |
| `invalid parameter` на CAdES | Порожні ref cert/CRL/OCSP | Передавайте непорожні DER |
| Verify fails | Інший payload | Ті самі `data`, що підписували |

---

## Тести

```bash
make go-test
make python-test
make php-test
make node-test
```

---

## Див. також

| Тема | Документ |
|------|----------|
| Мапінг FFI | [API_INVENTORY.md](../API_INVENTORY.md) |
| Збірка binding-ів | [BINDINGS.md](BINDINGS.md) |
| C API | [FFI.md](../FFI.md) |
| Релізи | [PUBLISHING.md](../PUBLISHING.md) |
| CAdES-X-L Type 1/2 (planned) | [ROADMAP.md](ROADMAP.md#todo) |
