# Client libraries guide

> **Languages:** English · [Українська](uk/CLIENT_LIBRARIES.md)

This guide is for application developers using **Go**, **Python**, **PHP**, or **Node.js** bindings. All packages call the same Rust implementation through a stable C ABI (`uacryptex-ffi`). There is no cryptographic logic in the binding layers.

For build layout and FFI maintenance, see [BINDINGS.md](BINDINGS.md). For the C contract, see [FFI.md](FFI.md).

---

## Packages

| Language | Install (target) | Import / namespace | Min. runtime |
|----------|------------------|--------------------|--------------|
| **Go** | `go get github.com/itcrow/uacryptex/uacryptex@v0.1.0` | `github.com/itcrow/uacryptex/uacryptex` | Go 1.22+, **CGO** |
| **Python** | `pip install uacryptex` (planned) / `pip install -e python/` | `import uacryptex` | Python 3.9+ |
| **PHP** | `composer require itcrow/uacryptex` | `Itcrow\Uacryptex\Uacryptex` | PHP 8.1+, **ext-ffi** |
| **Node.js** | `npm install @itcrow/uacryptex` (planned) / `npm install` in `nodejs/` | `require('@itcrow/uacryptex')` | Node.js 18+ |

Published package names and registry flow: [PUBLISHING.md](PUBLISHING.md).

---

## Native library requirement

Every client package needs a prebuilt **`uacryptex-ffi`** binary for your OS and CPU:

| Platform | Shared library (Python / PHP / Node) | Static library (Go cgo) |
|----------|--------------------------------------|-------------------------|
| Linux amd64 | `libuacryptex_ffi.so` | `libuacryptex_ffi.a` |
| Linux arm64 | `libuacryptex_ffi.so` | `libuacryptex_ffi.a` |
| macOS | `libuacryptex_ffi.dylib` | `libuacryptex_ffi.a` |
| Windows | `uacryptex_ffi.dll` | `libuacryptex_ffi.a` (MinGW; Go cgo) |

**From a git checkout:**

```bash
./scripts/build-ffi.sh              # host only
./scripts/sync-native-libs.sh       # copy into go/python/php/nodejs trees

# or download a release tarball:
./scripts/fetch-native-lib.sh 0.1.0
./scripts/sync-native-libs.sh
```

**Override search path** (all languages):

```bash
export UACRYPTEX_LIB=/absolute/path/to/libuacryptex_ffi.so
```

Default lookup order: `UACRYPTEX_LIB` → bundled `native/lib/{os}/{arch}/` inside the package → `../native/lib/...` relative to the binding source tree.

Supported triples: `scripts/platforms.sh` (`linux`/`darwin`/`windows` × `amd64`/`arm64`).

---

## Common concepts

### Handles and lifecycle

Operations that use a private key or PKCS#12 container hold an opaque **native handle**:

| Type | Open with | Release with |
|------|-----------|--------------|
| `PrivateKey` | `OpenPrivateKey`, `OpenPKCS8`, `Keystore.PrivateKey()` | `Close()` / `close()` |
| `Keystore` | `OpenPKCS12` | `Close()` / `close()` |

Rules:

1. Call **`Close()`** (or `close()`) when finished — this invokes `uacryptex_handle_free`.
2. A `PrivateKey` from `Keystore.PrivateKey()` **shares** the keystore handle. Close only the **keystore** (or do not close the key separately). In Python, use `with open_pkcs12(...) as ks:` and call `ks.private_key()` without closing the key alone.
3. FFI output buffers are copied into language-owned memory and freed immediately; you do not free CMS or signature bytes yourself.

### Errors

Native status codes map to idiomatic errors:

| Code | Meaning | Go | Python | PHP | Node.js |
|------|---------|-----|--------|-----|---------|
| `0` | OK | `nil` | — | — | — |
| `1` | Allocation failed | `ErrMemory` | `AllocationError` | `AllocationError` | `AllocationError` |
| `2` | Invalid argument | `ErrInvalidParam` | `InvalidParamError` | `InvalidParamError` | `InvalidParamError` |
| `3` | Verify failed | `ErrVerifyFailed` | `VerifyFailedError` | `VerifyFailedError` | `VerifyFailedError` |
| other | Core message | `*Error` | `UacryptexError` | `UacryptexException` | `UacryptexError` |

Verification APIs (`VerifyCMS`, `VerifyHash`, …) return/throw on failure. Signing and generation APIs return `(result, error)` in Go and raise in Python/PHP/Node.

### Thread safety

Treat handles as **not thread-safe** unless your application serializes access. Create one handle per goroutine/thread or guard with a mutex.

### Version

All packages expose the Rust core semver (currently **0.1.0**):

| Go | Python | PHP | Node.js |
|----|--------|-----|---------|
| `uacryptex.Version` / `LibraryVersion()` | `__version__` / `library_version()` | `Uacryptex::VERSION` / `libraryVersion()` | `VERSION` / `libraryVersion()` |

---

## Quick start — sign and verify CMS

### Go

```go
import "github.com/itcrow/uacryptex/uacryptex"

key, err := uacryptex.OpenPrivateKey(keyDER, certDER)
if err != nil { /* ... */ }
defer key.Close()

cms, err := uacryptex.SignCMS(payload, key)
if err != nil { /* ... */ }

if err := uacryptex.VerifyCMS(payload, cms); err != nil { /* ... */ }
```

`PrivateKey` implements `crypto.Signer` — pass a **32-byte GOST3411 digest** to `Sign`.

### Python

```python
import uacryptex

with uacryptex.open_private_key(key_der, cert_der) as key:
    cms = uacryptex.sign_cms(payload, key)
    uacryptex.verify_cms(payload, cms)
```

### PHP

```php
use Itcrow\Uacryptex\Uacryptex;

$key = Uacryptex::openPrivateKey($keyDer, $certDer);
try {
    $cms = Uacryptex::signCms($payload, $key);
    Uacryptex::verifyCms($payload, $cms);
} finally {
    $key->close();
}
```

CLI: `php -d ffi.enable=1 script.php` (or `ffi.enable=true` in `php.ini`).

### Node.js

```javascript
const uacryptex = require('@itcrow/uacryptex');

const key = uacryptex.openPrivateKey(keyBuf, certBuf);
try {
  const cms = uacryptex.signCms(Buffer.from(payload), key);
  uacryptex.verifyCms(Buffer.from(payload), cms);
} finally {
  key.close();
}
```

---

## PKCS#12 keystore

```text
OpenPKCS12(p12, password) → Keystore
  ├─ PrivateKey()           → signing key (shared handle)
  ├─ CertificateCount()
  ├─ GetCertificate(i)
  └─ SetCertificate(cert)  → attach external cert to store
```

| Go | Python | PHP | Node.js |
|----|--------|-----|---------|
| `OpenPKCS12` | `open_pkcs12` | `openPkcs12` | `openPkcs12` |
| `(*Keystore).PrivateKey()` | `Keystore.private_key()` | `$ks->privateKey()` | `ks.privateKey()` |
| `(*Keystore).CertificateCount()` | `certificate_count()` | `$ks->certificateCount()` | `ks.certificateCount()` |
| `(*Keystore).GetCertificate(i)` | `get_certificate(i)` | `$ks->getCertificate(i)` | `ks.getCertificate(i)` |

Password is a string; P12 must be DER bytes (`[]byte` / `bytes` / `string` / `Buffer`).

---

## Keys and raw signatures

| Operation | Go | Python | PHP | Node.js |
|-----------|-----|--------|-----|---------|
| Raw key + cert | `OpenPrivateKey` | `open_private_key` | `openPrivateKey` | `openPrivateKey` |
| PKCS#8 | `OpenPKCS8` | `open_pkcs8` | `openPkcs8` | `openPkcs8` |
| Sign digest | `(*PrivateKey).SignHash` | `PrivateKey.sign_hash` | `$key->signHash` | `key.signHash` |
| Sign data (hash-then-sign) | `(*PrivateKey).SignData` | `sign_data` / `sign_data` | `signData` | `signData` |
| Verify digest | `VerifyHash` | `verify_hash` | `verifyHash` | `verifyHash` |
| Verify data | `VerifyData` | `verify_data` | `verifyData` | `verifyData` |
| Digest (GOST3411 default) | `Digest` | `digest` | `digest` | `digest` |

`Digest(data, algorithmAid, cert)` — pass `nil`/`None`/`null` for default GOST3411; optional `algorithmAid` or signer `cert` selects the hash algorithm from the certificate.

---

## CMS and CAdES profiles

| Profile | Description | Sign API |
|---------|-------------|----------|
| **BES** | Basic CMS SignedData | `SignCMS` / `sign_cms` / `signCms` |
| **T** | BES + signature timestamp | `SignCmsCadesT` (+ TSA key, serial, time) |
| **C** | BES + cert/CRL refs | `SignCmsCadesC` (+ ref cert, CRL) |
| **X** | BES + cert/OCSP values | `SignCmsCadesX` (+ ref cert, OCSP response) |
| **LT** | X + validation data in SignedData | `SignCmsCadesLT` (+ full CRL, optional delta CRL) |
| **A** | LT + archive timestamp | `SignCmsCadesA` (+ TSA key, serial, time) |

Verify all profiles with **`VerifyCMS`** / `verify_cms` / `verifyCms` over the **original signed payload** (not the CMS blob alone).

### CAdES-T / CAdES-A parameters

- **`signKey`** — signer private key.
- **`tsaKey`** — TSA private key (same API as any `PrivateKey`).
- **`serial`** — TST serial number bytes (caller-chosen).
- **`currentTime`** — Unix seconds for token generation.
- **`policyOID`** — optional TSP policy OID string (`*string` in Go; `None`/`null` if unused).

### CAdES-C / X / LT / A validation material

| Parameter | Used in | Purpose |
|-----------|---------|---------|
| `refCert` | C, X, LT, A | Issuer / validation certificate DER |
| `refCrl` | C | CRL DER for revocation refs |
| `fullCrl` | LT, A | Full CRL embedded in LT |
| `deltaCrl` | LT, A | Optional delta CRL (`[]byte{}` / empty string if none) |
| `ocspResponse` | X, LT, A | OCSP response bytes |

### Enveloped CMS

| Go | Python | PHP | Node.js |
|----|--------|-----|---------|
| `EnvelopCMS(data, originatorKey, recipientCert)` | `envelop_cms` | `envelopCms` | `envelopCms` |
| `DecryptCMS(cms, recipientKey, recipientCert, originatorCert, external)` | `decrypt_cms` | `decryptCms` | `decryptCms` |

Encryption: DSTU4145 key agreement + GOST28147-CFB. `originatorCert` and `external` are optional depending on how the EnvelopedData was built.

---

## Certificates and CRL

| Operation | Go | Python | PHP | Node.js |
|-----------|-----|--------|-----|---------|
| Verify cert chain sig | `VerifyCertificate` | `verify_certificate` | `verifyCertificate` | `verifyCertificate` |
| Check validity window | `CheckCertificateValidity` | `check_certificate_validity` | `checkCertificateValidity` | `checkCertificateValidity` |
| Extract SPKI | `CertificateSPKI` | `certificate_spki` | `certificateSpki` | `certificateSpki` |
| Verify CRL | `VerifyCRL` | `verify_crl` | `verifyCrl` | `verifyCrl` |
| Revocation check | `IsCertificateRevoked` | `is_certificate_revoked` | `isCertificateRevoked` | `isCertificateRevoked` |
| Issue CRL | `(*PrivateKey).GenerateCRL` | `generate_crl` | `$key->generateCrl` | `key.generateCrl` |

CRL types: `CRLTypeFull` / `CRL_TYPE_FULL` (1), `CRLTypeDelta` / `CRL_TYPE_DELTA` (0).

---

## OCSP, TSP, CSR, issuance

| Operation | Go | Python | PHP | Node.js |
|-----------|-----|--------|-----|---------|
| OCSP request (unsigned) | `OcspRequestFromCert` | `ocsp_request_from_cert` | `ocspRequestFromCert` | `ocspRequestFromCert` |
| OCSP request (signed) | `OcspRequestGenerate` | `ocsp_request_generate` | `ocspRequestGenerate` | `ocspRequestGenerate` |
| Verify OCSP request | `OcspRequestVerify` | — | — | — |
| Verify OCSP response | `OcspResponseVerify` | `ocsp_response_verify` | `ocspResponseVerify` | `ocspResponseVerify` |
| Validate OCSP response | `OcspResponseValidate` | — | `ocspResponseValidate` | `ocspResponseValidate` |
| Generate OCSP response | `(*PrivateKey).OcspResponseGenerate` | — | `$key->ocspResponseGenerate` | `key.ocspResponseGenerate` |
| TSP request (data) | `TspRequestFromData` | `tsp_request_from_data` | `tspRequestFromData` | `tspRequestFromData` |
| TSP request (hash) | `TspRequestFromHash` | — | — | — |
| Verify TSP response | `TspResponseVerify` | `tsp_response_verify` | `tspResponseVerify` | `tspResponseVerify` |
| Generate TSP response | `(*PrivateKey).TspResponseGenerate` | `tsp_response_generate` | `$key->tspResponseGenerate` | `key.tspResponseGenerate` |
| Generate CSR | `(*PrivateKey).CsrGenerate` | `csr_generate` | `$key->csrGenerate` | `key.csrGenerate` |
| Verify CSR | `CsrVerify` | `csr_verify` | `csrVerify` | `csrVerify` |
| Issue certificate | `(*PrivateKey).GenerateCertificate` | `generate_certificate` | `$key->generateCertificate` | `key.generateCertificate` |

`OcspRequestGenerate` / `ocsp_request_generate`: pass `requestorKey` / `PrivateKey` for a signed request; `nil`/`None`/`null` for unsigned.

`OcspResponseValidate(request, response, rootCert, currentTime, timeoutMinutes)` checks freshness and `nextUpdate`.

---

## Low-level DSTU 4145 (polynomial basis)

`VerifyDstu4145PB` / `verify_dstu4145_pb` / `verifyDstu4145Pb` — verify a signature over GF(2^m) with explicit field parameters (`f`, `a`, `b`, `n`, generator, public point, hash, `r`, `s`). Used for KAT and custom curves; most applications use `OpenPrivateKey` + `SignHash` instead.

---

## Language-specific notes

### Go

- Requires **`CGO_ENABLED=1`** and a static archive under `go/native/lib/{GOOS}/{GOARCH}/`.
- `PrivateKey` implements [`crypto.Signer`](https://pkg.go.dev/crypto#Signer); `Sign` expects an already-hashed digest.
- **Runnable demo:** `cd go && CGO_ENABLED=1 go run ./examples/demo/` — see [go/README.md](../go/README.md).
- Godoc examples: `go/uacryptex/example_test.go`.

### Python

- Package data bundles `uacryptex/native/lib/**` in wheels (when published).
- Context managers: `with open_pkcs12(...) as ks:` and `with open_private_key(...) as key:`.
- Module exports: see `python/uacryptex/__init__.py` (`__all__`).

### PHP

- Requires **`ext-ffi`**. For CLI tests: `php -d ffi.enable=1`.
- Prefer `try` / `finally` with `$key->close()` and `$ks->close()`.
- Autoload: `Itcrow\Uacryptex\` from `php/src/` (monorepo) or Composer package `itcrow/uacryptex`.

### Node.js

- Uses [koffi](https://github.com/Koromix/koffi) to load the shared library.
- Pass binary data as `Buffer`; empty optional buffers as `null`.
- Type hints: `nodejs/lib/index.d.ts` (if present).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `cannot load shared library` / `dlopen` failed | Native lib missing or wrong arch | Run `build-ffi.sh` + `sync-native-libs.sh` or set `UACRYPTEX_LIB` |
| Go: `build constraints exclude all Go files` | CGO disabled | `export CGO_ENABLED=1` |
| PHP: `FFI API is restricted` | `ffi.enable` off | `php -d ffi.enable=1` or enable in `php.ini` |
| `invalid parameter` on CAdES-C/X/LT | Empty ref cert / CRL / OCSP | Pass non-empty DER blobs |
| Verify fails after sign | Wrong payload passed to `VerifyCMS` | Verify against the **same** `data` bytes that were signed |
| Version mismatch | Stale native lib | Rebuild FFI and sync; check `library_version()` |

---

## Tests and examples

```bash
make go-test
make python-test
make php-test      # PHP 8.1+, ffi.enable=1
make node-test
```

Integration vectors live under `testdata/` (Cryptonite KAT). Go MVP test: `go/uacryptex/mvp_test.go`.

---

## Related documentation

| Topic | Document |
|-------|----------|
| API ↔ FFI symbol map | [API_INVENTORY.md](API_INVENTORY.md) |
| Build matrix & parity table | [BINDINGS.md](BINDINGS.md) |
| C function signatures | [FFI.md](FFI.md) |
| Release & registries | [PUBLISHING.md](PUBLISHING.md) |
| Planned CAdES-X-L Type 1/2 | [ROADMAP.md](ROADMAP.md#todo) |
