# uacryptex FFI contract

> **Languages:** English · [Українська](uk/FFI.md)

Stable C ABI between `uacryptex-ffi` (Rust) and language bindings:

| Binding | Internal layer |
|---------|----------------|
| Go | `go/uacryptex/internal/native` (cgo) |
| Python | `python/uacryptex/_native.py` (ctypes) |
| PHP | `php/src/Native.php` (FFI) |
| Node.js | `nodejs/lib/native.js` (koffi) |

Header source: `cbindgen` from `crates/uacryptex-ffi`. Sync script copies to Go tree.

## Types

```c
typedef struct {
    uint8_t *ptr;
    size_t len;
} UacryptexBuf;

typedef struct {
    int32_t code;
    char message[256];
} UacryptexError;

typedef struct UacryptexHandle UacryptexHandle;
```

## Error codes

Aligned with Cryptonite `RET_*` where applicable:

| Code | Name | Meaning |
|------|------|---------|
| 0 | OK | Success |
| 1 | MEMORY | Allocation failed |
| 2 | INVALID_PARAM | Bad argument |
| 3 | VERIFY_FAILED | Signature/CMS verify failed |
| … | … | See `uacryptex-core::Error` |

## Lifecycle

```c
// Always safe to call on zero-init struct
void uacryptex_error_init(UacryptexError *err);

// Frees buffer returned by any uacryptex_* function
void uacryptex_buf_free(UacryptexBuf buf);

// Frees opaque handle (key, pkcs12 session, etc.)
void uacryptex_handle_free(UacryptexHandle *handle);
```

## Core functions (Phase 0 — implemented)

```c
int32_t uacryptex_version(char *out, size_t cap);
```

### Phase 1 — DSTU 4145 verify (polynomial basis)

```c
int32_t uacryptex_dstu4145_verify_pb(
    const uint32_t *f, size_t f_len, int32_t a,
    const uint8_t *b, size_t b_len,
    const uint8_t *n, size_t n_len,
    const uint8_t *gx, size_t gx_len, const uint8_t *gy, size_t gy_len,
    const uint8_t *qx, size_t qx_len, const uint8_t *qy, size_t qy_len,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len,
    UacryptexError *err
);
```

**Octet encoding (Cryptonite-compatible):**

| Argument | Cryptonite equivalent |
|----------|----------------------|
| `b`, `n`, `gx`, `gy`, `qx`, `qy`, `hash` | `ba_alloc_from_be_hex_string` → `ByteArray` |
| `r`, `s` | `ba_alloc_from_le_hex_string` → `ByteArray` |

Returns `0` (`RET_OK`) when the signature is valid.

### Phase 2 — PKI / storage (implemented)

```c
int32_t uacryptex_pkcs12_open(
    const uint8_t *data, size_t len,
    const char *password,
    UacryptexHandle **store,
    UacryptexError *err
);

int32_t uacryptex_pkcs12_set_certificates(
    UacryptexHandle *store,
    const uint8_t *cert, size_t cert_len,
    UacryptexError *err
);

int32_t uacryptex_sign_open(
    const uint8_t *key, size_t key_len,
    const uint8_t *cert, size_t cert_len,
    UacryptexHandle **out,
    UacryptexError *err
);

int32_t uacryptex_sign_hash(
    const uint8_t *hash, size_t hash_len,
    UacryptexHandle *key,
    UacryptexBuf *out,
    UacryptexError *err
);

int32_t uacryptex_cms_sign(
    const uint8_t *data, size_t data_len,
    UacryptexHandle *key,
    UacryptexBuf *out,
    UacryptexError *err
);

int32_t uacryptex_cms_verify(
    const uint8_t *data, size_t data_len,
    const uint8_t *cms, size_t cms_len,
    UacryptexError *err
);

int32_t uacryptex_cms_envelop_encrypt(
    const uint8_t *data, size_t data_len,
    UacryptexHandle *originator_key,
    const uint8_t *recipient_cert, size_t recipient_cert_len,
    UacryptexBuf *out,
    UacryptexError *err
);

int32_t uacryptex_cms_envelop_encrypt_with_cipher(
    const uint8_t *data, size_t data_len,
    UacryptexHandle *originator_key,
    const uint8_t *recipient_cert, size_t recipient_cert_len,
    int32_t content_cipher,
    UacryptexBuf *out,
    UacryptexError *err
);

int32_t uacryptex_cms_envelop_decrypt(
    const uint8_t *cms, size_t cms_len,
    const uint8_t *external, size_t external_len,
    const uint8_t *originator_cert, size_t originator_cert_len,
    UacryptexHandle *recipient_key,
    const uint8_t *recipient_cert, size_t recipient_cert_len,
    UacryptexBuf *out,
    UacryptexError *err
);
```

`uacryptex_cms_envelop_encrypt` uses GOST28147-CFB content encryption and DSTU4145 DH key agreement (originator cert embedded in CMS). Decrypt with `originator_cert_len == 0` when the originator is embedded; `external_len == 0` when ciphertext is inside the structure.

`uacryptex_cms_envelop_encrypt_with_cipher` selects the content encryption algorithm via `content_cipher`. Key agreement remains DSTU4145 DH with GOST28147-Wrap; decrypt reads the cipher from the CMS OID (same `uacryptex_cms_envelop_decrypt` for all variants).

| Constant | Value | Content encryption |
|----------|------:|--------------------|
| `UACRYPTEX_CONTENT_CIPHER_GOST28147_CFB` | 0 | GOST 28147-CFB (default, Cryptonite-compatible) |
| `UACRYPTEX_CONTENT_CIPHER_KALYNA256_GCM` | 1 | DSTU 7624 Kalyna-256/256-GMAC-256 (AEAD GCM) |
| `UACRYPTEX_CONTENT_CIPHER_KALYNA128_GCM` | 2 | DSTU 7624 Kalyna-128/128-GMAC-128 (AEAD GCM) |
| `UACRYPTEX_CONTENT_CIPHER_KALYNA512_GCM` | 3 | DSTU 7624 Kalyna-512/512-GMAC-512 (AEAD GCM) |

Kalyna-128 wraps a 32-byte CEK with GOST28147-Wrap and uses the first 16 bytes as the cipher key. Kalyna-512 uses a 64-byte CEK wrapped as two GOST28147-Wrap blocks (88 bytes in `encrypted_key`).

`uacryptex_cms_sign` accepts handles from `uacryptex_pkcs12_open` (when a matching certificate is bound) or `uacryptex_sign_open`.

### Phase 3 — Digest, detached sign/verify, PKCS#8, cert/CRL (implemented)

```c
int32_t uacryptex_digest(
    const uint8_t *data, size_t data_len,
    const uint8_t *algorithm_aid, size_t algorithm_aid_len,
    const uint8_t *cert, size_t cert_len,
    UacryptexBuf *out, UacryptexError *err
);

int32_t uacryptex_sign_data(
    const uint8_t *data, size_t data_len,
    UacryptexHandle *key,
    UacryptexBuf *out, UacryptexError *err
);

int32_t uacryptex_dstu4145_sign(...);   /* alias for uacryptex_sign_hash */

int32_t uacryptex_verify_hash(
    const uint8_t *digest, size_t digest_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *cert, size_t cert_len,
    UacryptexError *err
);

int32_t uacryptex_verify_data(...);     /* hash-then-verify over raw data */
int32_t uacryptex_dstu4145_verify(...); /* alias for uacryptex_verify_hash */

int32_t uacryptex_pkcs8_open(
    const uint8_t *der, size_t der_len,
    const uint8_t *cert, size_t cert_len,
    UacryptexHandle **out, UacryptexError *err
);

int32_t uacryptex_pkcs12_certificate_count(
    UacryptexHandle *store, size_t *count, UacryptexError *err
);

int32_t uacryptex_pkcs12_get_certificate(
    UacryptexHandle *store, size_t index,
    UacryptexBuf *out, UacryptexError *err
);

int32_t uacryptex_cert_verify(cert, issuer_cert, err);
int32_t uacryptex_cert_check_validity(cert, unix_secs, err);  /* 0 = now */
int32_t uacryptex_cert_spki(cert, out, err);

int32_t uacryptex_crl_verify(crl, issuer_cert, err);
int32_t uacryptex_crl_check_cert(crl, issuer_cert, cert, &revoked, err);
```

Cert/CRL helpers are stateless (DER in/out). PKCS#8 and detached sign/verify use the same `UacryptexHandle` as CMS.

### Phase 4 — OCSP, TSP, CSR (implemented)

```c
int32_t uacryptex_ocsp_request_from_cert(...);
int32_t uacryptex_ocsp_request_verify(...);
int32_t uacryptex_ocsp_response_verify(...);
int32_t uacryptex_ocsp_response_validate(...);
int32_t uacryptex_ocsp_response_generate(...);  /* ocsp responder key handle */

int32_t uacryptex_tsp_request_from_data(...);   /* policy NULL → DSTU PB TSP policy */
int32_t uacryptex_tsp_request_from_hash(...);
int32_t uacryptex_tsp_response_verify(...);
int32_t uacryptex_tsp_response_generate(...);   /* TSA key handle */

int32_t uacryptex_csr_generate(...);            /* Cryptonite subject string */
int32_t uacryptex_csr_verify(...);

int32_t uacryptex_cert_generate(...);           /* CSR + CA/self-signed key handle */

int32_t uacryptex_crl_generate(...);            /* previous CRL + CA key handle */
```

### Phase 5 — Advanced CMS / PKI (partial)

```c
int32_t uacryptex_crl_generate(ca_key, previous_crl, crl_type, diff_next_update_secs,
                               merge_delta_crl, revoke_serial, template_name, description, out, err);
```

`crl_type`: 0 = delta, 1 = full. `diff_next_update_secs` > 0 → `ecrl_generate_diff_next_update`; else `ecrl_generate`.

High-level bindings: `generate_crl` / `GenerateCRL`, `verify_dstu4145_pb` / `VerifyDstu4145PB`.

```c
int32_t uacryptex_ocsp_request_generate(root_cert, user_cert, requestor_key,
                                        ocsp_responder_cert, nonce, include_nonce, out, err);
```

`requestor_key` NULL → unsigned; non-NULL → signed request with optional OCSP responder cert in chain.
Bindings: `ocsp_request_generate` / `OcspRequestGenerate`.

```c
int32_t uacryptex_cms_sign_cades_t(data, sign_key, tsa_key, serial, current_time, policy_oid, out, err);
```

CAdES-T: BES CMS + TSP token as `id-aa-signatureTimeStampToken` unsigned attribute.
Bindings: `sign_cms_cades_t` / `SignCmsCadesT`.

```c
int32_t uacryptex_cms_sign_cades_c(data, sign_key, ref_cert, ref_crl, out, err);
```

CAdES-C: BES CMS + `id-aa-ets-certificateRefs` and `id-aa-ets-revocationRefs` (hashes of issuer cert DER and CRL DER).
Bindings: `sign_cms_cades_c` / `SignCmsCadesC`.

```c
int32_t uacryptex_cms_sign_cades_x(data, sign_key, ref_cert, ocsp_response, out, err);
```

CAdES-X: BES CMS + `id-aa-ets-certValues` and `id-aa-ets-revocationValues` (embedded cert + OCSP response).
Bindings: `sign_cms_cades_x` / `SignCmsCadesX`.

```c
int32_t uacryptex_cms_sign_cades_lt(data, sign_key, ref_cert, full_crl, delta_crl, ocsp_response, out, err);
```

CAdES-LT: CAdES-X Long (refs + values + validation certificates/CRLs in SignedData). `delta_crl` optional when `delta_crl_len == 0`.
Bindings: `sign_cms_cades_lt` / `SignCmsCadesLT`.

```c
int32_t uacryptex_cms_sign_cades_xl_type1(data, sign_key, ref_cert, full_crl, delta_crl, ocsp_response,
    tsa_key, serial, current_time, policy_oid, out, err);
int32_t uacryptex_cms_sign_cades_xl_type2(data, sign_key, ref_cert, full_crl, delta_crl, ocsp_response,
    tsa_key, serial, current_time, policy_oid, out, err);
```

CAdES-X Long Type 1: LT + `id-aa-ets-escTimeStamp` (timestamp over CAdES-C imprint per RFC 5126 §6.3.5).
CAdES-X Long Type 2: LT + `id-aa-ets-certCRLTimestamp` (timestamp over certificate/revocation refs per §6.3.6).
Bindings (Go): `SignCmsCadesXLType1` / `SignCmsCadesXLType2`.

```c
int32_t uacryptex_cms_sign_cades_a(data, sign_key, ref_cert, full_crl, delta_crl, ocsp_response,
    tsa_key, serial, current_time, policy_oid, out, err);
```

CAdES-A: CAdES-LT + `id-aa-ets-archiveTimeStamp` (archive imprint per ETSI CAdES-A).
Bindings: `sign_cms_cades_a` / `SignCmsCadesA` (Go, Python, PHP, Node).

## Planned functions (by phase)

### Phase 5 — Advanced CMS / PKI (remaining)

(none — CAdES-X-L Type 1/2 implemented; see `uacryptex_cms_sign_cades_xl_type1` / `_type2` above)

### Phase 1 — Primitives (remaining)

```c
/* ONB-basis DSTU4145 verify; low-level GF(2^m) only today */
```

Remove old planned dstu4145_sign/verify from phase 1 since implemented as aliases above - I replaced that section.

## Rules for FFI authors

1. All functions return `int32_t` status (`0` = OK).
2. Output errors via `UacryptexError *err` when `err != NULL`.
3. No exceptions across boundary.
4. No Rust `String` / `Vec` pointers without `UacryptexBuf` wrapper.
5. Thread safety documented per handle type; default: one handle per goroutine or external lock.

## Regenerating header

```bash
./scripts/sync-header.sh
# runs: cbindgen crates/uacryptex-ffi -o include/uacryptex.h
# copies to go/uacryptex/internal/native/uacryptex.h
```
