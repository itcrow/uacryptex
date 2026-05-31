# uacryptex Python bindings

Idiomatic Python API over the stable C ABI (`uacryptex-ffi`).

**Full guide (all languages):** [docs/CLIENT_LIBRARIES.md](../docs/CLIENT_LIBRARIES.md)

## Prerequisites

Build the native shared library from the repository root:

```bash
./scripts/build-ffi.sh
```

Or set `UACRYPTEX_LIB` to `libuacryptex_ffi.so` / `.dylib` / `.dll`.

## Install (editable)

```bash
cd python
pip install -e .
```

## Usage

```python
import uacryptex

print(uacryptex.library_version())

with uacryptex.open_pkcs12(p12_bytes, "password") as ks:
    key = ks.private_key()
    cms = uacryptex.sign_cms(b"payload", key)
    uacryptex.verify_cms(b"payload", cms)
```

### PKI helpers (selection)

| Area | Functions |
|------|-----------|
| Digest / sign | `digest`, `sign_data`, `verify_hash`, `verify_data` |
| Certificates | `verify_certificate`, `check_certificate_validity`, `generate_certificate` |
| CRL | `verify_crl`, `is_certificate_revoked`, `generate_crl` |
| OCSP | `ocsp_request_from_cert`, `ocsp_request_generate`, `ocsp_response_verify` |
| TSP / CSR | `tsp_request_from_data`, `tsp_response_generate`, `csr_generate`, `csr_verify` |
| CMS | `sign_cms`, `verify_cms`, `envelop_cms`, `decrypt_cms` |
| CMS CAdES-T | `sign_cms_cades_t` |
| Low-level | `verify_dstu4145_pb` |

Signed OCSP request example:

```python
key = uacryptex.open_private_key(user_key, user_cert)
req = uacryptex.ocsp_request_generate(
    root_cert, user_cert, requestor_key=key, ocsp_responder_cert=ocsp_cert
)
```

## Tests

```bash
cd python && python tests/test_version.py
```

Requires a built native library under `../native/lib/{platform}/{arch}/`.
