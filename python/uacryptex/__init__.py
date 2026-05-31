"""Ukrainian cryptography for Python — DSTU/GOST PKI via uacryptex Rust core."""

from __future__ import annotations

from . import _native
from .errors import (
    AllocationError,
    InvalidParamError,
    UacryptexError,
    VerifyFailedError,
)

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "UacryptexError",
    "AllocationError",
    "InvalidParamError",
    "VerifyFailedError",
    "library_version",
    "PrivateKey",
    "Keystore",
    "open_private_key",
    "open_pkcs12",
    "open_pkcs8",
    "sign_cms",
    "sign_cms_cades_t",
    "sign_cms_cades_c",
    "sign_cms_cades_x",
    "sign_cms_cades_lt",
    "sign_cms_cades_a",
    "verify_cms",
    "envelop_cms",
    "decrypt_cms",
    "digest",
    "sign_data",
    "verify_hash",
    "verify_data",
    "verify_certificate",
    "check_certificate_validity",
    "certificate_spki",
    "verify_crl",
    "is_certificate_revoked",
    "CRL_TYPE_DELTA",
    "CRL_TYPE_FULL",
    "generate_crl",
    "verify_dstu4145_pb",
    "ocsp_request_from_cert",
    "ocsp_request_generate",
    "ocsp_response_verify",
    "tsp_request_from_data",
    "tsp_response_verify",
    "tsp_response_generate",
    "csr_generate",
    "csr_verify",
    "generate_certificate",
]


def library_version() -> str:
    """Return the Rust core version string."""
    return _native.version()


class PrivateKey:
    """Signing key backed by uacryptex-core (DSTU4145, ECDSA, …)."""

    def __init__(self, handle):
        self._handle = handle

    def close(self) -> None:
        if self._handle is not None:
            _native.handle_free(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def sign_hash(self, digest: bytes) -> bytes:
        if self._handle is None:
            raise InvalidParamError("closed private key")
        return _native.sign_hash(self._handle, digest)

    def sign_data(self, data: bytes) -> bytes:
        if self._handle is None:
            raise InvalidParamError("closed private key")
        return _native.sign_data(self._handle, data)


class Keystore:
    """Opened PKCS#12 container with a selected private key."""

    def __init__(self, handle):
        self._handle = handle
        self._owns_handle = True

    def close(self) -> None:
        if self._owns_handle and self._handle is not None:
            _native.handle_free(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def set_certificate(self, cert: bytes) -> None:
        if self._handle is None:
            raise InvalidParamError("closed keystore")
        _native.set_certificate(self._handle, cert)

    def private_key(self) -> PrivateKey:
        if self._handle is None:
            raise InvalidParamError("closed keystore")
        key = PrivateKey(self._handle)
        key._handle = self._handle  # shared handle; keystore owns free
        return key

    def certificate_count(self) -> int:
        if self._handle is None:
            raise InvalidParamError("closed keystore")
        return _native.pkcs12_certificate_count(self._handle)

    def get_certificate(self, index: int) -> bytes:
        if self._handle is None:
            raise InvalidParamError("closed keystore")
        return _native.pkcs12_get_certificate(self._handle, index)


def open_private_key(key: bytes, cert: bytes) -> PrivateKey:
    """Create a signing key from raw private key bytes and a DER certificate."""
    return PrivateKey(_native.sign_open(key, cert))


def open_pkcs12(data: bytes, password: str) -> Keystore:
    """Open a PKCS#12 keystore and select the first available private key."""
    return Keystore(_native.pkcs12_open(data, password))


def open_pkcs8(der: bytes, cert: bytes | None = None) -> PrivateKey:
    """Open a signing key from PKCS#8 PrivateKeyInfo DER."""
    return PrivateKey(_native.pkcs8_open(der, cert))


def digest(data: bytes, algorithm_aid: bytes | None = None, cert: bytes | None = None) -> bytes:
    """Compute GOST3411 (default) or cert/AlgorithmIdentifier-selected digest."""
    return _native.digest(data, algorithm_aid, cert)


def sign_data(data: bytes, key: PrivateKey) -> bytes:
    """Sign raw data (hash-then-sign)."""
    if key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.sign_data(key._handle, data)


def verify_hash(digest: bytes, signature: bytes, cert: bytes) -> None:
    """Verify a detached signature over a digest."""
    _native.verify_hash(digest, signature, cert)


def verify_data(data: bytes, signature: bytes, cert: bytes) -> None:
    """Verify a detached signature over raw data."""
    _native.verify_data(data, signature, cert)


def verify_certificate(cert: bytes, issuer_cert: bytes) -> None:
    """Verify certificate signature using issuer certificate."""
    _native.cert_verify(cert, issuer_cert)


def check_certificate_validity(cert: bytes, unix_secs: int = 0) -> None:
    """Check certificate notBefore/notAfter (0 = now)."""
    _native.cert_check_validity(cert, unix_secs)


def certificate_spki(cert: bytes) -> bytes:
    """Return SubjectPublicKeyInfo DER from certificate."""
    return _native.cert_spki(cert)


def verify_crl(crl: bytes, issuer_cert: bytes) -> None:
    """Verify CRL signature using issuer certificate."""
    _native.crl_verify(crl, issuer_cert)


def is_certificate_revoked(crl: bytes, issuer_cert: bytes, cert: bytes) -> bool:
    """Return True when cert is revoked by crl."""
    return _native.crl_check_cert(crl, issuer_cert, cert)


CRL_TYPE_DELTA = 0
CRL_TYPE_FULL = 1


def generate_crl(
    key: PrivateKey,
    previous_crl: bytes,
    crl_type: int,
    diff_next_update_secs: int,
    merge_delta_crl: bytes | None = None,
    revoke_serial: bytes | None = None,
    template_name: str = "",
    description: str = "",
) -> bytes:
    """Issue a new CRL from previous_crl using CA private key."""
    if key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.crl_generate(
        key._handle,
        previous_crl,
        crl_type,
        diff_next_update_secs,
        merge_delta_crl,
        revoke_serial,
        template_name,
        description,
    )


def verify_dstu4145_pb(
    f: list[int],
    a: int,
    b: bytes,
    n: bytes,
    gx: bytes,
    gy: bytes,
    qx: bytes,
    qy: bytes,
    hash_: bytes,
    r: bytes,
    s: bytes,
) -> None:
    """Verify DSTU 4145 signature over GF(2^m) in polynomial basis."""
    _native.dstu4145_verify_pb(f, a, b, n, gx, gy, qx, qy, hash_, r, s)


def ocsp_request_from_cert(root_cert: bytes, user_cert: bytes) -> bytes:
    return _native.ocsp_request_from_cert(root_cert, user_cert)


def ocsp_request_generate(
    root_cert: bytes,
    user_cert: bytes,
    requestor_key: PrivateKey | None = None,
    ocsp_responder_cert: bytes | None = None,
    nonce: bytes | None = None,
    include_nonce: bool = True,
) -> bytes:
    handle = requestor_key._handle if requestor_key is not None else None
    if requestor_key is not None and handle is None:
        raise InvalidParamError("closed private key")
    return _native.ocsp_request_generate(
        root_cert, user_cert, handle, ocsp_responder_cert, nonce, include_nonce
    )


def ocsp_response_verify(response: bytes, ocsp_responder_cert: bytes) -> None:
    _native.ocsp_response_verify(response, ocsp_responder_cert)


def tsp_request_from_data(data: bytes, policy_oid: str | None = None, cert_req: bool = True) -> bytes:
    return _native.tsp_request_from_data(data, policy_oid, cert_req)


def tsp_response_verify(response: bytes, tsa_cert: bytes) -> None:
    _native.tsp_response_verify(response, tsa_cert)


def tsp_response_generate(key: PrivateKey, request: bytes, serial: bytes, current_time: int) -> bytes:
    if key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.tsp_response_generate(key._handle, request, serial, current_time)


def csr_generate(key: PrivateKey, subject: str, dns: str | None = None, email: str | None = None) -> bytes:
    if key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.csr_generate(key._handle, subject, dns, email)


def csr_verify(csr: bytes) -> None:
    _native.csr_verify(csr)


def generate_certificate(
    key: PrivateKey,
    csr: bytes,
    version: int,
    serial: bytes,
    not_before: int,
    not_after: int,
    self_signed: bool = False,
) -> bytes:
    if key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.cert_generate(key._handle, csr, version, serial, not_before, not_after, self_signed)


def sign_cms(data: bytes, key: PrivateKey) -> bytes:
    """Sign data and return a CMS SignedData structure (CAdES-BES subset)."""
    if key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.cms_sign(key._handle, data)


def sign_cms_cades_t(
    data: bytes,
    sign_key: PrivateKey,
    tsa_key: PrivateKey,
    serial: bytes,
    current_time: int,
    policy_oid: str | None = None,
) -> bytes:
    """Sign data and return CAdES-T CMS (BES + signature timestamp token)."""
    if sign_key._handle is None or tsa_key._handle is None:
        raise InvalidParamError("closed private key")
    return _native.cms_sign_cades_t(
        sign_key._handle, tsa_key._handle, data, serial, current_time, policy_oid
    )


def sign_cms_cades_c(
    data: bytes,
    sign_key: PrivateKey,
    ref_cert: bytes,
    ref_crl: bytes,
) -> bytes:
    """Sign data and return CAdES-C CMS (BES + certificate/revocation references)."""
    if sign_key._handle is None:
        raise InvalidParamError("closed private key")
    if not ref_cert or not ref_crl:
        raise InvalidParamError("reference certificate and CRL required")
    return _native.cms_sign_cades_c(sign_key._handle, data, ref_cert, ref_crl)


def sign_cms_cades_x(
    data: bytes,
    sign_key: PrivateKey,
    ref_cert: bytes,
    ocsp_response: bytes,
) -> bytes:
    """Sign data and return CAdES-X CMS (BES + certificate/revocation values)."""
    if sign_key._handle is None:
        raise InvalidParamError("closed private key")
    if not ref_cert or not ocsp_response:
        raise InvalidParamError("reference certificate and OCSP response required")
    return _native.cms_sign_cades_x(sign_key._handle, data, ref_cert, ocsp_response)


def sign_cms_cades_lt(
    data: bytes,
    sign_key: PrivateKey,
    ref_cert: bytes,
    full_crl: bytes,
    ocsp_response: bytes,
    delta_crl: bytes = b"",
) -> bytes:
    """Sign data and return CAdES-LT CMS (X + validation data in SignedData)."""
    if sign_key._handle is None:
        raise InvalidParamError("closed private key")
    if not ref_cert or not full_crl or not ocsp_response:
        raise InvalidParamError("reference certificate, CRL and OCSP response required")
    return _native.cms_sign_cades_lt(
        sign_key._handle, data, ref_cert, full_crl, delta_crl, ocsp_response
    )


def sign_cms_cades_a(
    data: bytes,
    sign_key: PrivateKey,
    tsa_key: PrivateKey,
    ref_cert: bytes,
    full_crl: bytes,
    ocsp_response: bytes,
    serial: bytes,
    current_time: int,
    delta_crl: bytes = b"",
    policy_oid: str | None = None,
) -> bytes:
    """Sign data and return CAdES-A CMS (LT + archive timestamp)."""
    if sign_key._handle is None or tsa_key._handle is None:
        raise InvalidParamError("closed private key")
    if not ref_cert or not full_crl or not ocsp_response:
        raise InvalidParamError("reference certificate, CRL and OCSP response required")
    return _native.cms_sign_cades_a(
        sign_key._handle,
        tsa_key._handle,
        data,
        ref_cert,
        full_crl,
        delta_crl,
        ocsp_response,
        serial,
        current_time,
        policy_oid,
    )


def verify_cms(data: bytes, cms: bytes) -> None:
    """Verify a CMS SignedData signature over data."""
    _native.cms_verify(data, cms)


def envelop_cms(data: bytes, originator_key: PrivateKey, recipient_cert: bytes) -> bytes:
    """Encrypt data for recipient_cert using originator_key (DSTU4145 DH + GOST28147-CFB)."""
    if originator_key._handle is None:
        raise InvalidParamError("closed private key")
    if not recipient_cert:
        raise InvalidParamError("recipient certificate required")
    return _native.cms_envelop_encrypt(originator_key._handle, data, recipient_cert)


def decrypt_cms(
    cms: bytes,
    recipient_key: PrivateKey,
    recipient_cert: bytes,
    originator_cert: bytes | None = None,
    external: bytes | None = None,
) -> bytes:
    """Decrypt PKCS#7 EnvelopedData using recipient_key and recipient_cert."""
    if recipient_key._handle is None:
        raise InvalidParamError("closed private key")
    if not cms or not recipient_cert:
        raise InvalidParamError("cms and recipient certificate required")
    return _native.cms_envelop_decrypt(
        recipient_key._handle, cms, external, originator_cert, recipient_cert
    )
