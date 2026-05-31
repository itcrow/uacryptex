"""Low-level ctypes wrapper for uacryptex C ABI."""

from __future__ import annotations

import os
import platform
from ctypes import (
    CDLL,
    POINTER,
    Structure,
    c_char,
    c_char_p,
    c_int32,
    c_int64,
    c_size_t,
    c_uint8,
    c_uint32,
    c_void_p,
    create_string_buffer,
)
from pathlib import Path

from .errors import RET_OK, map_native_error

Handle = c_void_p


class UacryptexBuf(Structure):
    _fields_ = [("ptr", c_void_p), ("len", c_size_t)]


class UacryptexError(Structure):
    _fields_ = [("code", c_int32), ("message", c_char * 256)]


def _platform_dir() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "linux", "darwin": "darwin"}.get(system, "windows")
    arch = "arm64" if machine in ("aarch64", "arm64") else "amd64"
    return os_name, arch


def _lib_filename(os_name: str) -> str:
    if os_name == "windows":
        return "uacryptex_ffi.dll"
    if os_name == "darwin":
        return "libuacryptex_ffi.dylib"
    return "libuacryptex_ffi.so"


def _lib_candidates() -> list[Path]:
    os_name, arch = _platform_dir()
    name = _lib_filename(os_name)
    shared = Path("native") / "lib" / os_name / arch / "shared" / name
    pkg = Path(__file__).resolve().parent
    repo = pkg.parents[2]
    return [
        pkg / shared,
        repo / "native" / "lib" / os_name / arch / "shared" / name,
    ]


def default_lib_path() -> Path:
    for candidate in _lib_candidates():
        if candidate.is_file():
            return candidate
    return _lib_candidates()[0]


def load_library(path: str | Path | None = None) -> CDLL:
    if path:
        lib_path = Path(path)
    elif os.environ.get("UACRYPTEX_LIB"):
        lib_path = Path(os.environ["UACRYPTEX_LIB"])
    else:
        lib_path = default_lib_path()
    if not lib_path.is_file():
        tried = ", ".join(str(p) for p in _lib_candidates())
        raise OSError(
            f"uacryptex native library not found: {lib_path}. "
            f"Tried: {tried}. Run ./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh "
            "or set UACRYPTEX_LIB."
        )
    lib = CDLL(str(lib_path))

    lib.uacryptex_error_init.argtypes = [POINTER(UacryptexError)]
    lib.uacryptex_error_init.restype = None

    lib.uacryptex_buf_free.argtypes = [UacryptexBuf]
    lib.uacryptex_buf_free.restype = None

    lib.uacryptex_handle_free.argtypes = [Handle]
    lib.uacryptex_handle_free.restype = None

    lib.uacryptex_version.argtypes = [c_char_p, c_size_t]
    lib.uacryptex_version.restype = c_int32

    lib.uacryptex_sign_open.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(Handle),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_sign_open.restype = c_int32

    lib.uacryptex_pkcs12_open.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        c_char_p,
        POINTER(Handle),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_pkcs12_open.restype = c_int32

    lib.uacryptex_pkcs12_set_certificates.argtypes = [
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_pkcs12_set_certificates.restype = c_int32

    lib.uacryptex_sign_hash.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_sign_hash.restype = c_int32

    lib.uacryptex_cms_sign.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_sign.restype = c_int32

    lib.uacryptex_cms_sign_cades_t.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        c_int64,
        c_char_p,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_sign_cades_t.restype = c_int32

    lib.uacryptex_cms_sign_cades_c.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_sign_cades_c.restype = c_int32

    lib.uacryptex_cms_sign_cades_x.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_sign_cades_x.restype = c_int32

    lib.uacryptex_cms_sign_cades_lt.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_sign_cades_lt.restype = c_int32

    lib.uacryptex_cms_sign_cades_a.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        c_int64,
        c_char_p,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_sign_cades_a.restype = c_int32

    lib.uacryptex_cms_verify.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_verify.restype = c_int32

    lib.uacryptex_cms_envelop_encrypt.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_envelop_encrypt.restype = c_int32

    lib.uacryptex_cms_envelop_decrypt.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cms_envelop_decrypt.restype = c_int32

    lib.uacryptex_digest.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_digest.restype = c_int32

    lib.uacryptex_sign_data.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_sign_data.restype = c_int32

    lib.uacryptex_pkcs8_open.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(Handle),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_pkcs8_open.restype = c_int32

    lib.uacryptex_verify_hash.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_verify_hash.restype = c_int32

    lib.uacryptex_verify_data.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_verify_data.restype = c_int32

    lib.uacryptex_cert_verify.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cert_verify.restype = c_int32

    lib.uacryptex_cert_check_validity.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        c_int64,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cert_check_validity.restype = c_int32

    lib.uacryptex_cert_spki.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_cert_spki.restype = c_int32

    lib.uacryptex_crl_verify.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_crl_verify.restype = c_int32

    lib.uacryptex_crl_check_cert.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_int32),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_crl_check_cert.restype = c_int32

    lib.uacryptex_crl_generate.argtypes = [
        Handle,
        POINTER(c_uint8),
        c_size_t,
        c_int32,
        c_int64,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        c_char_p,
        c_char_p,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_crl_generate.restype = c_int32

    lib.uacryptex_dstu4145_verify_pb.argtypes = [
        POINTER(c_uint32),
        c_size_t,
        c_int32,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        POINTER(UacryptexError),
    ]
    lib.uacryptex_dstu4145_verify_pb.restype = c_int32

    lib.uacryptex_pkcs12_certificate_count.argtypes = [
        Handle,
        POINTER(c_size_t),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_pkcs12_certificate_count.restype = c_int32

    lib.uacryptex_pkcs12_get_certificate.argtypes = [
        Handle,
        c_size_t,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_pkcs12_get_certificate.restype = c_int32

    lib.uacryptex_ocsp_request_from_cert.restype = c_int32

    lib.uacryptex_ocsp_request_generate.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        Handle,
        POINTER(c_uint8),
        c_size_t,
        POINTER(c_uint8),
        c_size_t,
        c_int32,
        POINTER(UacryptexBuf),
        POINTER(UacryptexError),
    ]
    lib.uacryptex_ocsp_request_generate.restype = c_int32

    lib.uacryptex_ocsp_response_verify.restype = c_int32
    lib.uacryptex_tsp_request_from_data.restype = c_int32
    lib.uacryptex_tsp_response_verify.restype = c_int32
    lib.uacryptex_tsp_response_generate.restype = c_int32
    lib.uacryptex_csr_generate.restype = c_int32
    lib.uacryptex_csr_verify.restype = c_int32

    lib.uacryptex_cert_generate.restype = c_int32

    return lib


_lib: CDLL | None = None


def get_lib() -> CDLL:
    global _lib
    if _lib is None:
        _lib = load_library()
    return _lib


def _init_error() -> UacryptexError:
    err = UacryptexError()
    get_lib().uacryptex_error_init(err)
    return err


def _check(code: int, err: UacryptexError) -> None:
    msg = err.message.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    exc = map_native_error(code, msg)
    if exc is not None:
        raise exc


def _bytes_ptr(data: bytes | None):
    if not data:
        return None, 0
    buf = (c_uint8 * len(data)).from_buffer_copy(data)
    return buf, len(data)


def _buf_to_bytes(buf: UacryptexBuf) -> bytes:
    if not buf.ptr or buf.len == 0:
        get_lib().uacryptex_buf_free(buf)
        return b""
    out = bytes((c_uint8 * buf.len).from_address(buf.ptr))
    get_lib().uacryptex_buf_free(buf)
    return out


def version() -> str:
    lib = get_lib()
    buf = create_string_buffer(64)
    code = lib.uacryptex_version(buf, len(buf))
    if code != RET_OK:
        raise OSError(f"uacryptex_version failed with code {code}")
    return buf.value.decode("utf-8")


def sign_open(key: bytes, cert: bytes) -> Handle:
    lib = get_lib()
    key_buf, key_len = _bytes_ptr(key)
    cert_buf, cert_len = _bytes_ptr(cert)
    out = Handle()
    err = _init_error()
    code = lib.uacryptex_sign_open(key_buf, key_len, cert_buf, cert_len, out, err)
    _check(code, err)
    return out


def pkcs12_open(data: bytes, password: str) -> Handle:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    out = Handle()
    err = _init_error()
    code = lib.uacryptex_pkcs12_open(data_buf, data_len, password.encode("utf-8"), out, err)
    _check(code, err)
    return out


def handle_free(handle: Handle | None) -> None:
    if handle:
        get_lib().uacryptex_handle_free(handle)


def set_certificate(handle: Handle, cert: bytes) -> None:
    lib = get_lib()
    cert_buf, cert_len = _bytes_ptr(cert)
    err = _init_error()
    code = lib.uacryptex_pkcs12_set_certificates(handle, cert_buf, cert_len, err)
    _check(code, err)


def sign_hash(handle: Handle, digest: bytes) -> bytes:
    lib = get_lib()
    digest_buf, digest_len = _bytes_ptr(digest)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_sign_hash(digest_buf, digest_len, handle, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def cms_sign(handle: Handle, data: bytes) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_sign(data_buf, data_len, handle, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def cms_sign_cades_t(
    sign_key: Handle,
    tsa_key: Handle,
    data: bytes,
    serial: bytes,
    current_time: int,
    policy_oid: str | None = None,
) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    serial_buf, serial_len = _bytes_ptr(serial)
    policy = policy_oid.encode("utf-8") if policy_oid else None
    policy_buf, _ = _bytes_ptr(policy)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_sign_cades_t(
        data_buf,
        data_len,
        sign_key,
        tsa_key,
        serial_buf,
        serial_len,
        c_int64(current_time),
        policy_buf,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def cms_sign_cades_c(
    sign_key: Handle,
    data: bytes,
    ref_cert: bytes,
    ref_crl: bytes,
) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    cert_buf, cert_len = _bytes_ptr(ref_cert)
    crl_buf, crl_len = _bytes_ptr(ref_crl)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_sign_cades_c(
        data_buf,
        data_len,
        sign_key,
        cert_buf,
        cert_len,
        crl_buf,
        crl_len,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def cms_sign_cades_x(
    sign_key: Handle,
    data: bytes,
    ref_cert: bytes,
    ocsp_response: bytes,
) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    cert_buf, cert_len = _bytes_ptr(ref_cert)
    ocsp_buf, ocsp_len = _bytes_ptr(ocsp_response)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_sign_cades_x(
        data_buf,
        data_len,
        sign_key,
        cert_buf,
        cert_len,
        ocsp_buf,
        ocsp_len,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def cms_sign_cades_lt(
    sign_key: Handle,
    data: bytes,
    ref_cert: bytes,
    full_crl: bytes,
    delta_crl: bytes,
    ocsp_response: bytes,
) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    cert_buf, cert_len = _bytes_ptr(ref_cert)
    full_buf, full_len = _bytes_ptr(full_crl)
    delta_buf, delta_len = _bytes_ptr(delta_crl)
    ocsp_buf, ocsp_len = _bytes_ptr(ocsp_response)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_sign_cades_lt(
        data_buf,
        data_len,
        sign_key,
        cert_buf,
        cert_len,
        full_buf,
        full_len,
        delta_buf,
        delta_len,
        ocsp_buf,
        ocsp_len,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def cms_sign_cades_a(
    sign_key: Handle,
    tsa_key: Handle,
    data: bytes,
    ref_cert: bytes,
    full_crl: bytes,
    delta_crl: bytes,
    ocsp_response: bytes,
    serial: bytes,
    current_time: int,
    policy_oid: str | None = None,
) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    cert_buf, cert_len = _bytes_ptr(ref_cert)
    full_buf, full_len = _bytes_ptr(full_crl)
    delta_buf, delta_len = _bytes_ptr(delta_crl)
    ocsp_buf, ocsp_len = _bytes_ptr(ocsp_response)
    serial_buf, serial_len = _bytes_ptr(serial)
    policy = policy_oid.encode("utf-8") if policy_oid else None
    policy_buf, _ = _bytes_ptr(policy)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_sign_cades_a(
        data_buf,
        data_len,
        sign_key,
        cert_buf,
        cert_len,
        full_buf,
        full_len,
        delta_buf,
        delta_len,
        ocsp_buf,
        ocsp_len,
        tsa_key,
        serial_buf,
        serial_len,
        c_int64(current_time),
        policy_buf,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def cms_verify(data: bytes, cms: bytes) -> None:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    cms_buf, cms_len = _bytes_ptr(cms)
    err = _init_error()
    code = lib.uacryptex_cms_verify(data_buf, data_len, cms_buf, cms_len, err)
    _check(code, err)


def cms_envelop_encrypt(handle: Handle, data: bytes, recipient_cert: bytes) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    cert_buf, cert_len = _bytes_ptr(recipient_cert)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_envelop_encrypt(data_buf, data_len, handle, cert_buf, cert_len, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def cms_envelop_decrypt(
    handle: Handle,
    cms: bytes,
    external: bytes | None,
    originator_cert: bytes | None,
    recipient_cert: bytes,
) -> bytes:
    lib = get_lib()
    cms_buf, cms_len = _bytes_ptr(cms)
    ext_buf, ext_len = _bytes_ptr(external)
    orig_buf, orig_len = _bytes_ptr(originator_cert)
    rcpt_buf, rcpt_len = _bytes_ptr(recipient_cert)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cms_envelop_decrypt(
        cms_buf,
        cms_len,
        ext_buf,
        ext_len,
        orig_buf,
        orig_len,
        handle,
        rcpt_buf,
        rcpt_len,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def digest(
    data: bytes,
    algorithm_aid: bytes | None = None,
    cert: bytes | None = None,
) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    aid_buf, aid_len = _bytes_ptr(algorithm_aid)
    cert_buf, cert_len = _bytes_ptr(cert)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_digest(data_buf, data_len, aid_buf, aid_len, cert_buf, cert_len, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def sign_data(handle: Handle, data: bytes) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_sign_data(data_buf, data_len, handle, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def pkcs8_open(der: bytes, cert: bytes | None = None) -> Handle:
    lib = get_lib()
    der_buf, der_len = _bytes_ptr(der)
    cert_buf, cert_len = _bytes_ptr(cert)
    out = Handle()
    err = _init_error()
    code = lib.uacryptex_pkcs8_open(der_buf, der_len, cert_buf, cert_len, out, err)
    _check(code, err)
    return out


def verify_hash(digest: bytes, signature: bytes, cert: bytes) -> None:
    lib = get_lib()
    digest_buf, digest_len = _bytes_ptr(digest)
    sig_buf, sig_len = _bytes_ptr(signature)
    cert_buf, cert_len = _bytes_ptr(cert)
    err = _init_error()
    code = lib.uacryptex_verify_hash(digest_buf, digest_len, sig_buf, sig_len, cert_buf, cert_len, err)
    _check(code, err)


def verify_data(data: bytes, signature: bytes, cert: bytes) -> None:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    sig_buf, sig_len = _bytes_ptr(signature)
    cert_buf, cert_len = _bytes_ptr(cert)
    err = _init_error()
    code = lib.uacryptex_verify_data(data_buf, data_len, sig_buf, sig_len, cert_buf, cert_len, err)
    _check(code, err)


def cert_verify(cert: bytes, issuer_cert: bytes) -> None:
    lib = get_lib()
    cert_buf, cert_len = _bytes_ptr(cert)
    issuer_buf, issuer_len = _bytes_ptr(issuer_cert)
    err = _init_error()
    code = lib.uacryptex_cert_verify(cert_buf, cert_len, issuer_buf, issuer_len, err)
    _check(code, err)


def cert_check_validity(cert: bytes, unix_secs: int = 0) -> None:
    lib = get_lib()
    cert_buf, cert_len = _bytes_ptr(cert)
    err = _init_error()
    code = lib.uacryptex_cert_check_validity(cert_buf, cert_len, c_int64(unix_secs), err)
    _check(code, err)


def cert_spki(cert: bytes) -> bytes:
    lib = get_lib()
    cert_buf, cert_len = _bytes_ptr(cert)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cert_spki(cert_buf, cert_len, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def crl_verify(crl: bytes, issuer_cert: bytes) -> None:
    lib = get_lib()
    crl_buf, crl_len = _bytes_ptr(crl)
    issuer_buf, issuer_len = _bytes_ptr(issuer_cert)
    err = _init_error()
    code = lib.uacryptex_crl_verify(crl_buf, crl_len, issuer_buf, issuer_len, err)
    _check(code, err)


def crl_check_cert(crl: bytes, issuer_cert: bytes, cert: bytes) -> bool:
    lib = get_lib()
    crl_buf, crl_len = _bytes_ptr(crl)
    issuer_buf, issuer_len = _bytes_ptr(issuer_cert)
    cert_buf, cert_len = _bytes_ptr(cert)
    revoked = c_int32()
    err = _init_error()
    code = lib.uacryptex_crl_check_cert(
        crl_buf, crl_len, issuer_buf, issuer_len, cert_buf, cert_len, revoked, err
    )
    _check(code, err)
    return bool(revoked.value)


def crl_generate(
    handle: Handle,
    previous_crl: bytes,
    crl_type: int,
    diff_next_update_secs: int,
    merge_delta_crl: bytes | None = None,
    revoke_serial: bytes | None = None,
    template_name: str = "",
    description: str = "",
) -> bytes:
    lib = get_lib()
    prev_buf, prev_len = _bytes_ptr(previous_crl)
    merge_buf, merge_len = _bytes_ptr(merge_delta_crl)
    serial_buf, serial_len = _bytes_ptr(revoke_serial)
    tmpl = template_name.encode("utf-8") if template_name else None
    desc = description.encode("utf-8") if description else None
    tmpl_buf, _ = _bytes_ptr(tmpl)
    desc_buf, _ = _bytes_ptr(desc)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_crl_generate(
        handle,
        prev_buf,
        prev_len,
        c_int32(crl_type),
        c_int64(diff_next_update_secs),
        merge_buf,
        merge_len,
        serial_buf,
        serial_len,
        tmpl_buf,
        desc_buf,
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def dstu4145_verify_pb(
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
    lib = get_lib()
    f_arr = (c_uint32 * len(f))(*f)
    b_buf, b_len = _bytes_ptr(b)
    n_buf, n_len = _bytes_ptr(n)
    gx_buf, gx_len = _bytes_ptr(gx)
    gy_buf, gy_len = _bytes_ptr(gy)
    qx_buf, qx_len = _bytes_ptr(qx)
    qy_buf, qy_len = _bytes_ptr(qy)
    hash_buf, hash_len = _bytes_ptr(hash_)
    r_buf, r_len = _bytes_ptr(r)
    s_buf, s_len = _bytes_ptr(s)
    err = _init_error()
    code = lib.uacryptex_dstu4145_verify_pb(
        f_arr,
        len(f),
        c_int32(a),
        b_buf,
        b_len,
        n_buf,
        n_len,
        gx_buf,
        gx_len,
        gy_buf,
        gy_len,
        qx_buf,
        qx_len,
        qy_buf,
        qy_len,
        hash_buf,
        hash_len,
        r_buf,
        r_len,
        s_buf,
        s_len,
        err,
    )
    _check(code, err)


def pkcs12_certificate_count(handle: Handle) -> int:
    lib = get_lib()
    count = c_size_t()
    err = _init_error()
    code = lib.uacryptex_pkcs12_certificate_count(handle, count, err)
    _check(code, err)
    return int(count.value)


def pkcs12_get_certificate(handle: Handle, index: int) -> bytes:
    lib = get_lib()
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_pkcs12_get_certificate(handle, index, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def ocsp_request_from_cert(root_cert: bytes, user_cert: bytes) -> bytes:
    lib = get_lib()
    root_buf, root_len = _bytes_ptr(root_cert)
    user_buf, user_len = _bytes_ptr(user_cert)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_ocsp_request_from_cert(root_buf, root_len, user_buf, user_len, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def ocsp_request_generate(
    root_cert: bytes,
    user_cert: bytes,
    requestor_key: Handle | None = None,
    ocsp_responder_cert: bytes | None = None,
    nonce: bytes | None = None,
    include_nonce: bool = True,
) -> bytes:
    lib = get_lib()
    root_buf, root_len = _bytes_ptr(root_cert)
    user_buf, user_len = _bytes_ptr(user_cert)
    ocsp_buf, ocsp_len = _bytes_ptr(ocsp_responder_cert)
    nonce_buf, nonce_len = _bytes_ptr(nonce)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_ocsp_request_generate(
        root_buf,
        root_len,
        user_buf,
        user_len,
        requestor_key,
        ocsp_buf,
        ocsp_len,
        nonce_buf,
        nonce_len,
        c_int32(1 if include_nonce else 0),
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)


def ocsp_response_verify(response: bytes, ocsp_responder_cert: bytes) -> None:
    lib = get_lib()
    resp_buf, resp_len = _bytes_ptr(response)
    cert_buf, cert_len = _bytes_ptr(ocsp_responder_cert)
    err = _init_error()
    code = lib.uacryptex_ocsp_response_verify(resp_buf, resp_len, cert_buf, cert_len, err)
    _check(code, err)


def tsp_request_from_data(data: bytes, policy_oid: str | None = None, cert_req: bool = True) -> bytes:
    lib = get_lib()
    data_buf, data_len = _bytes_ptr(data)
    policy = policy_oid.encode("utf-8") if policy_oid else None
    policy_buf, _ = _bytes_ptr(policy)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_tsp_request_from_data(data_buf, data_len, policy_buf, int(cert_req), out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def tsp_response_verify(response: bytes, tsa_cert: bytes) -> None:
    lib = get_lib()
    resp_buf, resp_len = _bytes_ptr(response)
    cert_buf, cert_len = _bytes_ptr(tsa_cert)
    err = _init_error()
    code = lib.uacryptex_tsp_response_verify(resp_buf, resp_len, cert_buf, cert_len, err)
    _check(code, err)


def tsp_response_generate(handle: Handle, request: bytes, serial: bytes, current_time: int) -> bytes:
    lib = get_lib()
    req_buf, req_len = _bytes_ptr(request)
    serial_buf, serial_len = _bytes_ptr(serial)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_tsp_response_generate(
        req_buf, req_len, handle, serial_buf, serial_len, c_int64(current_time), out, err
    )
    _check(code, err)
    return _buf_to_bytes(out)


def csr_generate(handle: Handle, subject: str, dns: str | None = None, email: str | None = None) -> bytes:
    lib = get_lib()
    out = UacryptexBuf()
    err = _init_error()
    dns_b = dns.encode("utf-8") if dns else None
    email_b = email.encode("utf-8") if email else None
    dns_buf, _ = _bytes_ptr(dns_b)
    email_buf, _ = _bytes_ptr(email_b)
    code = lib.uacryptex_csr_generate(handle, subject.encode("utf-8"), dns_buf, email_buf, None, out, err)
    _check(code, err)
    return _buf_to_bytes(out)


def csr_verify(csr: bytes) -> None:
    lib = get_lib()
    csr_buf, csr_len = _bytes_ptr(csr)
    err = _init_error()
    code = lib.uacryptex_csr_verify(csr_buf, csr_len, err)
    _check(code, err)


def cert_generate(
    handle: Handle,
    csr: bytes,
    version: int,
    serial: bytes,
    not_before: int,
    not_after: int,
    self_signed: bool = False,
) -> bytes:
    lib = get_lib()
    csr_buf, csr_len = _bytes_ptr(csr)
    serial_buf, serial_len = _bytes_ptr(serial)
    out = UacryptexBuf()
    err = _init_error()
    code = lib.uacryptex_cert_generate(
        handle,
        csr_buf,
        csr_len,
        version,
        serial_buf,
        serial_len,
        c_int64(not_before),
        c_int64(not_after),
        c_int32(1 if self_signed else 0),
        out,
        err,
    )
    _check(code, err)
    return _buf_to_bytes(out)
