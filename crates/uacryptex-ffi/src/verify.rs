//! Standalone signature verification FFI.

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::VerifyAdapter;
use uacryptex_core::{Error, RET_OK};

use crate::error::{bytes_from_ptr, write_error, UacryptexError};

/// Verify a detached signature over a precomputed digest.
#[no_mangle]
pub extern "C" fn uacryptex_verify_hash(
    digest: *const u8,
    digest_len: usize,
    signature: *const u8,
    signature_len: usize,
    cert: *const u8,
    cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let digest = bytes_from_ptr(digest, digest_len)
            .map_err(|code| Error::InvalidParam(format!("invalid digest: code {code}")))?;
        let signature = bytes_from_ptr(signature, signature_len)
            .map_err(|code| Error::InvalidParam(format!("invalid signature: code {code}")))?;
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let cert = Cert::decode(cert_der)?;
        let adapter = VerifyAdapter::init_by_cert(&cert)?;
        adapter.verify_hash(digest, signature)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Verify a detached signature over raw data (hash-then-verify inside adapter).
#[no_mangle]
pub extern "C" fn uacryptex_verify_data(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    cert: *const u8,
    cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let data = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let signature = bytes_from_ptr(signature, signature_len)
            .map_err(|code| Error::InvalidParam(format!("invalid signature: code {code}")))?;
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let cert = Cert::decode(cert_der)?;
        let adapter = VerifyAdapter::init_by_cert(&cert)?;
        adapter.verify_data(data, signature)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Alias for [`uacryptex_verify_hash`] (FFI.md Phase 1).
#[no_mangle]
pub extern "C" fn uacryptex_dstu4145_verify(
    digest: *const u8,
    digest_len: usize,
    signature: *const u8,
    signature_len: usize,
    cert: *const u8,
    cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    uacryptex_verify_hash(digest, digest_len, signature, signature_len, cert, cert_len, err)
}
