//! Raw key + certificate open (`uacryptex_sign_open`) and signing.

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::SignAdapter;
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};
use crate::handle::{Handle, HandleInner};
use crate::UacryptexHandle;

/// Open a signing handle from raw private key bytes and an X.509 certificate.
#[no_mangle]
pub extern "C" fn uacryptex_sign_open(
    key: *const u8,
    key_len: usize,
    cert: *const u8,
    cert_len: usize,
    out: *mut *mut UacryptexHandle,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<*mut UacryptexHandle, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        unsafe {
            if !(*out).is_null() {
                return Err(Error::InvalidParam("out handle must be null".into()));
            }
        }
        let key_der = bytes_from_ptr(key, key_len)
            .map_err(|code| Error::InvalidParam(format!("invalid key: code {code}")))?;
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let cert = Cert::decode(cert_der)?;
        let sa = SignAdapter::init_by_cert(key_der, &cert)?;
        Ok(Handle {
            inner: HandleInner::Sign(sa),
        }
        .into_raw())
    };

    match run() {
        Ok(handle) => {
            unsafe {
                *out = handle;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Sign a precomputed digest (`SignAdapter::sign_hash`).
#[no_mangle]
pub extern "C" fn uacryptex_sign_hash(
    hash: *const u8,
    hash_len: usize,
    key: *mut UacryptexHandle,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let digest = bytes_from_ptr(hash, hash_len)
            .map_err(|code| Error::InvalidParam(format!("invalid hash: code {code}")))?;
        if key.is_null() {
            return Err(Error::InvalidParam("key handle is null".into()));
        }
        let handle = unsafe { &mut *key };
        let sa = handle.sign_adapter()?;
        let sig = sa.sign_hash(digest)?;
        Ok(UacryptexBuf::from_vec(sig))
    };

    match run() {
        Ok(buf) => {
            unsafe {
                *out = buf;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Sign raw data (hash-then-sign inside adapter).
#[no_mangle]
pub extern "C" fn uacryptex_sign_data(
    data: *const u8,
    data_len: usize,
    key: *mut UacryptexHandle,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let data = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        if key.is_null() {
            return Err(Error::InvalidParam("key handle is null".into()));
        }
        let handle = unsafe { &mut *key };
        let sa = handle.sign_adapter()?;
        let sig = sa.sign_data(data)?;
        Ok(UacryptexBuf::from_vec(sig))
    };

    match run() {
        Ok(buf) => {
            unsafe {
                *out = buf;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Alias for [`uacryptex_sign_hash`] (FFI.md Phase 1).
#[no_mangle]
pub extern "C" fn uacryptex_dstu4145_sign(
    hash: *const u8,
    hash_len: usize,
    key: *mut UacryptexHandle,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    uacryptex_sign_hash(hash, hash_len, key, out, err)
}
