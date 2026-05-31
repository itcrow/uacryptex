//! PKCS#8 private key open (`uacryptex_pkcs8_open`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::storage::pkcs8::{pkcs8_decode, pkcs8_get_sign_adapter};
use uacryptex_core::{Error, RET_OK};

use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};
use crate::handle::{Handle, HandleInner};
use crate::UacryptexHandle;

/// Open a signing handle from PKCS#8 PrivateKeyInfo DER and optional matching certificate.
#[no_mangle]
pub extern "C" fn uacryptex_pkcs8_open(
    der: *const u8,
    der_len: usize,
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
        let der = bytes_from_ptr(der, der_len)
            .map_err(|code| Error::InvalidParam(format!("invalid pkcs8: code {code}")))?;
        let key = pkcs8_decode(der)?;
        let cert = if cert_len == 0 {
            None
        } else {
            let cert_der = bytes_from_ptr(cert, cert_len)
                .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
            Some(Cert::decode(cert_der)?)
        };
        let cert_ref = cert.as_ref();
        let sa = pkcs8_get_sign_adapter(&key, cert_ref)?;
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
