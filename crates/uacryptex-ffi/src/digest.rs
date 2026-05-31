//! Digest FFI (`uacryptex_digest`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::DigestAdapter;
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};

/// Hash `data` with GOST3411 (default), optional AlgorithmIdentifier DER, or cert-selected digest.
#[no_mangle]
pub extern "C" fn uacryptex_digest(
    data: *const u8,
    data_len: usize,
    algorithm_aid: *const u8,
    algorithm_aid_len: usize,
    cert: *const u8,
    cert_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let data = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let aid = if algorithm_aid_len == 0 {
            None
        } else {
            Some(
                bytes_from_ptr(algorithm_aid, algorithm_aid_len).map_err(|code| {
                    Error::InvalidParam(format!("invalid algorithm_aid: code {code}"))
                })?,
            )
        };
        let cert = if cert_len == 0 {
            None
        } else {
            let der = bytes_from_ptr(cert, cert_len)
                .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
            Some(Cert::decode(der)?)
        };
        let cert_ref = cert.as_ref();
        let hash = DigestAdapter::digest_data(data, aid, cert_ref)?;
        Ok(UacryptexBuf::from_vec(hash))
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
