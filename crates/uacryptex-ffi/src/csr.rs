//! PKCS#10 certification request (CSR) FFI.

use der::{Decode, Encode};
use uacryptex_core::pki::creq::{creq_verify, CertificationRequest};
use uacryptex_core::pki::crypto::{spki_algorithm_der, VerifyAdapter};
use uacryptex_core::pki::engine::{
    ecert_request_alloc, ecert_request_generate, ecert_request_set_subj_alt_name,
    ecert_request_set_subj_dir_attr, ecert_request_set_subj_name,
};
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, cstr_to_str, write_error, UacryptexError};
use crate::UacryptexHandle;

fn optional_cstr(ptr: *const std::os::raw::c_char) -> Result<Option<String>, Error> {
    if ptr.is_null() {
        return Ok(None);
    }
    let s = cstr_to_str(ptr)
        .map_err(|code| Error::InvalidParam(format!("invalid string pointer: code {code}")))?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(s.to_string()))
    }
}

/// Generate PKCS#10 CSR using private key handle and Cryptonite subject string.
#[no_mangle]
pub extern "C" fn uacryptex_csr_generate(
    key: *mut UacryptexHandle,
    subject: *const std::os::raw::c_char,
    dns: *const std::os::raw::c_char,
    email: *const std::os::raw::c_char,
    subject_dir_attr: *const std::os::raw::c_char,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        if key.is_null() {
            return Err(Error::InvalidParam("key handle is null".into()));
        }
        let handle = unsafe { &mut *key };
        let sa = handle.sign_adapter()?;
        let mut engine = ecert_request_alloc(&sa)?;
        let subject = optional_cstr(subject)?;
        let dns = optional_cstr(dns)?;
        let email = optional_cstr(email)?;
        let subject_dir_attr = optional_cstr(subject_dir_attr)?;
        ecert_request_set_subj_name(&mut engine, subject.as_deref())?;
        ecert_request_set_subj_alt_name(&mut engine, dns.as_deref(), email.as_deref())?;
        ecert_request_set_subj_dir_attr(&mut engine, subject_dir_attr.as_deref())?;
        let mut req = None;
        ecert_request_generate(&engine, &mut req)?;
        let csr = req.ok_or_else(|| Error::Internal("csr generate returned none".into()))?;
        let der = csr
            .to_der()
            .map_err(|e| Error::Internal(format!("csr encode: {e}")))?;
        Ok(UacryptexBuf::from_vec(der))
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

/// Verify CSR self-signature using public key embedded in the request.
#[no_mangle]
pub extern "C" fn uacryptex_csr_verify(
    csr: *const u8,
    csr_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let der = bytes_from_ptr(csr, csr_len)
            .map_err(|code| Error::InvalidParam(format!("invalid csr: code {code}")))?;
        let request = CertificationRequest::from_der(der)
            .map_err(|e| Error::Internal(format!("csr decode: {e}")))?;
        let sign_aid = request
            .algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("csr sign aid encode: {e}")))?;
        let spki_der = request
            .info
            .public_key
            .to_der()
            .map_err(|e| Error::Internal(format!("csr spki encode: {e}")))?;
        let spki_aid = spki_algorithm_der(&spki_der)?;
        let adapter = VerifyAdapter::init_by_spki(&sign_aid, &spki_der, &spki_aid)?;
        creq_verify(&request, &adapter)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}
