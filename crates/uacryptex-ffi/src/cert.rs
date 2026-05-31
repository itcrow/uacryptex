//! X.509 certificate helpers (stateless — DER in/out).

use der::Decode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::creq::CertificationRequest;
use uacryptex_core::pki::crypto::{DigestAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{ecert_alloc, ecert_generate};
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};
use crate::UacryptexHandle;

/// Verify certificate signature using issuer certificate.
#[no_mangle]
pub extern "C" fn uacryptex_cert_verify(
    cert: *const u8,
    cert_len: usize,
    issuer_cert: *const u8,
    issuer_cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let issuer_der = bytes_from_ptr(issuer_cert, issuer_cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid issuer_cert: code {code}")))?;
        let cert = Cert::decode(cert_der)?;
        let issuer = Cert::decode(issuer_der)?;
        let adapter = VerifyAdapter::init_by_cert(&issuer)?;
        cert.verify(&adapter)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Check notBefore/notAfter at `unix_secs` (0 = now).
#[no_mangle]
pub extern "C" fn uacryptex_cert_check_validity(
    cert: *const u8,
    cert_len: usize,
    unix_secs: i64,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let cert = Cert::decode(cert_der)?;
        let at = if unix_secs == 0 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| Error::Internal(format!("system time: {e}")))?
                .as_secs() as i64
        } else {
            unix_secs
        };
        cert.check_validity_at(at)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Return SubjectPublicKeyInfo DER from certificate.
#[no_mangle]
pub extern "C" fn uacryptex_cert_spki(
    cert: *const u8,
    cert_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let cert = Cert::decode(cert_der)?;
        Ok(UacryptexBuf::from_vec(cert.spki_der()?))
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

/// Issue an X.509 certificate from PKCS#10 CSR using CA (or self-signed) key handle.
#[no_mangle]
pub extern "C" fn uacryptex_cert_generate(
    ca_key: *mut UacryptexHandle,
    csr: *const u8,
    csr_len: usize,
    version: u8,
    serial: *const u8,
    serial_len: usize,
    not_before: i64,
    not_after: i64,
    self_signed: i32,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        if ca_key.is_null() {
            return Err(Error::InvalidParam("ca_key handle is null".into()));
        }
        let csr_der = bytes_from_ptr(csr, csr_len)
            .map_err(|code| Error::InvalidParam(format!("invalid csr: code {code}")))?;
        let serial = bytes_from_ptr(serial, serial_len)
            .map_err(|code| Error::InvalidParam(format!("invalid serial: code {code}")))?;
        let request = CertificationRequest::from_der(csr_der)
            .map_err(|e| Error::Internal(format!("csr decode: {e}")))?;
        let handle = unsafe { &mut *ca_key };
        let sa = handle.sign_adapter()?;
        let da = DigestAdapter::init_default()?;
        let engine = ecert_alloc(&sa, da, self_signed != 0)?;
        let mut cert = None;
        ecert_generate(
            &engine, &request, version, serial, not_before, not_after, None, &mut cert,
        )?;
        let cert = cert.ok_or_else(|| Error::Internal("cert generate returned none".into()))?;
        Ok(UacryptexBuf::from_vec(cert.encode()?))
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
