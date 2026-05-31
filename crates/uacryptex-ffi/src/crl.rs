//! CRL verification, revocation check, and issuance FFI.

use std::os::raw::c_char;

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::VerifyAdapter;
use uacryptex_core::pki::engine::{
    ecrl_add_revoked_cert_by_sn, ecrl_alloc, ecrl_generate, ecrl_generate_diff_next_update,
    ecrl_merge_delta, CrlType,
};
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, cstr_to_str, write_error, UacryptexError};
use crate::UacryptexHandle;

fn optional_cstr(ptr: *const c_char) -> Result<String, Error> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    let s = cstr_to_str(ptr)
        .map_err(|code| Error::InvalidParam(format!("invalid string pointer: code {code}")))?;
    Ok(s.to_string())
}

fn crl_type_from_i32(value: i32) -> Result<CrlType, Error> {
    match value {
        0 => Ok(CrlType::Delta),
        1 => Ok(CrlType::Full),
        _ => Err(Error::InvalidParam(
            "crl_type must be 0 (delta) or 1 (full)".into(),
        )),
    }
}

/// Verify CRL signature using issuer certificate.
#[no_mangle]
pub extern "C" fn uacryptex_crl_verify(
    crl: *const u8,
    crl_len: usize,
    issuer_cert: *const u8,
    issuer_cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let crl_der = bytes_from_ptr(crl, crl_len)
            .map_err(|code| Error::InvalidParam(format!("invalid crl: code {code}")))?;
        let issuer_der = bytes_from_ptr(issuer_cert, issuer_cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid issuer_cert: code {code}")))?;
        let crl = Crl::decode(crl_der)?;
        let issuer = Cert::decode(issuer_der)?;
        let adapter = VerifyAdapter::init_by_cert(&issuer)?;
        crl.verify(&adapter)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Check whether `cert` is revoked by `crl`. Sets `*revoked` to 1 if revoked, 0 if not.
#[no_mangle]
pub extern "C" fn uacryptex_crl_check_cert(
    crl: *const u8,
    crl_len: usize,
    issuer_cert: *const u8,
    issuer_cert_len: usize,
    cert: *const u8,
    cert_len: usize,
    revoked: *mut i32,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<i32, Error> {
        check_out(revoked as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid revoked pointer: code {code}")))?;
        let crl_der = bytes_from_ptr(crl, crl_len)
            .map_err(|code| Error::InvalidParam(format!("invalid crl: code {code}")))?;
        let issuer_der = bytes_from_ptr(issuer_cert, issuer_cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid issuer_cert: code {code}")))?;
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cert: code {code}")))?;
        let crl = Crl::decode(crl_der)?;
        let issuer = Cert::decode(issuer_der)?;
        let cert = Cert::decode(cert_der)?;
        let adapter = VerifyAdapter::init_by_cert(&issuer)?;
        crl.verify(&adapter)?;
        Ok(if crl.check_cert(&cert)? { 1 } else { 0 })
    };

    match run() {
        Ok(flag) => {
            unsafe {
                *revoked = flag;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Issue a new CRL from a previous CRL using CA key handle.
///
/// `crl_type`: 0 = delta, 1 = full.
/// `diff_next_update_secs`: if > 0 use `thisUpdate=now` and `nextUpdate=now+diff`; else roll from previous `nextUpdate`.
/// `merge_delta_crl`: optional delta CRL to merge when `crl_type` is full (NULL allowed).
/// `revoke_serial`: optional serial number to add before generate (NULL allowed).
#[no_mangle]
pub extern "C" fn uacryptex_crl_generate(
    ca_key: *mut UacryptexHandle,
    previous_crl: *const u8,
    previous_crl_len: usize,
    crl_type: i32,
    diff_next_update_secs: i64,
    merge_delta_crl: *const u8,
    merge_delta_crl_len: usize,
    revoke_serial: *const u8,
    revoke_serial_len: usize,
    template_name: *const c_char,
    description: *const c_char,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        if ca_key.is_null() {
            return Err(Error::InvalidParam("ca_key handle is null".into()));
        }
        let previous_der = bytes_from_ptr(previous_crl, previous_crl_len)
            .map_err(|code| Error::InvalidParam(format!("invalid previous_crl: code {code}")))?;
        let crl_type = crl_type_from_i32(crl_type)?;
        let template_name = optional_cstr(template_name)?;
        let description = optional_cstr(description)?;

        let previous = Crl::decode(previous_der)?;
        let handle = unsafe { &mut *ca_key };
        let sa = handle.sign_adapter()?;
        let issuer = handle.matching_cert()?;
        let va = VerifyAdapter::init_by_cert(&issuer)?;

        let mut engine = ecrl_alloc(
            Some(&previous),
            &sa,
            &va,
            None,
            &template_name,
            crl_type,
            &description,
        )?;

        if merge_delta_crl_len > 0 {
            let delta_der =
                bytes_from_ptr(merge_delta_crl, merge_delta_crl_len).map_err(|code| {
                    Error::InvalidParam(format!("invalid merge_delta_crl: code {code}"))
                })?;
            let delta = Crl::decode(delta_der)?;
            ecrl_merge_delta(&mut engine, &delta)?;
        }

        if revoke_serial_len > 0 {
            let serial = bytes_from_ptr(revoke_serial, revoke_serial_len).map_err(|code| {
                Error::InvalidParam(format!("invalid revoke_serial: code {code}"))
            })?;
            ecrl_add_revoked_cert_by_sn(&mut engine, serial, None, None)?;
        }

        let mut crl = None;
        if diff_next_update_secs > 0 {
            ecrl_generate_diff_next_update(&engine, diff_next_update_secs, &mut crl)?;
        } else {
            ecrl_generate(&engine, &mut crl)?;
        }
        let crl = crl.ok_or_else(|| Error::Internal("crl generate returned none".into()))?;
        Ok(UacryptexBuf::from_vec(crl.encode()?))
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
