//! CMS sign/verify (`uacryptex_cms_sign`, `uacryptex_cms_verify`).

use der::Encode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::build_content_info_cades_t;
use uacryptex_core::pki::cms::cert_matches_signer_id;
use uacryptex_core::pki::cms::CertificateChoices;
use uacryptex_core::pki::cms::{build_content_info, SignedDataContainer};
use uacryptex_core::pki::crypto::{DigestAdapter, VerifyAdapter};
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};
use crate::UacryptexHandle;

/// Sign `data` with a private key handle (PKCS#12 or raw key+cert).
#[no_mangle]
pub extern "C" fn uacryptex_cms_sign(
    data: *const u8,
    data_len: usize,
    key: *mut UacryptexHandle,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        if key.is_null() {
            return Err(Error::InvalidParam("key handle is null".into()));
        }
        let handle = unsafe { &mut *key };
        let sa = handle.sign_adapter()?;
        let cms = build_content_info(&sa, payload, OidId::Data)?;
        Ok(UacryptexBuf::from_vec(cms))
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

/// Sign `data` and attach a CAdES-T timestamp (BES + id-aa-signatureTimeStampToken).
#[no_mangle]
pub extern "C" fn uacryptex_cms_sign_cades_t(
    data: *const u8,
    data_len: usize,
    sign_key: *mut UacryptexHandle,
    tsa_key: *mut UacryptexHandle,
    serial: *const u8,
    serial_len: usize,
    current_time: i64,
    policy_oid: *const std::os::raw::c_char,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        use der::asn1::Int;

        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let serial_bytes = bytes_from_ptr(serial, serial_len).map_err(|code| {
            Error::InvalidParam(format!("invalid serial: code {code}"))
        })?;
        if sign_key.is_null() {
            return Err(Error::InvalidParam("sign_key handle is null".into()));
        }
        if tsa_key.is_null() {
            return Err(Error::InvalidParam("tsa_key handle is null".into()));
        }
        let policy = if policy_oid.is_null() {
            None
        } else {
            let s = crate::error::cstr_to_str(policy_oid).map_err(|code| {
                Error::InvalidParam(format!("invalid policy_oid: code {code}"))
            })?;
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        };
        let sign_handle = unsafe { &mut *sign_key };
        let tsa_handle = unsafe { &mut *tsa_key };
        let sa = sign_handle.sign_adapter()?;
        let tsp_sa = tsa_handle.sign_adapter()?;
        let serial = Int::new(serial_bytes)
            .map_err(|e| Error::Internal(format!("serial integer: {e}")))?;
        let cms = build_content_info_cades_t(
            &sa,
            payload,
            OidId::Data,
            &tsp_sa,
            &serial,
            current_time,
            policy.as_deref(),
        )?;
        Ok(UacryptexBuf::from_vec(cms))
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

/// Sign `data` and attach CAdES-C refs (BES + certificate/revocation references).
#[no_mangle]
pub extern "C" fn uacryptex_cms_sign_cades_c(
    data: *const u8,
    data_len: usize,
    sign_key: *mut UacryptexHandle,
    ref_cert: *const u8,
    ref_cert_len: usize,
    ref_crl: *const u8,
    ref_crl_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let cert_der = bytes_from_ptr(ref_cert, ref_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ref_cert: code {code}"))
        })?;
        let crl_der = bytes_from_ptr(ref_crl, ref_crl_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ref_crl: code {code}"))
        })?;
        if sign_key.is_null() {
            return Err(Error::InvalidParam("sign_key handle is null".into()));
        }
        let handle = unsafe { &mut *sign_key };
        let sa = handle.sign_adapter()?;
        let ref_cert = Cert::decode(cert_der)?;
        let ref_crl = uacryptex_core::pki::crl::Crl::decode(crl_der)?;
        let cms = uacryptex_core::pki::cms::build_content_info_cades_c(
            &sa,
            payload,
            OidId::Data,
            &ref_cert,
            &ref_crl,
        )?;
        Ok(UacryptexBuf::from_vec(cms))
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

/// Sign `data` and attach CAdES-X values (BES + certificate/revocation values).
#[no_mangle]
pub extern "C" fn uacryptex_cms_sign_cades_x(
    data: *const u8,
    data_len: usize,
    sign_key: *mut UacryptexHandle,
    ref_cert: *const u8,
    ref_cert_len: usize,
    ocsp_response: *const u8,
    ocsp_response_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let cert_der = bytes_from_ptr(ref_cert, ref_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ref_cert: code {code}"))
        })?;
        let ocsp_der = bytes_from_ptr(ocsp_response, ocsp_response_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ocsp_response: code {code}"))
        })?;
        if sign_key.is_null() {
            return Err(Error::InvalidParam("sign_key handle is null".into()));
        }
        let handle = unsafe { &mut *sign_key };
        let sa = handle.sign_adapter()?;
        let ref_cert = Cert::decode(cert_der)?;
        let cms = uacryptex_core::pki::cms::build_content_info_cades_x(
            &sa,
            payload,
            OidId::Data,
            &ref_cert,
            ocsp_der,
        )?;
        Ok(UacryptexBuf::from_vec(cms))
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

/// Sign `data` with CAdES-LT (X + validation certificates/CRLs in SignedData).
#[no_mangle]
pub extern "C" fn uacryptex_cms_sign_cades_lt(
    data: *const u8,
    data_len: usize,
    sign_key: *mut UacryptexHandle,
    ref_cert: *const u8,
    ref_cert_len: usize,
    full_crl: *const u8,
    full_crl_len: usize,
    delta_crl: *const u8,
    delta_crl_len: usize,
    ocsp_response: *const u8,
    ocsp_response_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let cert_der = bytes_from_ptr(ref_cert, ref_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ref_cert: code {code}"))
        })?;
        let full_der = bytes_from_ptr(full_crl, full_crl_len).map_err(|code| {
            Error::InvalidParam(format!("invalid full_crl: code {code}"))
        })?;
        let ocsp_der = bytes_from_ptr(ocsp_response, ocsp_response_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ocsp_response: code {code}"))
        })?;
        if sign_key.is_null() {
            return Err(Error::InvalidParam("sign_key handle is null".into()));
        }
        let handle = unsafe { &mut *sign_key };
        let sa = handle.sign_adapter()?;
        let ref_cert = Cert::decode(cert_der)?;
        let full_crl = uacryptex_core::pki::crl::Crl::decode(full_der)?;
        let mut validation_crls = vec![full_crl];
        if delta_crl_len > 0 {
            let delta_der = bytes_from_ptr(delta_crl, delta_crl_len).map_err(|code| {
                Error::InvalidParam(format!("invalid delta_crl: code {code}"))
            })?;
            validation_crls.push(uacryptex_core::pki::crl::Crl::decode(delta_der)?);
        }
        let cms = uacryptex_core::pki::cms::build_content_info_cades_lt(
            &sa,
            payload,
            OidId::Data,
            &ref_cert,
            &validation_crls,
            ocsp_der,
        )?;
        Ok(UacryptexBuf::from_vec(cms))
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

/// Sign `data` with CAdES-A (LT + id-aa-ets-archiveTimeStamp).
#[no_mangle]
pub extern "C" fn uacryptex_cms_sign_cades_a(
    data: *const u8,
    data_len: usize,
    sign_key: *mut UacryptexHandle,
    ref_cert: *const u8,
    ref_cert_len: usize,
    full_crl: *const u8,
    full_crl_len: usize,
    delta_crl: *const u8,
    delta_crl_len: usize,
    ocsp_response: *const u8,
    ocsp_response_len: usize,
    tsa_key: *mut UacryptexHandle,
    serial: *const u8,
    serial_len: usize,
    current_time: i64,
    policy_oid: *const std::os::raw::c_char,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        use der::asn1::Int;

        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let cert_der = bytes_from_ptr(ref_cert, ref_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ref_cert: code {code}"))
        })?;
        let full_der = bytes_from_ptr(full_crl, full_crl_len).map_err(|code| {
            Error::InvalidParam(format!("invalid full_crl: code {code}"))
        })?;
        let ocsp_der = bytes_from_ptr(ocsp_response, ocsp_response_len).map_err(|code| {
            Error::InvalidParam(format!("invalid ocsp_response: code {code}"))
        })?;
        let serial_bytes = bytes_from_ptr(serial, serial_len).map_err(|code| {
            Error::InvalidParam(format!("invalid serial: code {code}"))
        })?;
        if sign_key.is_null() {
            return Err(Error::InvalidParam("sign_key handle is null".into()));
        }
        if tsa_key.is_null() {
            return Err(Error::InvalidParam("tsa_key handle is null".into()));
        }
        let policy = if policy_oid.is_null() {
            None
        } else {
            let s = crate::error::cstr_to_str(policy_oid).map_err(|code| {
                Error::InvalidParam(format!("invalid policy_oid: code {code}"))
            })?;
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        };
        let sign_handle = unsafe { &mut *sign_key };
        let tsa_handle = unsafe { &mut *tsa_key };
        let sa = sign_handle.sign_adapter()?;
        let tsp_sa = tsa_handle.sign_adapter()?;
        let ref_cert = Cert::decode(cert_der)?;
        let full_crl = uacryptex_core::pki::crl::Crl::decode(full_der)?;
        let mut validation_crls = vec![full_crl];
        if delta_crl_len > 0 {
            let delta_der = bytes_from_ptr(delta_crl, delta_crl_len).map_err(|code| {
                Error::InvalidParam(format!("invalid delta_crl: code {code}"))
            })?;
            validation_crls.push(uacryptex_core::pki::crl::Crl::decode(delta_der)?);
        }
        let serial = Int::new(serial_bytes)
            .map_err(|e| Error::Internal(format!("serial integer: {e}")))?;
        let cms = uacryptex_core::pki::cms::build_content_info_cades_a(
            &sa,
            payload,
            OidId::Data,
            &ref_cert,
            &validation_crls,
            ocsp_der,
            &tsp_sa,
            &serial,
            current_time,
            policy.as_deref(),
        )?;
        Ok(UacryptexBuf::from_vec(cms))
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

/// Verify a CMS SignedData signature.
///
/// When `data_len > 0`, verifies the signature over `data` (detached or matching
/// encapsulated content). When `data_len == 0`, verifies encapsulated content only.
#[no_mangle]
pub extern "C" fn uacryptex_cms_verify(
    data: *const u8,
    data_len: usize,
    cms: *const u8,
    cms_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let cms_der = bytes_from_ptr(cms, cms_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cms: code {code}")))?;
        cms_verify_impl(payload, cms_der)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

fn cms_verify_impl(data: &[u8], cms_der: &[u8]) -> Result<(), Error> {
    let sdata = SignedDataContainer::decode(cms_der)?;
    let signer_count = sdata.signer_count();
    if signer_count == 0 {
        return Err(Error::Unsupported("CMS has no signers".into()));
    }

    let internal = sdata.encapsulated_content().ok();
    let use_external = !data.is_empty()
        && internal
            .as_ref()
            .is_none_or(|inner| inner.as_slice() != data);

    if data.is_empty() && internal.is_none() {
        return Err(Error::Unsupported(
            "CMS has no encapsulated content and no external data".into(),
        ));
    }

    let certs = sdata
        .inner()
        .certificates
        .as_ref()
        .ok_or_else(|| Error::Unsupported("CMS has no embedded certificates".into()))?;

    if certs.0.len() < signer_count {
        return Err(Error::InvalidParam(
            "CMS certificate count does not match signer count".into(),
        ));
    }

    for i in 0..signer_count {
        let sinfo = sdata.inner().signer_info(i).ok_or_else(|| {
            Error::InvalidParam("signer info index out of bounds".into())
        })?;
        let cert = certs
            .iter()
            .find_map(|choice| {
                let CertificateChoices::Certificate(c) = choice else {
                    return None;
                };
                let cert = Cert::decode(&c.to_der().ok()?).ok()?;
                cert_matches_signer_id(&cert, &sinfo.sid)
                    .ok()
                    .filter(|&matches| matches)
                    .map(|_| cert)
            })
            .ok_or_else(|| {
                Error::InvalidParam(
                    "no embedded certificate matches signer identifier".into(),
                )
            })?;
        let da = DigestAdapter::init_by_cert(&cert)?;
        let va = VerifyAdapter::init_by_cert(&cert)?;
        if use_external {
            sdata.verify_external_data(data, &da, &va, i)?;
        } else {
            sdata.verify_internal_data(&da, &va, i)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uacryptex_core::pki::cert::Cert;
    use uacryptex_core::pki::cms::build_signed_data;
    use uacryptex_core::pki::crypto::SignAdapter;
    use uacryptex_core::RET_VERIFY_FAILED;

    #[test]
    fn cms_verify_internal_via_ffi() {
        let cert = Cert::decode(include_bytes!(
            "../../../testdata/pki/certificate257.der"
        ))
        .unwrap();
        let key = hex::decode(
            "7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A",
        )
        .unwrap();
        let sa = SignAdapter::init_by_cert(&key, &cert).unwrap();
        let data = b"Status message test";
        let cms = build_signed_data(&sa, data, OidId::Data)
            .unwrap()
            .encode_content_info()
            .unwrap();

        let mut err = UacryptexError::default();
        let rc = uacryptex_cms_verify(
            data.as_ptr(),
            data.len(),
            cms.as_ptr(),
            cms.len(),
            &mut err,
        );
        assert_eq!(rc, RET_OK, "err={err:?}");
    }

    #[test]
    fn cms_verify_rejects_tampered_data() {
        let cert = Cert::decode(include_bytes!(
            "../../../testdata/pki/certificate257.der"
        ))
        .unwrap();
        let key = hex::decode(
            "7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A",
        )
        .unwrap();
        let sa = SignAdapter::init_by_cert(&key, &cert).unwrap();
        let cms = build_signed_data(&sa, b"original", OidId::Data)
            .unwrap()
            .encode_content_info()
            .unwrap();
        let bad = b"tampered";

        let mut err = UacryptexError::default();
        let rc = uacryptex_cms_verify(
            bad.as_ptr(),
            bad.len(),
            cms.as_ptr(),
            cms.len(),
            &mut err,
        );
        assert_eq!(rc, RET_VERIFY_FAILED);
    }
}
