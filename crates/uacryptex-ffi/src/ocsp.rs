//! OCSP request/response FFI.

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::{DigestAdapter, VerifyAdapter};
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::engine::{
    eocspreq_generate_from_cert, OcspRequestEngine, OcspResponseEngine, ResponderIdType,
};
use uacryptex_core::pki::ocsp::{OcspReq, OcspResp};
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};
use crate::UacryptexHandle;

/// Build a signed OCSP request for `user_cert` issued by `root_cert`.
#[no_mangle]
pub extern "C" fn uacryptex_ocsp_request_from_cert(
    root_cert: *const u8,
    root_cert_len: usize,
    user_cert: *const u8,
    user_cert_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let root_der = bytes_from_ptr(root_cert, root_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid root_cert: code {code}"))
        })?;
        let user_der = bytes_from_ptr(user_cert, user_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid user_cert: code {code}"))
        })?;
        let root = Cert::decode(root_der)?;
        let user = Cert::decode(user_der)?;
        let req = eocspreq_generate_from_cert(&root, &user)?;
        Ok(UacryptexBuf::from_vec(req.encode()?))
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

/// Build an OCSP request for `user_cert` issued by `root_cert`.
///
/// When `requestor_key` is non-null, the request is signed (CAdES-style requestor cert chain).
/// When null, produces an unsigned request (same as `uacryptex_ocsp_request_from_cert` when nonce enabled).
/// `ocsp_responder_cert` is optional; include in signed request cert chain when set.
/// `include_nonce`: non-zero adds nonce extension; `nonce` may be NULL (20 zero bytes used).
#[no_mangle]
pub extern "C" fn uacryptex_ocsp_request_generate(
    root_cert: *const u8,
    root_cert_len: usize,
    user_cert: *const u8,
    user_cert_len: usize,
    requestor_key: *mut UacryptexHandle,
    ocsp_responder_cert: *const u8,
    ocsp_responder_cert_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    include_nonce: i32,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let root_der = bytes_from_ptr(root_cert, root_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid root_cert: code {code}"))
        })?;
        let user_der = bytes_from_ptr(user_cert, user_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid user_cert: code {code}"))
        })?;
        let root = Cert::decode(root_der)?;
        let user = Cert::decode(user_der)?;
        let da = DigestAdapter::init_default()?;
        let root_va = VerifyAdapter::init_by_cert(&root)?;

        let ocsp_va = if ocsp_responder_cert_len > 0 {
            let ocsp_der = bytes_from_ptr(ocsp_responder_cert, ocsp_responder_cert_len)
                .map_err(|code| {
                    Error::InvalidParam(format!("invalid ocsp_responder_cert: code {code}"))
                })?;
            Some(VerifyAdapter::init_by_cert(&Cert::decode(ocsp_der)?)?)
        } else {
            None
        };

        let requestor_sa = if requestor_key.is_null() {
            None
        } else {
            let handle = unsafe { &mut *requestor_key };
            Some(handle.sign_adapter()?)
        };

        let mut engine = OcspRequestEngine::alloc(
            include_nonce != 0,
            &root_va,
            ocsp_va.as_ref(),
            requestor_sa.as_ref(),
            &da,
        )?;
        engine.add_cert(&user)?;

        let req = if include_nonce != 0 {
            let nonce_bytes = if nonce_len > 0 {
                bytes_from_ptr(nonce, nonce_len).map_err(|code| {
                    Error::InvalidParam(format!("invalid nonce: code {code}"))
                })?
                .to_vec()
            } else {
                vec![0u8; 20]
            };
            engine.generate(Some(&nonce_bytes))?
        } else {
            engine.generate(None)?
        };

        Ok(UacryptexBuf::from_vec(req.encode()?))
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

/// Verify signed OCSP request using requestor certificate.
#[no_mangle]
pub extern "C" fn uacryptex_ocsp_request_verify(
    request: *const u8,
    request_len: usize,
    requestor_cert: *const u8,
    requestor_cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let der = bytes_from_ptr(request, request_len)
            .map_err(|code| Error::InvalidParam(format!("invalid request: code {code}")))?;
        let cert_der = bytes_from_ptr(requestor_cert, requestor_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid requestor_cert: code {code}"))
        })?;
        let req = OcspReq::decode(der)?;
        let cert = Cert::decode(cert_der)?;
        let adapter = VerifyAdapter::init_by_cert(&cert)?;
        req.verify(&adapter)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Verify OCSP response signature using OCSP responder certificate.
#[no_mangle]
pub extern "C" fn uacryptex_ocsp_response_verify(
    response: *const u8,
    response_len: usize,
    ocsp_responder_cert: *const u8,
    ocsp_responder_cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let der = bytes_from_ptr(response, response_len)
            .map_err(|code| Error::InvalidParam(format!("invalid response: code {code}")))?;
        let cert_der = bytes_from_ptr(ocsp_responder_cert, ocsp_responder_cert_len).map_err(
            |code| Error::InvalidParam(format!("invalid ocsp_responder_cert: code {code}")),
        )?;
        let resp = OcspResp::decode(der)?;
        let cert = Cert::decode(cert_der)?;
        let adapter = VerifyAdapter::init_by_cert(&cert)?;
        resp.verify(&adapter)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Validate OCSP response freshness and singleResponse nextUpdate (`OcspRequestEngine::validate_response`).
#[no_mangle]
pub extern "C" fn uacryptex_ocsp_response_validate(
    request: *const u8,
    request_len: usize,
    response: *const u8,
    response_len: usize,
    root_cert: *const u8,
    root_cert_len: usize,
    current_time: i64,
    timeout_minutes: i32,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let req_der = bytes_from_ptr(request, request_len)
            .map_err(|code| Error::InvalidParam(format!("invalid request: code {code}")))?;
        let resp_der = bytes_from_ptr(response, response_len)
            .map_err(|code| Error::InvalidParam(format!("invalid response: code {code}")))?;
        let root_der = bytes_from_ptr(root_cert, root_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid root_cert: code {code}"))
        })?;
        let _request = OcspReq::decode(req_der)?;
        let response = OcspResp::decode(resp_der)?;
        let root = Cert::decode(root_der)?;
        let da = DigestAdapter::init_default()?;
        let root_va = VerifyAdapter::init_by_cert(&root)?;
        let engine = OcspRequestEngine::alloc(false, &root_va, None, None, &da)?;
        engine.validate_response(&response, current_time, timeout_minutes)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Generate OCSP response for a signed request (responder key handle + CRLs).
#[no_mangle]
pub extern "C" fn uacryptex_ocsp_response_generate(
    request: *const u8,
    request_len: usize,
    root_cert: *const u8,
    root_cert_len: usize,
    user_cert: *const u8,
    user_cert_len: usize,
    full_crl: *const u8,
    full_crl_len: usize,
    delta_crl: *const u8,
    delta_crl_len: usize,
    ocsp_key: *mut UacryptexHandle,
    current_time: i64,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        if ocsp_key.is_null() {
            return Err(Error::InvalidParam("ocsp_key handle is null".into()));
        }
        let req_der = bytes_from_ptr(request, request_len)
            .map_err(|code| Error::InvalidParam(format!("invalid request: code {code}")))?;
        let root_der = bytes_from_ptr(root_cert, root_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid root_cert: code {code}"))
        })?;
        let user_der = bytes_from_ptr(user_cert, user_cert_len).map_err(|code| {
            Error::InvalidParam(format!("invalid user_cert: code {code}"))
        })?;
        let full_der = bytes_from_ptr(full_crl, full_crl_len)
            .map_err(|code| Error::InvalidParam(format!("invalid full_crl: code {code}")))?;
        let request = OcspReq::decode(req_der)?;
        let root = Cert::decode(root_der)?;
        let user = Cert::decode(user_der)?;
        let full = Crl::decode(full_der)?;
        let mut crls = vec![full];
        if delta_crl_len > 0 {
            let delta_der = bytes_from_ptr(delta_crl, delta_crl_len).map_err(|code| {
                Error::InvalidParam(format!("invalid delta_crl: code {code}"))
            })?;
            crls.push(Crl::decode(delta_der)?);
        }
        let da = DigestAdapter::init_default()?;
        let root_va = VerifyAdapter::init_by_cert(&root)?;
        let user_va = VerifyAdapter::init_by_cert(&user)?;
        let handle = unsafe { &mut *ocsp_key };
        let ocsp_sa = handle.sign_adapter()?;
        let mut engine = OcspResponseEngine::alloc(
            &root_va,
            &ocsp_sa,
            &crls,
            &da,
            true,
            true,
            ResponderIdType::ByHashKey,
        )?;
        engine.set_sign_required(request.has_signature());
        engine.set_crls(&crls)?;
        let response = engine.generate(&request, &user_va, current_time)?;
        Ok(UacryptexBuf::from_vec(response.encode()?))
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
