//! TSP (RFC 3161) request/response FFI.

use der::asn1::Int;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::{DigestAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    default_tsp_digest_aids, etspreq_generate, etspreq_generate_from_gost34311, etspresp_generate,
    TspAdapterMap,
};
use uacryptex_core::pki::tsp::TspResp;
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, cstr_to_str, check_out, write_error, UacryptexError};
use crate::UacryptexHandle;

const DEFAULT_POLICY_OID: &str = "1.2.804.2.1.1.1.2.3.1";

fn parse_policy_oid(policy: *const std::os::raw::c_char) -> Result<String, Error> {
    if policy.is_null() {
        return Ok(DEFAULT_POLICY_OID.to_string());
    }
    let s = cstr_to_str(policy).map_err(|code| {
        Error::InvalidParam(format!("invalid policy oid: code {code}"))
    })?;
    if s.is_empty() {
        Ok(DEFAULT_POLICY_OID.to_string())
    } else {
        Ok(s.to_string())
    }
}

/// Build TSP request from raw data (GOST3411 hash of `data`).
#[no_mangle]
pub extern "C" fn uacryptex_tsp_request_from_data(
    data: *const u8,
    data_len: usize,
    policy_oid: *const std::os::raw::c_char,
    cert_req: i32,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let data = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let policy = parse_policy_oid(policy_oid)?;
        let da = DigestAdapter::init_default()?;
        let oid = der::asn1::ObjectIdentifier::new(&policy)
            .map_err(|e| Error::Internal(format!("policy oid: {e}")))?;
        let req = etspreq_generate(&da, data, None, &oid, cert_req != 0)?;
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

/// Build TSP request from precomputed GOST3411 digest.
#[no_mangle]
pub extern "C" fn uacryptex_tsp_request_from_hash(
    hash: *const u8,
    hash_len: usize,
    policy_oid: *const std::os::raw::c_char,
    cert_req: i32,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        let hash = bytes_from_ptr(hash, hash_len)
            .map_err(|code| Error::InvalidParam(format!("invalid hash: code {code}")))?;
        let policy = parse_policy_oid(policy_oid)?;
        let req = etspreq_generate_from_gost34311(hash, &policy, cert_req != 0)?;
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

/// Verify TSP response token signature using TSA certificate.
#[no_mangle]
pub extern "C" fn uacryptex_tsp_response_verify(
    response: *const u8,
    response_len: usize,
    tsa_cert: *const u8,
    tsa_cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let der = bytes_from_ptr(response, response_len)
            .map_err(|code| Error::InvalidParam(format!("invalid response: code {code}")))?;
        let cert_der = bytes_from_ptr(tsa_cert, tsa_cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid tsa_cert: code {code}")))?;
        let resp = TspResp::decode(der)?;
        let cert = Cert::decode(cert_der)?;
        let da = DigestAdapter::init_default()?;
        let va = VerifyAdapter::init_by_cert(&cert)?;
        resp.verify(&da, &va)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Generate TSP response for `request` using TSA private key handle.
#[no_mangle]
pub extern "C" fn uacryptex_tsp_response_generate(
    request: *const u8,
    request_len: usize,
    key: *mut UacryptexHandle,
    serial: *const u8,
    serial_len: usize,
    current_time: i64,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        if key.is_null() {
            return Err(Error::InvalidParam("key handle is null".into()));
        }
        let req_der = bytes_from_ptr(request, request_len)
            .map_err(|code| Error::InvalidParam(format!("invalid request: code {code}")))?;
        let serial = bytes_from_ptr(serial, serial_len)
            .map_err(|code| Error::InvalidParam(format!("invalid serial: code {code}")))?;
        let handle = unsafe { &mut *key };
        let sa = handle.sign_adapter()?;
        let da = DigestAdapter::init_default()?;
        let mut map = TspAdapterMap::new();
        map.add(da.clone_state()?, sa);
        let sn = Int::new(serial).map_err(|e| Error::Internal(format!("serial int: {e}")))?;
        let digest_aids = default_tsp_digest_aids()?;
        let resp = etspresp_generate(&map, req_der, &sn, &digest_aids, current_time)?;
        Ok(UacryptexBuf::from_vec(resp.encode()?))
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
