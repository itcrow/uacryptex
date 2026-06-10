//! X.509 extension builders FFI.

use uacryptex_core::pki::ext::{
    ext_create_any, ext_create_key_usage, ext_create_subj_alt_name_directly,
    ext_create_subj_alt_name_dns_email, ext_to_der, ExtensionValue, GeneralNameKind,
    KeyUsageBits,
};
use uacryptex_core::pki::oid::oid_from_str;
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, cstr_to_str, write_error, UacryptexError};

/// Cryptonite `GeneralName_PR` values for [`uacryptex_ext_create_subj_alt_name`].
pub const UACRYPTEX_GN_OTHER_NAME: i32 = 0;
pub const UACRYPTEX_GN_RFC822_NAME: i32 = 1;
pub const UACRYPTEX_GN_DNS_NAME: i32 = 2;
pub const UACRYPTEX_GN_X400_ADDRESS: i32 = 3;
pub const UACRYPTEX_GN_DIRECTORY_NAME: i32 = 4;
pub const UACRYPTEX_GN_EDI_PARTY_NAME: i32 = 5;
pub const UACRYPTEX_GN_URI: i32 = 6;
pub const UACRYPTEX_GN_IP_ADDRESS: i32 = 7;
pub const UACRYPTEX_GN_REGISTERED_ID: i32 = 8;

fn extension_der(ext: ExtensionValue) -> Result<Vec<u8>, Error> {
    ext_to_der(&ext)
}

fn cstr_array(ptr: *const *const std::os::raw::c_char, count: usize) -> Result<Vec<String>, Error> {
    if count == 0 || ptr.is_null() {
        return Err(Error::InvalidParam("names array is empty".into()));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let item = unsafe { *ptr.add(i) };
        let s = cstr_to_str(item).map_err(|code| {
            Error::InvalidParam(format!("invalid names[{i}] pointer: code {code}"))
        })?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn i32_array(ptr: *const i32, count: usize) -> Result<Vec<GeneralNameKind>, Error> {
    if count == 0 || ptr.is_null() {
        return Err(Error::InvalidParam("types array is empty".into()));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let value = unsafe { *ptr.add(i) };
        out.push(GeneralNameKind::from_i32(value)?);
    }
    Ok(out)
}

/// Build SubjectAltName extension from GeneralName kind / value pairs (extension DER).
#[no_mangle]
pub extern "C" fn uacryptex_ext_create_subj_alt_name(
    critical: i32,
    types: *const i32,
    names: *const *const std::os::raw::c_char,
    count: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let kinds = i32_array(types, count)?;
        let values = cstr_array(names, count)?;
        let name_refs: Vec<&str> = values.iter().map(String::as_str).collect();
        let ext = ext_create_subj_alt_name_directly(critical != 0, &kinds, &name_refs)?;
        Ok(UacryptexBuf::from_vec(extension_der(ext)?))
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

/// Build SubjectAltName with DNS + RFC822 entries (extension DER).
#[no_mangle]
pub extern "C" fn uacryptex_ext_create_subj_alt_name_dns_email(
    critical: i32,
    dns: *const std::os::raw::c_char,
    email: *const std::os::raw::c_char,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let dns = cstr_to_str(dns)
            .map_err(|code| Error::InvalidParam(format!("invalid dns: code {code}")))?;
        let email = cstr_to_str(email)
            .map_err(|code| Error::InvalidParam(format!("invalid email: code {code}")))?;
        let ext = ext_create_subj_alt_name_dns_email(critical != 0, dns, email)?;
        Ok(UacryptexBuf::from_vec(extension_der(ext)?))
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

/// Build keyUsage extension (extension DER). `usage_bits` uses Cryptonite `KeyUsageBits` flags.
#[no_mangle]
pub extern "C" fn uacryptex_ext_create_key_usage(
    critical: i32,
    usage_bits: u32,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let ext = ext_create_key_usage(critical != 0, KeyUsageBits::from_bits(usage_bits))?;
        Ok(UacryptexBuf::from_vec(extension_der(ext)?))
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

/// Build arbitrary X.509 extension from dotted OID and raw extnValue bytes (extension DER).
#[no_mangle]
pub extern "C" fn uacryptex_ext_create_any(
    critical: i32,
    oid: *const std::os::raw::c_char,
    value: *const u8,
    value_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let oid_text = cstr_to_str(oid)
            .map_err(|code| Error::InvalidParam(format!("invalid oid: code {code}")))?;
        let oid_id = oid_from_str(oid_text)
            .ok_or_else(|| Error::InvalidParam(format!("unknown oid: {oid_text}")))?;
        let value = bytes_from_ptr(value, value_len)
            .map_err(|code| Error::InvalidParam(format!("invalid value: code {code}")))?;
        let ext = ext_create_any(critical != 0, oid_id, value)?;
        Ok(UacryptexBuf::from_vec(extension_der(ext)?))
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
