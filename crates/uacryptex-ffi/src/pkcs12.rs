//! PKCS#12 open (`uacryptex_pkcs12_open`) and certificate attach.

use uacryptex_core::storage::pkcs12::{
    pkcs12_decode, pkcs12_get_certificates, pkcs12_select_key, pkcs12_set_certificates,
};
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, cstr_to_str, write_error, UacryptexError};
use crate::handle::{Handle, HandleInner};
use crate::UacryptexHandle;

/// Open a PKCS#12 container and select the first available private key.
///
/// Returns `RET_OK` (0) on success; `*store` receives an opaque handle freed via
/// [`uacryptex_handle_free`].
#[no_mangle]
pub extern "C" fn uacryptex_pkcs12_open(
    data: *const u8,
    data_len: usize,
    password: *const std::os::raw::c_char,
    store: *mut *mut UacryptexHandle,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<*mut UacryptexHandle, Error> {
        check_out(store as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid store pointer: code {code}"))
        })?;
        unsafe {
            if !(*store).is_null() {
                return Err(Error::InvalidParam("store output must be null".into()));
            }
        }
        let der = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid pkcs12 data: code {code}")))?;
        let pass = cstr_to_str(password)
            .map_err(|code| Error::InvalidParam(format!("invalid password: code {code}")))?;
        let mut pkcs12 = pkcs12_decode(None, der, pass)?;
        pkcs12_select_key(&mut pkcs12, None, None)?;
        Ok(Handle {
            inner: HandleInner::Pkcs12(pkcs12),
        }
        .into_raw())
    };

    match run() {
        Ok(handle) => {
            unsafe {
                *store = handle;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Attach an external X.509 certificate to a PKCS#12 store (Cryptonite `pkcs12_set_certificates`).
///
/// May be called multiple times. Required for some containers (e.g. IIT test PFX) where keys
/// are stored without matching certificate bags.
#[no_mangle]
pub extern "C" fn uacryptex_pkcs12_set_certificates(
    store: *mut UacryptexHandle,
    cert: *const u8,
    cert_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        if store.is_null() {
            return Err(Error::InvalidParam("store handle is null".into()));
        }
        let cert_der = bytes_from_ptr(cert, cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid certificate: code {code}")))?;
        let handle = unsafe { &mut *store };
        let pkcs12 = handle.pkcs12_mut()?;
        pkcs12_set_certificates(pkcs12, &[cert_der])?;
        Ok(())
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

/// Return the number of X.509 certificates stored in the PKCS#12 container.
#[no_mangle]
pub extern "C" fn uacryptex_pkcs12_certificate_count(
    store: *mut UacryptexHandle,
    count: *mut usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<usize, Error> {
        check_out(count as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid count pointer: code {code}"))
        })?;
        if store.is_null() {
            return Err(Error::InvalidParam("store handle is null".into()));
        }
        let handle = unsafe { &*store };
        let pkcs12 = handle.pkcs12_ref()?;
        Ok(pkcs12_get_certificates(pkcs12)?.len())
    };

    match run() {
        Ok(n) => {
            unsafe {
                *count = n;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Copy certificate at `index` (0 .. count-1) from PKCS#12 into `out`.
#[no_mangle]
pub extern "C" fn uacryptex_pkcs12_get_certificate(
    store: *mut UacryptexHandle,
    index: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _).map_err(|code| {
            Error::InvalidParam(format!("invalid out pointer: code {code}"))
        })?;
        if store.is_null() {
            return Err(Error::InvalidParam("store handle is null".into()));
        }
        let handle = unsafe { &*store };
        let pkcs12 = handle.pkcs12_ref()?;
        let certs = pkcs12_get_certificates(pkcs12)?;
        let cert = certs
            .get(index)
            .ok_or_else(|| Error::InvalidParam(format!("certificate index {index} out of range")))?;
        Ok(UacryptexBuf::from_vec(cert.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    const IIT_PFX: &[u8] = include_bytes!("../../../testdata/storage/pkcs12_by_iit.pfx");

    #[test]
    fn pkcs12_open_iit_storage() {
        let mut store: *mut UacryptexHandle = std::ptr::null_mut();
        let mut err = UacryptexError::default();
        let rc = uacryptex_pkcs12_open(
            IIT_PFX.as_ptr(),
            IIT_PFX.len(),
            c"123456".as_ptr(),
            &mut store,
            &mut err,
        );
        assert_eq!(rc, RET_OK, "err={err:?}");
        assert!(!store.is_null());
        crate::uacryptex_handle_free(store);
    }
}
