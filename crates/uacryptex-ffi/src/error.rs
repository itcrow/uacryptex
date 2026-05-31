use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use uacryptex_core::{Error, RET_INVALID_PARAM, RET_OK};

/// FFI error payload.
#[derive(Debug)]
#[repr(C)]
pub struct UacryptexError {
    pub code: i32,
    pub message: [c_char; 256],
}

impl Default for UacryptexError {
    fn default() -> Self {
        Self {
            code: RET_OK,
            message: [0; 256],
        }
    }
}

/// Initialize `err` to success (code 0, empty message).
///
/// # Safety
///
/// `err` must be a valid pointer to a writable `UacryptexError`, or null (no-op).
#[no_mangle]
pub unsafe extern "C" fn uacryptex_error_init(err: *mut UacryptexError) {
    unsafe {
        if err.is_null() {
            return;
        }
        *err = UacryptexError::default();
    }
}

pub fn write_error(err: *mut UacryptexError, error: Error) -> i32 {
    let code = error.code();
    if !err.is_null() {
        unsafe {
            (*err).code = code;
            let mut msg = [0u8; 256];
            error.write_message(&mut msg);
            for (i, b) in msg.iter().enumerate() {
                (*err).message[i] = *b as c_char;
            }
        }
    }
    code
}

#[allow(dead_code)] // reserved for upcoming FFI entry points
pub fn check_out<T>(out: *mut T) -> Result<(), i32> {
    if out.is_null() {
        Err(RET_INVALID_PARAM)
    } else {
        Ok(())
    }
}

#[allow(dead_code)] // reserved for upcoming FFI entry points
pub fn cstr_to_str<'a>(s: *const c_char) -> Result<&'a str, i32> {
    if s.is_null() {
        return Err(RET_INVALID_PARAM);
    }
    unsafe { CStr::from_ptr(s).to_str().map_err(|_| RET_INVALID_PARAM) }
}

/// Read a byte slice from FFI pointer/length (null only allowed when `len == 0`).
pub fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(RET_INVALID_PARAM);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

pub fn u32_slice_from_ptr<'a>(ptr: *const u32, len: usize) -> Result<&'a [u32], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(RET_INVALID_PARAM);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

pub fn write_cstr(out: *mut c_char, cap: usize, value: &str) -> i32 {
    if out.is_null() || cap == 0 {
        return RET_INVALID_PARAM;
    }
    let bytes = value.as_bytes();
    let len = bytes.len().min(cap - 1);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, len);
        *out.add(len) = 0;
    }
    RET_OK
}
