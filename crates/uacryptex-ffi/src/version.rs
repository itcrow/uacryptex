use std::os::raw::c_char;

use uacryptex_core::VERSION;

use crate::error::write_cstr;

#[no_mangle]
pub extern "C" fn uacryptex_version(out: *mut c_char, cap: usize) -> i32 {
    write_cstr(out, cap, VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use uacryptex_core::RET_OK;

    #[test]
    fn version_string() {
        let mut buf = [0i8; 64];
        assert_eq!(uacryptex_version(buf.as_mut_ptr(), buf.len()), RET_OK);
        let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(s.to_str().unwrap(), VERSION);
    }
}
