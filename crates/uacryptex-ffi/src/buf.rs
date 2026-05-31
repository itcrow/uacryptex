use std::ptr;

/// Byte buffer owned by Rust; freed via [`uacryptex_buf_free`].
#[repr(C)]
pub struct UacryptexBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl UacryptexBuf {
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let len = v.len();
        let ptr = v.as_mut_ptr();
        std::mem::forget(v);
        Self { ptr, len }
    }

    pub fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn uacryptex_buf_free(buf: UacryptexBuf) {
    if buf.ptr.is_null() || buf.len == 0 {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buf_roundtrip() {
        let buf = UacryptexBuf::from_vec(vec![1, 2, 3]);
        assert_eq!(buf.len, 3);
        uacryptex_buf_free(buf);
    }
}
