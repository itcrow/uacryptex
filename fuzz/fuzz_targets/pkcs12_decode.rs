#![no_main]

use libfuzzer_sys::fuzz_target;
use uacryptex_core::storage::pkcs12::pkcs12_decode;

fuzz_target!(|data: &[u8]| {
    let _ = pkcs12_decode(None, data, "fuzz");
});
