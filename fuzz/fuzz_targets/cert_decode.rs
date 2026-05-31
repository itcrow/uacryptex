#![no_main]

use libfuzzer_sys::fuzz_target;
use uacryptex_core::pki::cert::Cert;

fuzz_target!(|data: &[u8]| {
    let _ = Cert::decode(data);
});
