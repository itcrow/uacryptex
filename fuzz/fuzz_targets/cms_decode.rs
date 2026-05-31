#![no_main]

use libfuzzer_sys::fuzz_target;
use uacryptex_core::pki::cms::SignedDataContainer;

fuzz_target!(|data: &[u8]| {
    let _ = SignedDataContainer::decode(data);
});
