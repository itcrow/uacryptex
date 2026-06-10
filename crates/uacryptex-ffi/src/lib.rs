//! Stable C ABI for uacryptex. All business logic lives in `uacryptex-core`.

#![allow(clippy::not_unsafe_ptr_arg_deref, clippy::large_enum_variant)]

mod buf;
mod cert;
mod cms;
mod crl;
mod csr;
mod digest;
mod dstu4145;
mod enveloped;
mod error;
mod ext;
mod handle;
mod ocsp;
mod pkcs12;
mod pkcs8;
mod sign;
mod tsp;
mod verify;
mod version;

pub use buf::{uacryptex_buf_free, UacryptexBuf};
pub use cert::{
    uacryptex_cert_check_validity, uacryptex_cert_generate, uacryptex_cert_spki,
    uacryptex_cert_verify,
};
pub use cms::{
    uacryptex_cms_sign, uacryptex_cms_sign_cades_a, uacryptex_cms_sign_cades_c,
    uacryptex_cms_sign_cades_lt, uacryptex_cms_sign_cades_t, uacryptex_cms_sign_cades_x,
    uacryptex_cms_sign_cades_xl_type1, uacryptex_cms_sign_cades_xl_type2, uacryptex_cms_verify,
};
pub use crl::{uacryptex_crl_check_cert, uacryptex_crl_generate, uacryptex_crl_verify};
pub use csr::{uacryptex_csr_generate, uacryptex_csr_verify};
pub use digest::uacryptex_digest;
pub use dstu4145::uacryptex_dstu4145_verify_pb;
pub use enveloped::{
    uacryptex_cms_envelop_decrypt, uacryptex_cms_envelop_encrypt,
    uacryptex_cms_envelop_encrypt_with_cipher, UACRYPTEX_CONTENT_CIPHER_GOST28147_CFB,
    UACRYPTEX_CONTENT_CIPHER_KALYNA128_GCM, UACRYPTEX_CONTENT_CIPHER_KALYNA256_GCM,
    UACRYPTEX_CONTENT_CIPHER_KALYNA512_GCM,
};
pub use ext::{
    uacryptex_ext_create_any, uacryptex_ext_create_key_usage,
    uacryptex_ext_create_subj_alt_name, uacryptex_ext_create_subj_alt_name_dns_email,
    UACRYPTEX_GN_DIRECTORY_NAME, UACRYPTEX_GN_DNS_NAME, UACRYPTEX_GN_EDI_PARTY_NAME,
    UACRYPTEX_GN_IP_ADDRESS, UACRYPTEX_GN_OTHER_NAME, UACRYPTEX_GN_REGISTERED_ID,
    UACRYPTEX_GN_RFC822_NAME, UACRYPTEX_GN_URI, UACRYPTEX_GN_X400_ADDRESS,
};
pub use error::{uacryptex_error_init, UacryptexError};
pub use ocsp::{
    uacryptex_ocsp_request_from_cert, uacryptex_ocsp_request_generate,
    uacryptex_ocsp_request_verify, uacryptex_ocsp_response_generate,
    uacryptex_ocsp_response_validate, uacryptex_ocsp_response_verify,
};
pub use pkcs12::{
    uacryptex_pkcs12_certificate_count, uacryptex_pkcs12_get_certificate, uacryptex_pkcs12_open,
    uacryptex_pkcs12_set_certificates,
};
pub use pkcs8::uacryptex_pkcs8_open;
pub use sign::{
    uacryptex_dstu4145_sign, uacryptex_sign_data, uacryptex_sign_hash, uacryptex_sign_open,
};
pub use tsp::{
    uacryptex_tsp_request_from_data, uacryptex_tsp_request_from_hash,
    uacryptex_tsp_response_generate, uacryptex_tsp_response_verify,
};
pub use verify::{uacryptex_dstu4145_verify, uacryptex_verify_data, uacryptex_verify_hash};

pub use version::uacryptex_version;

/// Opaque handle for keys, PKCS#12 sessions, etc.
pub struct UacryptexHandle {
    inner: Option<handle::Handle>,
}

#[no_mangle]
pub extern "C" fn uacryptex_handle_free(handle: *mut UacryptexHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}
