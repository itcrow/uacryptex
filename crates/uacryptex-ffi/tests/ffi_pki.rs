//! End-to-end FFI: PKCS#12 / sign open → CMS sign → CMS verify.

use uacryptex_core::RET_OK;
use uacryptex_ffi::{
    uacryptex_buf_free, uacryptex_cms_sign, uacryptex_cms_verify, uacryptex_handle_free,
    uacryptex_pkcs12_open, uacryptex_sign_open, UacryptexBuf, UacryptexError, UacryptexHandle,
};

const IIT_PFX: &[u8] = include_bytes!("../../../testdata/storage/pkcs12_by_iit.pfx");
const USERFIZ_CERT: &[u8] =
    include_bytes!("../../../testdata/pki/pki_example/userfiz_certificate.cer");
const USERFIZ_KEY: &[u8] =
    include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat");

#[test]
fn ffi_pkcs12_open_iit_storage() {
    let mut store: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_pkcs12_open(
        IIT_PFX.as_ptr(),
        IIT_PFX.len(),
        c"123456".as_ptr(),
        &mut store,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "open err={err:?}");
    assert!(!store.is_null());
    uacryptex_handle_free(store);
}

#[test]
fn ffi_cms_sign_verify_roundtrip() {
    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let data = [0xf0; 100];
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_sign(data.as_ptr(), data.len(), key, &mut cms, &mut err);
    assert_eq!(rc, RET_OK, "sign err={err:?}");

    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.ptr, cms.len, &mut err);
    assert_eq!(rc, RET_OK, "verify err={err:?}");

    uacryptex_buf_free(cms);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cms_sign_cades_t_verify() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cms_sign_cades_t, uacryptex_cms_verify,
        uacryptex_handle_free, uacryptex_sign_open,
    };

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let data = [0xf0; 100];
    let serial = 128u8.to_be_bytes();
    let tsp_time = 1_359_151_200i64;
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_sign_cades_t(
        data.as_ptr(),
        data.len(),
        key,
        key,
        serial.as_ptr(),
        serial.len(),
        tsp_time,
        std::ptr::null(),
        &mut cms,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cms_sign_cades_t err={err:?}");

    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.ptr, cms.len, &mut err);
    assert_eq!(rc, RET_OK, "cms_verify err={err:?}");

    uacryptex_buf_free(cms);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cms_sign_cades_c_verify() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cms_sign_cades_c, uacryptex_cms_verify,
        uacryptex_handle_free, uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let data = [0xf0; 100];
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_sign_cades_c(
        data.as_ptr(),
        data.len(),
        key,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        &mut cms,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cms_sign_cades_c err={err:?}");

    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.ptr, cms.len, &mut err);
    assert_eq!(rc, RET_OK, "verify err={err:?}");

    uacryptex_buf_free(cms);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cms_sign_cades_x_verify() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cms_sign_cades_x, uacryptex_cms_verify,
        uacryptex_handle_free, uacryptex_ocsp_request_from_cert, uacryptex_ocsp_response_generate,
        uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const OCSP_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_certificate.cer");
    const OCSP_KEY: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_private_key_ba.dat");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");
    const DELTA_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/delta.crl");

    let mut err = UacryptexError::default();
    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let mut req = UacryptexBuf::empty();
    let rc = uacryptex_ocsp_request_from_cert(
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut req,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp request err={err:?}");

    let mut ocsp_key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        OCSP_KEY.as_ptr(),
        OCSP_KEY.len(),
        OCSP_CERT.as_ptr(),
        OCSP_CERT.len(),
        &mut ocsp_key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp key err={err:?}");

    let mut ocsp_resp = UacryptexBuf::empty();
    let ocsp_time = 1_359_151_200i64;
    let rc = uacryptex_ocsp_response_generate(
        req.ptr,
        req.len,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        ocsp_key,
        ocsp_time,
        &mut ocsp_resp,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp generate err={err:?}");

    let data = [0xf0; 100];
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_sign_cades_x(
        data.as_ptr(),
        data.len(),
        key,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        ocsp_resp.ptr,
        ocsp_resp.len,
        &mut cms,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cms_sign_cades_x err={err:?}");

    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.ptr, cms.len, &mut err);
    assert_eq!(rc, RET_OK, "verify err={err:?}");

    uacryptex_buf_free(cms);
    uacryptex_buf_free(ocsp_resp);
    uacryptex_buf_free(req);
    uacryptex_handle_free(ocsp_key);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cms_sign_cades_xl_type1_verify() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cms_sign_cades_xl_type1, uacryptex_cms_verify,
        uacryptex_handle_free, uacryptex_ocsp_request_from_cert, uacryptex_ocsp_response_generate,
        uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const OCSP_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_certificate.cer");
    const OCSP_KEY: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_private_key_ba.dat");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");
    const DELTA_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/delta.crl");

    let mut err = UacryptexError::default();
    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let mut req = UacryptexBuf::empty();
    let rc = uacryptex_ocsp_request_from_cert(
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut req,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp request err={err:?}");

    let mut ocsp_key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        OCSP_KEY.as_ptr(),
        OCSP_KEY.len(),
        OCSP_CERT.as_ptr(),
        OCSP_CERT.len(),
        &mut ocsp_key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp key err={err:?}");

    let mut ocsp_resp = UacryptexBuf::empty();
    let tsp_time = 1_359_151_200i64;
    let rc = uacryptex_ocsp_response_generate(
        req.ptr,
        req.len,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        ocsp_key,
        tsp_time,
        &mut ocsp_resp,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp generate err={err:?}");

    let data = [0xf0; 100];
    let serial = 128u8.to_be_bytes();
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_sign_cades_xl_type1(
        data.as_ptr(),
        data.len(),
        key,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        ocsp_resp.ptr,
        ocsp_resp.len,
        key,
        serial.as_ptr(),
        serial.len(),
        tsp_time,
        std::ptr::null(),
        &mut cms,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cms_sign_cades_xl_type1 err={err:?}");

    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.ptr, cms.len, &mut err);
    assert_eq!(rc, RET_OK, "verify err={err:?}");

    uacryptex_buf_free(cms);
    uacryptex_buf_free(ocsp_resp);
    uacryptex_buf_free(req);
    uacryptex_handle_free(ocsp_key);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cms_sign_cades_a_verify() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cms_sign_cades_a, uacryptex_cms_verify,
        uacryptex_handle_free, uacryptex_ocsp_request_from_cert, uacryptex_ocsp_response_generate,
        uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const OCSP_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_certificate.cer");
    const OCSP_KEY: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_private_key_ba.dat");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");
    const DELTA_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/delta.crl");

    let mut err = UacryptexError::default();
    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let mut req = UacryptexBuf::empty();
    let rc = uacryptex_ocsp_request_from_cert(
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut req,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp request err={err:?}");

    let mut ocsp_key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        OCSP_KEY.as_ptr(),
        OCSP_KEY.len(),
        OCSP_CERT.as_ptr(),
        OCSP_CERT.len(),
        &mut ocsp_key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp key err={err:?}");

    let mut ocsp_resp = UacryptexBuf::empty();
    let ocsp_time = 1_359_151_200i64;
    let rc = uacryptex_ocsp_response_generate(
        req.ptr,
        req.len,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        ocsp_key,
        ocsp_time,
        &mut ocsp_resp,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp generate err={err:?}");

    let data = [0xf0; 100];
    let serial = 128u8.to_be_bytes();
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_sign_cades_a(
        data.as_ptr(),
        data.len(),
        key,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        ocsp_resp.ptr,
        ocsp_resp.len,
        key,
        serial.as_ptr(),
        serial.len(),
        ocsp_time,
        std::ptr::null(),
        &mut cms,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cms_sign_cades_a err={err:?}");

    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.ptr, cms.len, &mut err);
    assert_eq!(rc, RET_OK, "verify err={err:?}");

    uacryptex_buf_free(cms);
    uacryptex_buf_free(ocsp_resp);
    uacryptex_buf_free(req);
    uacryptex_handle_free(ocsp_key);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cms_envelop_roundtrip() {
    use uacryptex_ffi::{
        uacryptex_cms_envelop_decrypt, uacryptex_cms_envelop_encrypt, uacryptex_sign_open,
    };

    const USERUR_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/userur_certificate.cer");
    const USERUR_KEY: &[u8] = include_bytes!("../../../testdata/pki/userur_private_key.dat");

    let mut originator: *mut UacryptexHandle = std::ptr::null_mut();
    let mut recipient: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut originator,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "originator open err={err:?}");
    let rc = uacryptex_sign_open(
        USERUR_KEY.as_ptr(),
        USERUR_KEY.len(),
        USERUR_CERT.as_ptr(),
        USERUR_CERT.len(),
        &mut recipient,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "recipient open err={err:?}");

    let plaintext = b"Status message for enveloped data test";
    let mut cms = UacryptexBuf::empty();
    let rc = uacryptex_cms_envelop_encrypt(
        plaintext.as_ptr(),
        plaintext.len(),
        originator,
        USERUR_CERT.as_ptr(),
        USERUR_CERT.len(),
        &mut cms,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "encrypt err={err:?}");

    let mut out = UacryptexBuf::empty();
    let rc = uacryptex_cms_envelop_decrypt(
        cms.ptr,
        cms.len,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        recipient,
        USERUR_CERT.as_ptr(),
        USERUR_CERT.len(),
        &mut out,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "decrypt err={err:?}");
    assert_eq!(
        unsafe { std::slice::from_raw_parts(out.ptr, out.len) },
        plaintext
    );

    uacryptex_buf_free(out);
    uacryptex_buf_free(cms);
    uacryptex_handle_free(originator);
    uacryptex_handle_free(recipient);
}

#[test]
fn ffi_cms_verify_pki_example_vector() {
    let data = [0xf0; 100];
    let cert = uacryptex_core::pki::cert::Cert::decode(USERFIZ_CERT).unwrap();
    let sa = uacryptex_core::pki::crypto::SignAdapter::init_by_cert(USERFIZ_KEY, &cert).unwrap();
    let cms = uacryptex_core::pki::cms::build_content_info(
        &sa,
        &data,
        uacryptex_core::pki::oid::OidId::Data,
    )
    .unwrap();

    let mut err = UacryptexError::default();
    let rc = uacryptex_cms_verify(data.as_ptr(), data.len(), cms.as_ptr(), cms.len(), &mut err);
    assert_eq!(rc, RET_OK, "verify err={err:?}");
}

#[test]
fn ffi_sign_data_verify_data_roundtrip() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_sign_data, uacryptex_sign_open, uacryptex_verify_data,
    };

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let data = b"detached signature payload";
    let mut sig = UacryptexBuf::empty();
    let rc = uacryptex_sign_data(data.as_ptr(), data.len(), key, &mut sig, &mut err);
    assert_eq!(rc, RET_OK, "sign_data err={err:?}");

    let rc = uacryptex_verify_data(
        data.as_ptr(),
        data.len(),
        sig.ptr,
        sig.len,
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "verify_data err={err:?}");

    uacryptex_buf_free(sig);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_digest_default_gost3411() {
    use uacryptex_ffi::uacryptex_buf_free;
    use uacryptex_ffi::uacryptex_digest;

    let data = b"hash me";
    let mut out = UacryptexBuf::empty();
    let mut err = UacryptexError::default();
    let rc = uacryptex_digest(
        data.as_ptr(),
        data.len(),
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "digest err={err:?}");
    assert_eq!(out.len, 32, "GOST3411-256 digest length");

    uacryptex_buf_free(out);
}

#[test]
fn ffi_cert_and_crl_helpers() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cert_spki, uacryptex_cert_verify, uacryptex_crl_check_cert,
        uacryptex_crl_verify,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");

    let mut err = UacryptexError::default();
    let rc = uacryptex_cert_verify(
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cert_verify err={err:?}");

    let mut spki = UacryptexBuf::empty();
    let rc = uacryptex_cert_spki(
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut spki,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cert_spki err={err:?}");
    assert!(!spki.ptr.is_null() && spki.len > 0);
    uacryptex_buf_free(spki);

    let rc = uacryptex_crl_verify(
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "crl_verify err={err:?}");

    let mut revoked: i32 = -1;
    let rc = uacryptex_crl_check_cert(
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut revoked,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "crl_check_cert err={err:?}");
    assert_eq!(revoked, 0, "userfiz should not be on full CRL");
}

#[test]
fn ffi_ocsp_roundtrip() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_ocsp_request_from_cert, uacryptex_ocsp_response_generate,
        uacryptex_ocsp_response_validate, uacryptex_ocsp_response_verify, uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const OCSP_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_certificate.cer");
    const OCSP_KEY: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_private_key_ba.dat");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");
    const DELTA_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/delta.crl");

    let mut err = UacryptexError::default();
    let mut req = UacryptexBuf::empty();
    let rc = uacryptex_ocsp_request_from_cert(
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut req,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp request err={err:?}");

    let mut ocsp_key: *mut UacryptexHandle = std::ptr::null_mut();
    let rc = uacryptex_sign_open(
        OCSP_KEY.as_ptr(),
        OCSP_KEY.len(),
        OCSP_CERT.as_ptr(),
        OCSP_CERT.len(),
        &mut ocsp_key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp key open err={err:?}");

    let mut resp = UacryptexBuf::empty();
    let ocsp_time = 1_359_151_200i64;
    let rc = uacryptex_ocsp_response_generate(
        req.ptr,
        req.len,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        ocsp_key,
        ocsp_time,
        &mut resp,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp generate err={err:?}");

    let rc = uacryptex_ocsp_response_verify(
        resp.ptr,
        resp.len,
        OCSP_CERT.as_ptr(),
        OCSP_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp verify err={err:?}");

    let rc = uacryptex_ocsp_response_validate(
        req.ptr,
        req.len,
        resp.ptr,
        resp.len,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        ocsp_time,
        2,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp validate err={err:?}");

    uacryptex_buf_free(req);
    uacryptex_buf_free(resp);
    uacryptex_handle_free(ocsp_key);
}

#[test]
fn ffi_ocsp_signed_request() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_ocsp_request_generate, uacryptex_ocsp_request_verify,
        uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const OCSP_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/ocsp_certificate.cer");

    let mut user_key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut user_key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let nonce = [0xAFu8; 20];
    let mut req = UacryptexBuf::empty();
    let rc = uacryptex_ocsp_request_generate(
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        user_key,
        OCSP_CERT.as_ptr(),
        OCSP_CERT.len(),
        nonce.as_ptr(),
        nonce.len(),
        1,
        &mut req,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp signed request err={err:?}");

    let rc = uacryptex_ocsp_request_verify(
        req.ptr,
        req.len,
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "ocsp request verify err={err:?}");

    uacryptex_buf_free(req);
    uacryptex_handle_free(user_key);
}

#[test]
fn ffi_tsp_roundtrip() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_tsp_request_from_data, uacryptex_tsp_response_generate,
        uacryptex_tsp_response_verify,
    };

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let data = b"timestamp this message";
    let mut req = UacryptexBuf::empty();
    let rc = uacryptex_tsp_request_from_data(
        data.as_ptr(),
        data.len(),
        std::ptr::null(),
        1,
        &mut req,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "tsp request err={err:?}");

    let serial = 128u8.to_be_bytes();
    let tsp_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut resp = UacryptexBuf::empty();
    let rc = uacryptex_tsp_response_generate(
        req.ptr,
        req.len,
        key,
        serial.as_ptr(),
        serial.len(),
        tsp_time,
        &mut resp,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "tsp generate err={err:?}");

    let rc = uacryptex_tsp_response_verify(
        resp.ptr,
        resp.len,
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "tsp verify err={err:?}");

    uacryptex_buf_free(req);
    uacryptex_buf_free(resp);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_csr_generate_verify() {
    use uacryptex_ffi::{uacryptex_buf_free, uacryptex_csr_generate, uacryptex_csr_verify};

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let subject = c"{CN=Test User}{C=UA}";
    let mut csr = UacryptexBuf::empty();
    let rc = uacryptex_csr_generate(
        key,
        subject.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        &mut csr,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "csr generate err={err:?}");

    let rc = uacryptex_csr_verify(csr.ptr, csr.len, &mut err);
    assert_eq!(rc, RET_OK, "csr verify err={err:?}");

    uacryptex_buf_free(csr);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_cert_generate_self_signed() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_cert_check_validity, uacryptex_cert_generate,
        uacryptex_cert_verify, uacryptex_csr_generate, uacryptex_sign_open,
    };

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        USERFIZ_KEY.as_ptr(),
        USERFIZ_KEY.len(),
        USERFIZ_CERT.as_ptr(),
        USERFIZ_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let subject = c"{CN=FFI Generated}{C=UA}";
    let mut csr = UacryptexBuf::empty();
    let rc = uacryptex_csr_generate(
        key,
        subject.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        &mut csr,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "csr err={err:?}");

    let serial = [0x01u8, 0x02, 0x03, 0x04];
    let mut cert = UacryptexBuf::empty();
    let rc = uacryptex_cert_generate(
        key,
        csr.ptr,
        csr.len,
        2,
        serial.as_ptr(),
        serial.len(),
        1_350_000_000,
        2_000_000_000,
        1,
        &mut cert,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "cert_generate err={err:?}");

    let rc = uacryptex_cert_verify(cert.ptr, cert.len, cert.ptr, cert.len, &mut err);
    assert_eq!(rc, RET_OK, "cert_verify err={err:?}");

    let rc = uacryptex_cert_check_validity(cert.ptr, cert.len, 0, &mut err);
    assert_eq!(rc, RET_OK, "validity err={err:?}");

    uacryptex_buf_free(csr);
    uacryptex_buf_free(cert);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_crl_generate_full_merge() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_crl_generate, uacryptex_crl_verify, uacryptex_handle_free,
        uacryptex_sign_open,
    };

    const ROOT_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_certificate.cer");
    const ROOT_KEY: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/root_private_key_ba.dat");
    const FULL_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/full.crl");
    const DELTA_CRL: &[u8] = include_bytes!("../../../testdata/pki/pki_example/delta.crl");

    let mut key: *mut UacryptexHandle = std::ptr::null_mut();
    let mut err = UacryptexError::default();
    let rc = uacryptex_sign_open(
        ROOT_KEY.as_ptr(),
        ROOT_KEY.len(),
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        &mut key,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "sign_open err={err:?}");

    let mut crl = UacryptexBuf::empty();
    let rc = uacryptex_crl_generate(
        key,
        FULL_CRL.as_ptr(),
        FULL_CRL.len(),
        1,
        60 * 60 * 24 * 7,
        DELTA_CRL.as_ptr(),
        DELTA_CRL.len(),
        std::ptr::null(),
        0,
        c"crl_full_templ".as_ptr(),
        c"description".as_ptr(),
        &mut crl,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "crl_generate err={err:?}");

    let rc = uacryptex_crl_verify(
        crl.ptr,
        crl.len,
        ROOT_CERT.as_ptr(),
        ROOT_CERT.len(),
        &mut err,
    );
    assert_eq!(rc, RET_OK, "crl_verify err={err:?}");

    uacryptex_buf_free(crl);
    uacryptex_handle_free(key);
}

#[test]
fn ffi_ext_create_subj_alt_name_and_key_usage() {
    use uacryptex_ffi::{
        uacryptex_buf_free, uacryptex_ext_create_key_usage, uacryptex_ext_create_subj_alt_name,
        uacryptex_ext_create_subj_alt_name_dns_email, UACRYPTEX_GN_DNS_NAME,
        UACRYPTEX_GN_RFC822_NAME,
    };

    let mut err = UacryptexError::default();
    let dns = c"ca.ua";
    let email = c"info@ca.ua";
    let mut san = UacryptexBuf::empty();
    let rc = uacryptex_ext_create_subj_alt_name_dns_email(0, dns.as_ptr(), email.as_ptr(), &mut san, &mut err);
    assert_eq!(rc, RET_OK, "san dns/email err={err:?}");
    assert!(san.len > 0);
    uacryptex_buf_free(san);

    let types = [UACRYPTEX_GN_DNS_NAME, UACRYPTEX_GN_RFC822_NAME];
    let names = [dns.as_ptr(), email.as_ptr()];
    let mut san2 = UacryptexBuf::empty();
    let rc = uacryptex_ext_create_subj_alt_name(
        0,
        types.as_ptr(),
        names.as_ptr(),
        2,
        &mut san2,
        &mut err,
    );
    assert_eq!(rc, RET_OK, "san kinds err={err:?}");
    assert!(san2.len > 0);
    uacryptex_buf_free(san2);

    let mut ku = UacryptexBuf::empty();
    let rc = uacryptex_ext_create_key_usage(1, 0x60, &mut ku, &mut err);
    assert_eq!(rc, RET_OK, "key usage err={err:?}");
    assert!(ku.len > 0);
    uacryptex_buf_free(ku);
}
