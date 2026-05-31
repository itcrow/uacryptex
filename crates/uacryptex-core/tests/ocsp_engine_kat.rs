//! OCSP engine KAT (`utest_ocsp_request_engine.c`, `utest_ocsp_response_engine.c`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    eocspreq_generate_from_cert, eocspresp_form_internal_error, eocspresp_form_malformed_req,
    eocspresp_form_try_later, eocspresp_form_unauthorized, OcspRequestEngine, OcspResponseEngine,
    ResponderIdType,
};
use uacryptex_core::pki::ocsp::{OcspReq, OcspResponseStatus};

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn eocspreq_generate_signed_request() {
    let root = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let ocsp = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/ocsp_certificate.cer"
    ))
    .unwrap();
    let user = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let private_key =
        include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat");

    let root_va = VerifyAdapter::init_by_cert(&root).unwrap();
    let ocsp_va = VerifyAdapter::init_by_cert(&ocsp).unwrap();
    let user_va = VerifyAdapter::init_by_cert(&user).unwrap();
    let sa = SignAdapter::init_by_cert(private_key, &user).unwrap();
    let da = DigestAdapter::init_default().unwrap();

    let mut engine =
        OcspRequestEngine::alloc(true, &root_va, Some(&ocsp_va), Some(&sa), &da).unwrap();
    engine.add_cert(&user).unwrap();
    let nonce = vec![0xAF; 20];
    let request = engine.generate(Some(&nonce)).unwrap();
    assert!(request.has_signature());
    request.verify(&user_va).unwrap();
}

#[test]
fn eocspreq_generate_from_cert_unsigned() {
    let root = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let user = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userur_certificate.cer"
    ))
    .unwrap();
    let request = eocspreq_generate_from_cert(&root, &user).unwrap();
    assert!(!request.has_signature());
}

#[test]
fn eocspresp_generate_good_status() {
    let root = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let ocsp = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/ocsp_certificate.cer"
    ))
    .unwrap();
    let user = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let ocsp_key = include_bytes!("../../../testdata/pki/pki_example/ocsp_private_key_ba.dat");
    let full = Crl::decode(include_bytes!("../../../testdata/pki/pki_example/full.crl")).unwrap();
    let delta = Crl::decode(include_bytes!(
        "../../../testdata/pki/pki_example/delta.crl"
    ))
    .unwrap();
    let crls = [full, delta];

    let root_va = VerifyAdapter::init_by_cert(&root).unwrap();
    let ocsp_va = VerifyAdapter::init_by_cert(&ocsp).unwrap();
    let req_va = VerifyAdapter::init_by_cert(&user).unwrap();
    let ocsp_sa = SignAdapter::init_by_cert(ocsp_key, &ocsp).unwrap();
    let da = DigestAdapter::init_default().unwrap();

    let mut engine = OcspResponseEngine::alloc(
        &root_va,
        &ocsp_sa,
        &crls,
        &da,
        true,
        true,
        ResponderIdType::ByHashKey,
    )
    .unwrap();
    engine.set_sign_required(true);
    engine.set_crls(&crls).unwrap();

    let request = OcspReq::decode(include_bytes!(
        "../../../testdata/pki/pki_example/ocsp_request.der"
    ))
    .unwrap();
    let current_time = 1_359_151_200;
    let response = engine.generate(&request, &req_va, current_time).unwrap();
    response.verify(&ocsp_va).unwrap();
    assert_eq!(response.response_status(), OcspResponseStatus::Successful);
}

#[test]
fn eocspresp_generate_revoked_and_validate() {
    let root = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let ocsp = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/ocsp_certificate.cer"
    ))
    .unwrap();
    let user = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let user_key = include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat");
    let ocsp_key = include_bytes!("../../../testdata/pki/pki_example/ocsp_private_key_ba.dat");
    let full = Crl::decode(include_bytes!("../../../testdata/pki/pki_example/full.crl")).unwrap();
    let delta = Crl::decode(include_bytes!(
        "../../../testdata/pki/pki_example/delta.crl"
    ))
    .unwrap();
    let crls = [full, delta];

    let root_va = VerifyAdapter::init_by_cert(&root).unwrap();
    let ocsp_va = VerifyAdapter::init_by_cert(&ocsp).unwrap();
    let req_va = VerifyAdapter::init_by_cert(&user).unwrap();
    let ocsp_sa = SignAdapter::init_by_cert(ocsp_key, &ocsp).unwrap();
    let user_sa = SignAdapter::init_by_cert(user_key, &user).unwrap();
    let da = DigestAdapter::init_default().unwrap();

    let mut req_engine =
        OcspRequestEngine::alloc(false, &root_va, Some(&ocsp_va), Some(&user_sa), &da).unwrap();
    req_engine.add_serial(&hex("3468")).unwrap();
    let request = req_engine.generate(None).unwrap();

    let mut resp_engine = OcspResponseEngine::alloc(
        &root_va,
        &ocsp_sa,
        &crls,
        &da,
        true,
        true,
        ResponderIdType::ByName,
    )
    .unwrap();
    resp_engine.set_sign_required(true);
    resp_engine.set_crls(&crls).unwrap();

    let current_time = 1_359_151_200;
    let response = resp_engine
        .generate(&request, &req_va, current_time)
        .unwrap();
    response.verify(&ocsp_va).unwrap();
    assert_eq!(response.response_status(), OcspResponseStatus::Successful);

    let req_engine = OcspRequestEngine::alloc(false, &root_va, None, None, &da).unwrap();
    req_engine
        .validate_response(&response, current_time, 2)
        .unwrap();
}

#[test]
fn eocspresp_form_error_responses() {
    let cases = [
        (
            eocspresp_form_malformed_req(),
            OcspResponseStatus::MalformedRequest,
        ),
        (
            eocspresp_form_internal_error(),
            OcspResponseStatus::InternalError,
        ),
        (eocspresp_form_try_later(), OcspResponseStatus::TryLater),
        (
            eocspresp_form_unauthorized(),
            OcspResponseStatus::Unauthorized,
        ),
    ];
    for (resp, status) in cases {
        assert_eq!(resp.response_status(), status);
        assert!(resp.response_bytes().is_err());
    }
}
