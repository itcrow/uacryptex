//! CAdES profile KAT (T / C / X / LT unsigned attributes).

use der::asn1::Int;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::{
    build_content_info_cades_c, build_content_info_cades_lt, build_content_info_cades_t,
    build_content_info_cades_x, SignedDataContainer,
};
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{OcspResponseEngine, ResponderIdType};
use uacryptex_core::pki::ocsp::{OcspReq, OcspResponseStatus};
use uacryptex_core::pki::oid::OidId;

fn userfiz_adapters() -> (SignAdapter, VerifyAdapter) {
    let cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let key = include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat");
    let sa = SignAdapter::init_by_cert(key, &cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    (sa, va)
}

fn pki_example_ocsp_response() -> Vec<u8> {
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
    let response = engine.generate(&request, &req_va, 1_359_151_200).unwrap();
    response.verify(&ocsp_va).unwrap();
    assert_eq!(response.response_status(), OcspResponseStatus::Successful);
    response.encode().unwrap()
}

#[test]
fn cades_t_build_and_verify_bes() {
    let (sa, va) = userfiz_adapters();
    let data = vec![0xf0; 100];
    let serial = Int::new(&128u8.to_be_bytes()).unwrap();
    let tsp_time = 1_359_151_200i64;

    let cms =
        build_content_info_cades_t(&sa, &data, OidId::Data, &sa, &serial, tsp_time, None).unwrap();

    let container = SignedDataContainer::decode(&cms).unwrap();
    let sinfo = container.inner().signer_info(0).unwrap();
    assert!(sinfo.unsigned_attrs.is_some());
    assert!(!sinfo.unsigned_attrs.as_ref().unwrap().is_empty());

    let da = DigestAdapter::init_by_cert(sa.cert().unwrap()).unwrap();
    container.verify_internal_data(&da, &va, 0).unwrap();
}

#[test]
fn cades_c_build_and_verify_bes() {
    let (sa, va) = userfiz_adapters();
    let root_cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let full_crl =
        Crl::decode(include_bytes!("../../../testdata/pki/pki_example/full.crl")).unwrap();
    let data = vec![0xf0; 100];

    let cms = build_content_info_cades_c(&sa, &data, OidId::Data, &root_cert, &full_crl).unwrap();

    let container = SignedDataContainer::decode(&cms).unwrap();
    let sinfo = container.inner().signer_info(0).unwrap();
    let attrs = sinfo.unsigned_attrs.as_ref().unwrap();
    assert_eq!(attrs.len(), 2);

    let da = DigestAdapter::init_by_cert(sa.cert().unwrap()).unwrap();
    container.verify_internal_data(&da, &va, 0).unwrap();
}

#[test]
fn cades_x_build_and_verify_bes() {
    let (sa, va) = userfiz_adapters();
    let root_cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let ocsp_response = pki_example_ocsp_response();
    let data = vec![0xf0; 100];

    let cms =
        build_content_info_cades_x(&sa, &data, OidId::Data, &root_cert, &ocsp_response).unwrap();

    let container = SignedDataContainer::decode(&cms).unwrap();
    let sinfo = container.inner().signer_info(0).unwrap();
    assert_eq!(sinfo.unsigned_attrs.as_ref().unwrap().len(), 2);

    let da = DigestAdapter::init_by_cert(sa.cert().unwrap()).unwrap();
    container.verify_internal_data(&da, &va, 0).unwrap();
}

#[test]
fn cades_lt_build_and_verify_bes() {
    let (sa, va) = userfiz_adapters();
    let root_cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let full_crl =
        Crl::decode(include_bytes!("../../../testdata/pki/pki_example/full.crl")).unwrap();
    let delta_crl = Crl::decode(include_bytes!(
        "../../../testdata/pki/pki_example/delta.crl"
    ))
    .unwrap();
    let ocsp_response = pki_example_ocsp_response();
    let data = vec![0xf0; 100];

    let cms = build_content_info_cades_lt(
        &sa,
        &data,
        OidId::Data,
        &root_cert,
        &[full_crl, delta_crl],
        &ocsp_response,
    )
    .unwrap();

    let container = SignedDataContainer::decode(&cms).unwrap();
    assert!(container.has_certs());
    assert!(container.has_crls());
    let sinfo = container.inner().signer_info(0).unwrap();
    assert_eq!(sinfo.unsigned_attrs.as_ref().unwrap().len(), 2);

    let da = DigestAdapter::init_by_cert(sa.cert().unwrap()).unwrap();
    container.verify_internal_data(&da, &va, 0).unwrap();
}

#[test]
fn cades_a_build_and_verify_bes() {
    use uacryptex_core::pki::cms::build_content_info_cades_a;

    let (sa, va) = userfiz_adapters();
    let root_cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap();
    let full_crl =
        Crl::decode(include_bytes!("../../../testdata/pki/pki_example/full.crl")).unwrap();
    let delta_crl = Crl::decode(include_bytes!(
        "../../../testdata/pki/pki_example/delta.crl"
    ))
    .unwrap();
    let ocsp_response = pki_example_ocsp_response();
    let data = vec![0xf0; 100];
    let serial = Int::new(&128u8.to_be_bytes()).unwrap();
    let tsp_time = 1_359_151_200i64;

    let cms = build_content_info_cades_a(
        &sa,
        &data,
        OidId::Data,
        &root_cert,
        &[full_crl, delta_crl],
        &ocsp_response,
        &sa,
        &serial,
        tsp_time,
        None,
    )
    .unwrap();

    let container = SignedDataContainer::decode(&cms).unwrap();
    assert!(container.has_certs());
    assert!(container.has_crls());
    let sinfo = container.inner().signer_info(0).unwrap();
    assert_eq!(sinfo.unsigned_attrs.as_ref().unwrap().len(), 3);

    let da = DigestAdapter::init_by_cert(sa.cert().unwrap()).unwrap();
    container.verify_internal_data(&da, &va, 0).unwrap();
}
