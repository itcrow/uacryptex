//! TSP response KAT (`pkixUtest/c/utest_tsp_response.c`).

use der::Encode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::ContentInfo;
use uacryptex_core::pki::crypto::{DigestAdapter, VerifyAdapter};
use uacryptex_core::pki::tsp::TspResp;
use uacryptex_core::Error;

fn tsp_response_dat() -> &'static [u8] {
    include_bytes!("../../../testdata/pki/tsp_response.dat")
}

fn load_tsp_response() -> TspResp {
    TspResp::decode(tsp_response_dat()).expect("decode tsp response")
}

#[test]
fn tsresp_decode_encode_roundtrip() {
    let resp = load_tsp_response();
    assert_eq!(resp.encode().unwrap(), tsp_response_dat());
}

#[test]
fn tsresp_get_status() {
    let resp = load_tsp_response();
    assert_eq!(
        resp.status().status,
        uacryptex_core::pki::tsp::PkiStatus::Accepted
    );
}

#[test]
fn tsresp_set_status() {
    let resp = load_tsp_response();
    let mut empty = TspResp::new();
    empty.set_status(resp.status().clone());
    assert_eq!(empty.status(), resp.status());
}

#[test]
fn tsresp_get_ts_token() {
    let resp = load_tsp_response();
    let token = resp.time_stamp_token().unwrap();
    let expected = resp.time_stamp_token().unwrap();
    assert_eq!(token.to_der().unwrap(), expected.to_der().unwrap());
}

#[test]
fn tsresp_get_ts_token_missing() {
    let resp = TspResp::new();
    assert_eq!(resp.time_stamp_token(), Err(Error::TspRespNoToken));
}

#[test]
fn tsresp_set_ts_token() {
    let resp = load_tsp_response();
    let token = resp.time_stamp_token().unwrap();
    let mut empty = TspResp::new();
    empty.set_time_stamp_token(token.clone());
    assert_eq!(
        empty.time_stamp_token().unwrap().to_der().unwrap(),
        token.to_der().unwrap()
    );
}

#[test]
fn tsresp_verify_no_token() {
    let resp = TspResp::new();
    let cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    let da = DigestAdapter::init_by_cert(&cert).unwrap();
    assert_eq!(resp.verify(&da, &va), Err(Error::TspRespNoToken));
}

#[test]
fn tsresp_get_ts_token_content_info_shape() {
    let resp = load_tsp_response();
    let token: ContentInfo = resp.time_stamp_token().unwrap();
    assert_eq!(token.content_type.to_string(), "1.2.840.113549.1.7.2");
    assert!(token.content.is_some());
}
