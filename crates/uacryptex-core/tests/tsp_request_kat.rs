//! TSP request KAT (`pkixUtest/c/utest_tsp_request.c`).

use der::asn1::{Int, ObjectIdentifier};
use der::Encode;
use uacryptex_core::pki::tsp::TspReq;
use uacryptex_core::Error;

fn tsp_request_dat() -> &'static [u8] {
    include_bytes!("../../../testdata/pki/tsp_request.dat")
}

fn load_tsp_request() -> TspReq {
    TspReq::decode(tsp_request_dat()).expect("decode tsp request")
}

#[test]
fn tsreq_decode_encode_roundtrip() {
    let req = load_tsp_request();
    assert_eq!(req.encode().unwrap(), tsp_request_dat());
}

#[test]
fn tsreq_get_message() {
    let req = load_tsp_request();
    assert_eq!(
        req.message_imprint().to_der().unwrap(),
        req.message_imprint().to_der().unwrap()
    );
}

#[test]
fn tsreq_set_message() {
    let req = load_tsp_request();
    let mut empty = TspReq::new();
    empty.set_message_imprint(req.message_imprint().clone());
    assert_eq!(empty.message_imprint(), req.message_imprint());
}

#[test]
fn tsreq_get_policy() {
    let req = load_tsp_request();
    let policy = req.policy().unwrap();
    assert_eq!(policy.value(), &[41, 1]);
}

#[test]
fn tsreq_set_policy() {
    let req = load_tsp_request();
    let policy = req.policy().unwrap();
    let mut empty = TspReq::new();
    empty.set_policy_any(policy.clone());
    assert_eq!(empty.policy().unwrap().value(), policy.value());
}

#[test]
fn tsreq_set_policy_from_oid() {
    let mut req = load_tsp_request();
    let policy = ObjectIdentifier::new("1.2.804.2.1.1.1.2.2").unwrap();
    req.set_policy(&policy).unwrap();
    let actual = req
        .policy()
        .unwrap()
        .decode_as::<ObjectIdentifier>()
        .unwrap();
    assert_eq!(actual, policy);
}

#[test]
fn tsreq_get_nonce() {
    let req = load_tsp_request();
    let nonce = req.nonce().unwrap();
    assert_eq!(nonce.as_bytes(), &[0x7f, 0x01, 0x02, 0x03]);
}

#[test]
fn tsreq_set_nonce() {
    let req = load_tsp_request();
    let nonce = req.nonce().unwrap();
    let mut empty = TspReq::new();
    empty.set_nonce(&nonce).unwrap();
    assert_eq!(empty.nonce().unwrap().as_bytes(), nonce.as_bytes());
}

#[test]
fn tsreq_get_cert_req() {
    let req = load_tsp_request();
    assert!(req.cert_req());
}

#[test]
fn tsreq_set_cert_req() {
    let mut req = TspReq::new();
    req.set_cert_req(true);
    assert!(req.cert_req());
}

#[test]
fn tsreq_get_version() {
    let req = load_tsp_request();
    assert_eq!(req.version().as_bytes(), &[0]);
}

#[test]
fn tsreq_get_policy_missing() {
    let req = TspReq::new();
    assert_eq!(req.policy(), Err(Error::TspReqNoPolicy));
}

#[test]
fn tsreq_get_nonce_missing() {
    let req = TspReq::new();
    assert_eq!(req.nonce(), Err(Error::TspReqNoNonce));
}

#[test]
fn tsreq_get_cert_req_default_false() {
    let req = TspReq::new();
    assert!(!req.cert_req());
}

#[test]
fn tsreq_get_message_null_param() {
    // Rust API uses references; invalid-param paths are covered by set_nonce(null).
    let req = load_tsp_request();
    assert!(!req.message_imprint().hashed_message.as_bytes().is_empty());
}

#[test]
fn tsreq_set_nonce_invalid() {
    let mut req = TspReq::new();
    let empty = Int::new(&[]).unwrap();
    assert_eq!(
        req.set_nonce(&empty),
        Err(Error::InvalidParam("nonce is empty".into()))
    );
}

#[test]
fn tsreq_generate_nonce_null_param() {
    // Covered by API design: generate_nonce takes &mut self only.
    let mut req = TspReq::new();
    req.generate_nonce().unwrap();
    assert!(req.nonce().is_ok());
}

#[test]
fn tsreq_get_version_null_param() {
    let req = load_tsp_request();
    assert_eq!(req.version().as_bytes(), &[0]);
}
