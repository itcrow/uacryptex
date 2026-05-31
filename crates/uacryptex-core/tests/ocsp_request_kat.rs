//! OCSP request KAT (`pkixUtest/c/utest_ocsp_request.c`).

use der::Encode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::VerifyAdapter;
use uacryptex_core::pki::ocsp::OcspReq;
use uacryptex_core::Error;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn ocsp_request_dat() -> &'static [u8] {
    include_bytes!("../../../testdata/pki/ocsp_request.dat")
}

fn load_ocsp_request() -> OcspReq {
    OcspReq::decode(ocsp_request_dat()).expect("decode ocsp request")
}

#[test]
fn ocspreq_decode_encode_roundtrip() {
    let req = load_ocsp_request();
    assert_eq!(req.encode().unwrap(), ocsp_request_dat());
}

#[test]
fn ocspreq_get_tbsreq() {
    let req = load_ocsp_request();
    let expected = hex(
        "308195306C306A3068300C060A2A8624020101010102010420305A35E24820678A3F6879A95734C98C654C31200315DD0D8\
         D341EDC928CE28704208D84EDA1BB9381E8C31190A8AC92853FC4D8C784C64A01B8371157D85D18555702140D84EDA1BB93\
         81E804000000209E0200D68B0700A2253023302106092B0601050507300102041494E533F8225EC8421B46828880C7A8D32\
         79F8061",
    );
    assert_eq!(req.tbs_request().to_der().unwrap(), expected);
}

#[test]
fn ocspreq_set_tbsreq() {
    let req = load_ocsp_request();
    let mut empty = OcspReq::new();
    empty.set_tbs_request(req.tbs_request().clone());
    assert_eq!(empty.tbs_request(), req.tbs_request());
}

#[test]
fn ocspreq_get_sign_and_has_sign() {
    let req = load_ocsp_request();
    assert!(req.optional_signature().is_none());
    assert!(!req.has_signature());
}

#[test]
fn ocspreq_set_sign() {
    let signed = OcspReq::decode(include_bytes!(
        "../../../testdata/pki/oscp_request_with_sign.dat"
    ))
    .unwrap();
    let signature = signed.optional_signature().unwrap().clone();
    let mut empty = OcspReq::new();
    empty.set_optional_signature(signature.clone());
    assert_eq!(empty.optional_signature(), Some(&signature));
}

#[test]
fn ocspreq_verify_no_sign() {
    let req = OcspReq::new();
    let cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    assert_eq!(req.verify(&va), Err(Error::OcspReqNoSign));
}
