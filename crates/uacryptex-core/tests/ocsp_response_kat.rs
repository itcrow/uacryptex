//! OCSP response KAT (`pkixUtest/c/utest_ocsp_response.c`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::VerifyAdapter;
use uacryptex_core::pki::ocsp::{OcspResp, OcspResponseStatus};
use uacryptex_core::Error;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn ocsp_response_dat() -> &'static [u8] {
    include_bytes!("../../../testdata/pki/ocsp_response.dat")
}

fn load_ocsp_response() -> OcspResp {
    OcspResp::decode(ocsp_response_dat()).expect("decode ocsp response")
}

#[test]
fn ocspresp_decode_encode_roundtrip() {
    let resp = load_ocsp_response();
    assert_eq!(resp.encode().unwrap(), ocsp_response_dat());
}

#[test]
fn ocspresp_get_set_status() {
    let resp = load_ocsp_response();
    assert_eq!(resp.response_status(), OcspResponseStatus::Successful);
    let mut empty = OcspResp::new();
    empty.set_response_status(resp.response_status());
    assert_eq!(empty.response_status(), OcspResponseStatus::Successful);
}

#[test]
fn ocspresp_get_set_response_bytes() {
    let resp = load_ocsp_response();
    let bytes = resp.response_bytes().unwrap();
    let mut empty = OcspResp::new();
    empty.set_response_bytes(bytes.clone());
    assert_eq!(empty.response_bytes().unwrap(), bytes);
}

#[test]
fn ocspresp_get_response_bytes_missing() {
    let resp = OcspResp::new();
    assert_eq!(resp.response_bytes(), Err(Error::OcspRespNoBytes));
}

#[test]
fn ocspresp_get_certs() {
    let resp = load_ocsp_response();
    let certs = resp.embedded_certs().unwrap();
    assert_eq!(certs.len(), 1);
    let expected = hex(
        "308202C2308201ACA003020102020101300B06092A864886F70D010105301E311C3009060355040613025255300F06035504031E080054006500730074301E170D3133303133313232303030305A170D3136303133313232303030305A301E311C3009060355040613025255300F06035504031E08005400650073007430820122300D06092A864886F70D01010105000382010F003082010A0282010100D8BE412580D1815E06B8187D2C95A9DE942BA00581F4160279A63E01155435E86BFD3B836C3191490BDC6359800FF19BD284025C32FE26EBEB36DF9350598A2808CCA882B393E29441F7576C4466D7CBF9779D394A704DA4C240177A06129B0873912E3D307D56D39AA33E8B156E6E630EBDCBBA9B3AB4F74604C56533E1160D00A4E24DD025FF776AF46D8AD1904885542B0FD261DE29684B41C02BC48E0FC24AC52D1D904453986385931CBB387A4BC8995FBE26F6C2FA7FE98618C73DC61719B9317F33DF6BFF0C585C3FB43197BEB94CCC6EC63000B4290D99763E09ABE27D065573072A573CC6FEEA4CFD21B049F3DA361B6908D03CF0822A9F2E9232A30203010001A30F300D300B0603551D0F040403020002300B06092A864886F70D0101050382010100692413263CEB1317E1B0F29BD790ABC38ECFA947FD529E3465754189AB1BB940BE85E2F854382BAA9C822A66D1808A8B103AB4C0560CEDC1734D6BDD64092027366EB633D883093935768A84893276C2C281255C0F750041EE19C821863AFBD80C2ABE3AE72DFBA367D5BC2409901834FD7967F9AA47F54FE2F95FB6CE9D65373E980AEFFF80C4B687AE89C3505F760E7E191F42765C844B0996AE405A6AF34FBD9418FBA12BE006F5689844590C2695B6702D59CBD365CBB4CA8070612C2347197B94E2D1A5420F743986D9A88D9340B45E49B65149ADD5C7A7EB61C7FBA019A5F373FDE6A61A0C884BA56E2539244419636ED6814731133DACBF034F051CF4",
    );
    assert_eq!(certs[0].encode().unwrap(), expected);
}

#[test]
fn ocspresp_get_certs_missing() {
    let resp = OcspResp::new();
    assert_eq!(resp.embedded_certs(), Err(Error::OcspRespNoBytes));
}

#[test]
fn ocspresp_get_cert_statuses_good() {
    let resp = load_ocsp_response();
    let statuses = resp.cert_statuses().unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].status, "good");
}

#[test]
fn ocspresp_get_cert_statuses_revoked() {
    let resp = OcspResp::decode(include_bytes!(
        "../../../testdata/pki/ocsp_resp_for_revoked_cert.dat"
    ))
    .unwrap();
    let statuses = resp.cert_statuses().unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].status, "revoked");
    assert_eq!(
        statuses[0].revocation_reason.as_deref(),
        Some("affiliationChanged")
    );
}

#[test]
fn ocspresp_get_cert_statuses_no_bytes() {
    let resp = OcspResp::decode(&hex("30030A0101")).unwrap();
    assert_eq!(resp.cert_statuses(), Err(Error::OcspRespNoBytes));
}

#[test]
fn ocspresp_get_responder_id() {
    let resp = load_ocsp_response();
    let expected = hex("a120301e311c3009060355040613025255300f06035504031e080054006500730074");
    assert_eq!(resp.responder_id_der().unwrap(), expected);
}

#[test]
fn ocspresp_get_responder_id_missing() {
    let resp = OcspResp::new();
    assert_eq!(resp.responder_id(), Err(Error::OcspRespNoBytes));
}

#[test]
fn ocspresp_verify_no_bytes() {
    let resp = OcspResp::new();
    let cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    assert_eq!(resp.verify(&va), Err(Error::OcspRespNoBytes));
}

#[test]
fn ocspresp_status_only_responses_have_no_bytes() {
    let resp = OcspResp::decode(&hex("30030A0101")).unwrap();
    assert_eq!(resp.response_status(), OcspResponseStatus::MalformedRequest);
    assert!(resp.response_bytes().is_err());
}
