//! X.509 certificate KAT (`pkixUtest/c/utest_cert.c`, `utest_pkix_utils.c` TOV cert).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::oid::OidId;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn tov_test_der() -> &'static [u8] {
    include_bytes!("../../../testdata/pki/tov_test.der")
}

fn load_tov_cert() -> Cert {
    Cert::decode(tov_test_der()).expect("decode TOV test certificate")
}

#[test]
fn cert_decode_encode_roundtrip() {
    let cert = load_tov_cert();
    assert_eq!(cert.encode().unwrap(), tov_test_der());
}

#[test]
fn cert_get_version_v3() {
    let cert = load_tov_cert();
    assert_eq!(cert.version(), 2);
}

#[test]
fn cert_get_serial_number() {
    let cert = load_tov_cert();
    assert_eq!(
        cert.serial_number(),
        hex("290539EC60662BE804000000710000008D060000")
    );
}

#[test]
fn cert_get_validity() {
    let cert = load_tov_cert();
    assert_eq!(cert.not_before_unix(), 1_421_399_437);
    assert_eq!(cert.not_after_unix(), 1_452_981_599);
    cert.check_validity_at(1_421_399_437).unwrap();
    cert.check_validity_at(1_452_981_599).unwrap();
    assert!(cert.check_validity_at(1_421_399_436).is_err());
    assert!(cert.check_validity_at(1_452_981_600).is_err());
}

#[test]
fn cert_get_subject_and_authority_key_ids() {
    let cert = load_tov_cert();
    assert_eq!(
        cert.subject_key_id().unwrap(),
        hex("94369F44E05A0D1B2854F3A982ACB4818FF6D0449D1A9FA34AD4A0D9EDECB5C9")
    );
    assert_eq!(
        cert.authority_key_id().unwrap(),
        hex("290539EC60662BE821EE4750BFDA1E15A34E00666B91E18834A50F710B83577E")
    );
}

#[test]
fn cert_get_basic_constraints_path_len() {
    let cert = load_tov_cert();
    assert_eq!(cert.basic_constraints_path_len().unwrap(), -1);
}

#[test]
fn cert_is_not_ocsp_responder() {
    let cert = load_tov_cert();
    assert!(!cert.is_ocsp_responder().unwrap());
}

#[test]
fn cert_get_tsp_url() {
    let cert = load_tov_cert();
    assert_eq!(
        cert.tsp_url().unwrap(),
        "http://test-acsk.privatbank.ua/services/tsp/"
    );
}

#[test]
fn cert_extension_lists() {
    let cert = load_tov_cert();
    let critical = cert.critical_extension_ids();
    let non_critical = cert.non_critical_extension_ids();
    assert_eq!(critical.len(), 5);
    assert!(critical.contains(&OidId::KeyUsageExtension));
    assert!(critical.contains(&OidId::BasicConstraintsExtension));
    assert!(critical.contains(&OidId::CertificatePoliciesExtension));
    assert!(critical.contains(&OidId::QcStatementsExtension));
    assert!(critical.contains(&OidId::ExtKeyUsageExtension));

    assert!(non_critical.contains(&OidId::SubjectKeyIdentifierExtension));
    assert!(non_critical.contains(&OidId::AuthorityKeyIdentifierExtension));
    assert!(non_critical.contains(&OidId::PrivateKeyUsagePeriodExtension));
    assert!(non_critical.contains(&OidId::CrlDistributionPointsExtension));
    assert!(non_critical.contains(&OidId::FreshestCrlExtension));
    assert!(non_critical.contains(&OidId::AuthorityInfoAccessExtension));
    assert!(non_critical.contains(&OidId::SubjectInfoAccessExtension));
}

#[test]
fn cert_spki_and_signature_algorithm_present() {
    let cert = load_tov_cert();
    let spki = cert.spki_der().unwrap();
    assert!(spki.starts_with(&[0x30]));
    let sig_alg = cert.signature_algorithm_der().unwrap();
    assert_eq!(sig_alg, hex("300D060B2A86240201010101030101"));
    assert!(!cert.signature_der().unwrap().is_empty());
    assert!(!cert.tbs_der().unwrap().is_empty());
}
