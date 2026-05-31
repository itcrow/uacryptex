//! CMS SignedData KAT (`pkixUtest/c/utest_signed_data*.c`, `utest_sinfo.c`).

use der::{Decode, Encode};
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::{
    build_signed_data, SignedDataContainer, SignedDataEngine, SignerInfoEngine,
};
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::oid::OidId;
use x509_cert::crl::CertificateList;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn load_certificate257() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der"))
        .expect("decode certificate257")
}

fn certificate257_private_key() -> Vec<u8> {
    hex("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A")
}

fn load_ecdsa_cert() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/ecdsa_cert.der")).expect("decode ecdsa cert")
}

fn ecdsa_private_key() -> Vec<u8> {
    hex("824E63745044AB4E2DC8FBAA39841B785FA9A0D00CE35F99DE2A0D9134A07269")
}

fn load_userfiz() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/userfiz.der")).expect("decode userfiz")
}

fn userfiz_private_key() -> Vec<u8> {
    include_bytes!("../../../testdata/pki/userfiz_private_key.dat").to_vec()
}

fn load_userur() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/userur.der")).expect("decode userur")
}

fn userur_private_key() -> Vec<u8> {
    include_bytes!("../../../testdata/pki/userur_private_key.dat").to_vec()
}

const STATUS_MESSAGE: &[u8] =
    b"\xd0\xa1\xd1\x82\xd0\xb0\xd1\x82\xd1\x83\xd1\x81 \xd0\xbf\xd0\xbe\xd0\xb2\xd1\x96\xd0\xb4\xd0\xbe\xd0\xbc\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xbd\xd1\x8f";

#[test]
fn cms_build_decode_encode_roundtrip() {
    let cert = load_certificate257();
    let sa = SignAdapter::init_by_cert(&certificate257_private_key(), &cert).unwrap();
    let content = b"Status message test";

    let built = build_signed_data(&sa, content, OidId::Data).unwrap();
    let der = built.encode().unwrap();
    let decoded = SignedDataContainer::decode(&der).unwrap();

    assert_eq!(decoded.version(), 1);
    assert_eq!(decoded.encapsulated_content().unwrap(), content);
    assert_eq!(decoded.encode().unwrap(), der);
    assert!(decoded.has_certs());
    assert!(!decoded.has_crls());
}

#[test]
fn cms_verify_internal_data_certificate257() {
    let cert = load_certificate257();
    let sa = SignAdapter::init_by_cert(&certificate257_private_key(), &cert).unwrap();
    let sdata = build_signed_data(&sa, STATUS_MESSAGE, OidId::Data).unwrap();

    let da = DigestAdapter::init_by_cert(&cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();

    sdata.verify_internal_data(&da, &va, 0).unwrap();
    sdata.verify_without_data(&va, 0).unwrap();
    sdata.verify_signing_cert(&da, &cert, 0).unwrap();
}

#[test]
fn cms_content_info_wrapper_roundtrip() {
    let cert = load_certificate257();
    let sa = SignAdapter::init_by_cert(&certificate257_private_key(), &cert).unwrap();
    let built = build_signed_data(&sa, b"pkcs7", OidId::Data).unwrap();
    let ci_der = built.encode_content_info().unwrap();
    let decoded = SignedDataContainer::decode(&ci_der).unwrap();
    assert_eq!(decoded.encapsulated_content().unwrap(), b"pkcs7");
}

#[test]
fn cms_verify_external_data_mismatch() {
    let cert = load_certificate257();
    let sa = SignAdapter::init_by_cert(&certificate257_private_key(), &cert).unwrap();
    let sdata = build_signed_data(&sa, b"ignored internal", OidId::Data).unwrap();

    let da = DigestAdapter::init_by_cert(&cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();

    assert!(sdata
        .verify_external_data(b"external payload", &da, &va, 0)
        .is_err());
}

#[test]
fn cms_signed_data_dat_fixture() {
    let der = include_bytes!("../../../testdata/pki/signed_data.dat");
    let sdata = SignedDataContainer::decode(der).unwrap();

    assert_eq!(sdata.version(), 1);
    assert_eq!(sdata.encapsulated_content().unwrap(), STATUS_MESSAGE);
    assert_eq!(sdata.signer_count(), 1);
    assert_eq!(sdata.encode().unwrap(), der);

    let cert = load_certificate257();
    let da = DigestAdapter::init_by_cert(&cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    sdata.verify_internal_data(&da, &va, 0).unwrap();
    sdata.verify_signing_cert(&da, &cert, 0).unwrap();
}

#[test]
fn cms_test_cms_sign_dat_fixture() {
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/test_sign.cer")).unwrap();
    let signed_attrs = include_bytes!("../../../testdata/pki/test_cms_signed_attr.der");
    let signature = include_bytes!("../../../testdata/pki/test_cms_sign.dat");

    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    va.verify_data(signed_attrs, signature).unwrap();
}

#[test]
fn cms_engine_multi_signer_with_crl() {
    let cert1 = load_userfiz();
    let cert2 = load_userur();
    let sa1 = SignAdapter::init_by_cert(&userfiz_private_key(), &cert1).unwrap();
    let sa2 = SignAdapter::init_by_cert(&userur_private_key(), &cert2).unwrap();
    let da1 = DigestAdapter::init_by_cert(&cert1).unwrap();
    let da2 = DigestAdapter::init_by_cert(&cert2).unwrap();

    let mut signer1 = SignerInfoEngine::new(&sa1, da1.clone(), None).unwrap();
    let signing_time = hex("301C06092A864886F70D010905310F170D3136303232363039323231325A");
    let attr = x509_cert::attr::Attribute::from_der(&signing_time).unwrap();
    signer1.add_signed_attr(&attr).unwrap();

    let mut engine = SignedDataEngine::new(signer1);
    engine
        .set_data(OidId::Data, STATUS_MESSAGE, true)
        .unwrap();
    engine.add_cert(cert1.clone()).unwrap();

    let crl = CertificateList::from_der(include_bytes!("../../../testdata/pki/example_full.crl"))
        .unwrap();
    let crl_der = crl.to_der().unwrap();
    engine.add_crl(crl.clone()).unwrap();

    let signer2 = SignerInfoEngine::new(&sa2, da2.clone(), None).unwrap();
    engine.add_signer(signer2);

    let sdata = engine.generate().unwrap();

    assert_eq!(sdata.signer_count(), 2);
    assert!(sdata.has_certs());
    assert!(sdata.has_crls());
    assert_eq!(sdata.crl_der(0).unwrap(), crl_der);

    let va1 = VerifyAdapter::init_by_cert(&cert1).unwrap();
    let va2 = VerifyAdapter::init_by_cert(&cert2).unwrap();

    sdata.verify_signing_cert(&da2, &cert2, 0).unwrap();
    sdata.verify_signing_cert(&da1, &cert1, 1).unwrap();
    sdata.verify_without_data(&va2, 0).unwrap();
    sdata.verify_without_data(&va1, 1).unwrap();
    sdata.verify_internal_data(&da2, &va2, 0).unwrap();
    sdata.verify_internal_data(&da1, &va1, 1).unwrap();
}

#[test]
fn cms_engine_ecdsa_signer() {
    let cert = load_ecdsa_cert();
    let sa = SignAdapter::init_by_cert(&ecdsa_private_key(), &cert).unwrap();
    let da = DigestAdapter::init_by_cert(&cert).unwrap();

    let signer = SignerInfoEngine::new(&sa, da.clone(), None).unwrap();
    let mut engine = SignedDataEngine::new(signer);
    engine.set_data(OidId::Data, b"ecdsa cms", true).unwrap();
    engine.add_cert(cert.clone()).unwrap();

    let sdata = engine.generate().unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    sdata.verify_internal_data(&da, &va, 0).unwrap();
    sdata.verify_signing_cert(&da, &cert, 0).unwrap();
}
