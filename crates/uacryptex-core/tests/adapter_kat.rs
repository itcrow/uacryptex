//! Crypto adapter KAT (`pkixUtest/c/utest_cryptonite_manager.c`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::{
    algorithm_identifier_der, gost3411_algorithm_der, spki_algorithm_der, DigestAdapter,
    SignAdapter, VerifyAdapter,
};
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::Error;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn load_tov_cert() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/tov_test.der")).expect("decode TOV cert")
}

fn load_certificate257() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der"))
        .expect("decode certificate257")
}

fn certificate257_private_key() -> Vec<u8> {
    hex("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A")
}

#[test]
fn da_init_default_empty_hash() {
    let mut da = DigestAdapter::init_default().unwrap();
    da.update(&[]).unwrap();
    let hash = da.finalize().unwrap();
    assert_eq!(
        hash,
        hex("5DF74E647FED52C1E941B26D546B8C689112F207EB8542965FDD9CD3083E5282")
    );
}

#[test]
fn da_init_by_cert_tov_empty_hash() {
    let cert = load_tov_cert();
    let spki = cert.spki_der().unwrap();
    let spki_aid = spki_algorithm_der(&spki).unwrap();

    let mut by_cert = DigestAdapter::init_by_cert(&cert).unwrap();
    by_cert.update(&[]).unwrap();
    let hash_by_cert = by_cert.finalize().unwrap();

    let mut by_aid = DigestAdapter::init_by_aid(&spki_aid).unwrap();
    by_aid.update(&[]).unwrap();
    let hash_by_aid = by_aid.finalize().unwrap();

    assert_eq!(hash_by_cert, hash_by_aid);
    assert_eq!(hash_by_cert.len(), 32);
}

#[test]
fn da_init_by_cert_copy_with_alloc() {
    let cert = load_tov_cert();
    let mut da = DigestAdapter::init_by_cert(&cert).unwrap();
    let mut da_copy = da.clone_state().unwrap();
    da.update(&[]).unwrap();
    da_copy.update(&[]).unwrap();
    assert_eq!(da.finalize().unwrap(), da_copy.finalize().unwrap());
}

#[test]
fn da_init_by_aid_sha512() {
    let aid = algorithm_identifier_der(OidId::PkiSha512, None).unwrap();
    let mut da = DigestAdapter::init_by_aid(&aid).unwrap();
    let mut da_copy = da.clone_state().unwrap();
    let data = b"Cryptonite";
    da.update(data).unwrap();
    da_copy.update(data).unwrap();
    let expected = hex(
        "a7eaa036beb43131b0818c2c324e52310763c95f91dc91234a395b0f1a0ebdd8\
         abe491e426ada2c4700231258347631ac94fa01e43150246cc5d824ac88e420b",
    );
    assert_eq!(da.finalize().unwrap(), expected);
    assert_eq!(da_copy.finalize().unwrap(), expected);
}

#[test]
fn da_init_by_aid_sha1() {
    let aid = algorithm_identifier_der(OidId::PkiSha1, None).unwrap();
    let mut da = DigestAdapter::init_by_aid(&aid).unwrap();
    let data = hex(
        "3b46736d559bd4e0c2c1b2553a33ad3c6cf23cac998d3d0c0e8fa4b19bca06f2\
         f386db2dcff9dca4f40ad8f561ffc308b46c5f31a7735b5fa7e0f9e6cb512e63d7eea05538d66a75cd0d4234b5ccf6c1715ccaaf9cdc0a2228135f716ee9bdee7fc13ec27a03a6d11c5c5b3685f51900b1337153bc6c4e8f52920c33fa37f4e7",
    );
    da.update(&data).unwrap();
    assert_eq!(
        da.finalize().unwrap(),
        hex("58429e8f371f9e1d69a5bf96a554d627cfd5485c")
    );
}

#[test]
fn sa_init_by_aid_certificate257_metadata() {
    let cert = load_certificate257();
    let private_key = certificate257_private_key();
    let sign_aid = cert.signature_algorithm_der().unwrap();
    let spki = cert.spki_der().unwrap();
    let spki_aid = spki_algorithm_der(&spki).unwrap();

    let sa = SignAdapter::init_by_aid(&private_key, &sign_aid, &spki_aid).unwrap();
    assert!(!sa.has_cert());
    assert!(sa.cert().is_err());
    assert_eq!(sa.digest_algorithm_der(), gost3411_algorithm_der());
    assert_eq!(sa.signature_algorithm_der(), hex("300D060B2A86240201010101030101"));
    assert_eq!(
        sa.spki_der().unwrap(),
        hex(
            "3081883060060B2A862402010101010301013051060D2A862402010101010301010206\
             0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17\
             F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC5790403240\
             00421D7B049230F30FD10C53CB78A347EFEE8CFBE04F0CF1660143AF44537E076834001"
        )
    );
}

#[test]
fn sa_init_by_cert_certificate257() {
    let cert = load_certificate257();
    let private_key = certificate257_private_key();
    let sa = SignAdapter::init_by_cert(&private_key, &cert).unwrap();
    assert!(sa.has_cert());
    assert_eq!(sa.cert().unwrap().encode().unwrap(), cert.encode().unwrap());
}

#[test]
fn sa_sign_verify_roundtrip_certificate257() {
    let cert = load_certificate257();
    let private_key = certificate257_private_key();
    let sign_aid = cert.signature_algorithm_der().unwrap();
    let spki = cert.spki_der().unwrap();
    let spki_aid = spki_algorithm_der(&spki).unwrap();

    let sa = SignAdapter::init_by_aid(&private_key, &sign_aid, &spki_aid).unwrap();
    let sa_copy = sa.clone_state().unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();

    let data = hex("00");
    let mut da = DigestAdapter::init_by_aid(&spki_aid).unwrap();
    da.update(&data).unwrap();
    let hash = da.finalize().unwrap();

    let sign = sa.sign_data(&data).unwrap();
    va.verify_hash(&hash, &sign).unwrap();

    let sign2 = sa_copy.sign_hash(&hash).unwrap();
    va.verify_data(&data, &sign2).unwrap();
}

#[test]
fn sa_rejects_wrong_private_key_by_cert() {
    let cert = load_certificate257();
    let wrong = hex("1B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    assert!(matches!(
        SignAdapter::init_by_cert(&wrong, &cert),
        Err(Error::InvalidParam(_))
    ));
}

#[test]
fn sa_rejects_bad_private_key_length() {
    let cert = load_certificate257();
    let sign_aid = cert.signature_algorithm_der().unwrap();
    let spki = cert.spki_der().unwrap();
    let spki_aid = spki_algorithm_der(&spki).unwrap();
    let bad = hex("12121B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    assert!(matches!(
        SignAdapter::init_by_aid(&bad, &sign_aid, &spki_aid),
        Err(Error::InvalidParam(_))
    ));
}

fn load_ecdsa_cert() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/ecdsa_cert.der")).expect("decode ecdsa cert")
}

fn ecdsa_private_key() -> Vec<u8> {
    hex("824E63745044AB4E2DC8FBAA39841B785FA9A0D00CE35F99DE2A0D9134A07269")
}

#[test]
fn da_init_by_cert_ecdsa_sha256_empty_hash() {
    let cert = load_ecdsa_cert();
    let mut da = DigestAdapter::init_by_cert(&cert).unwrap();
    da.update(&[]).unwrap();
    assert_eq!(
        da.finalize().unwrap(),
        hex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    );
}

#[test]
fn va_init_by_cert_ecdsa_metadata() {
    let cert = load_ecdsa_cert();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    assert!(va.has_cert());
    assert_eq!(
        va.digest_algorithm_der(),
        algorithm_identifier_der(OidId::PkiSha256, None).unwrap()
    );
    assert_eq!(va.signature_algorithm_der(), cert.signature_algorithm_der().unwrap());
}

#[test]
fn sa_ecdsa_wrong_private_key_by_cert() {
    let cert = load_ecdsa_cert();
    let wrong = hex("66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32AE24A37407D01D32AFFFF");
    assert!(matches!(
        SignAdapter::init_by_cert(&wrong, &cert),
        Err(Error::InvalidParam(_))
    ));
}

#[test]
fn sa_ecdsa_wrong_private_key_by_aid_succeeds() {
    let cert = load_ecdsa_cert();
    let wrong = hex("66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32AE24A37407D01D32AFFFF");
    let sign_aid = cert.signature_algorithm_der().unwrap();
    let spki = cert.spki_der().unwrap();
    let spki_aid = spki_algorithm_der(&spki).unwrap();
    SignAdapter::init_by_aid(&wrong, &sign_aid, &spki_aid).unwrap();
}

#[test]
fn sa_ecdsa_bad_private_key_length() {
    let cert = load_ecdsa_cert();
    let sign_aid = cert.signature_algorithm_der().unwrap();
    let spki = cert.spki_der().unwrap();
    let spki_aid = spki_algorithm_der(&spki).unwrap();
    let bad = hex("12121B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32AE24A37407D01D32AFFFF");
    assert!(matches!(
        SignAdapter::init_by_aid(&bad, &sign_aid, &spki_aid),
        Err(Error::InvalidParam(_))
    ));
}

#[test]
fn sa_ecdsa_sign_verify_roundtrip() {
    let cert = load_ecdsa_cert();
    let private_key = ecdsa_private_key();
    let mut sa = SignAdapter::init_by_cert(&private_key, &cert).unwrap();
    sa.set_opt_level(0x0303).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();

    let data = b"ecdsa adapter test";
    let sign = sa.sign_data(data).unwrap();
    va.verify_data(data, &sign).unwrap();
}

#[test]
fn adapter_set_opt_level_clone() {
    let cert = load_certificate257();
    let private_key = certificate257_private_key();
    let mut sa = SignAdapter::init_by_cert(&private_key, &cert).unwrap();
    sa.set_opt_level(0x0303).unwrap();
    let sa_copy = sa.clone_state().unwrap();
    sa.set_opt_level(0x3030).unwrap();

    let mut va = VerifyAdapter::init_by_cert(&cert).unwrap();
    va.set_opt_level(0x0505).unwrap();
    let va_copy = va.clone_state().unwrap();
    assert!(sa_copy.has_cert());
    assert!(va_copy.has_cert());
}
