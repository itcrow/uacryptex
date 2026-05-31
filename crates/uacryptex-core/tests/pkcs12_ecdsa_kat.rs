//! PKCS#12 ECDSA KAT (`storageUtest/c/utest_pkcs12_ecdsa.c`).

use uacryptex_core::pki::creq::creq_verify;
use uacryptex_core::pki::crypto::algorithm_identifier_der;
use uacryptex_core::pki::engine::{ecert_request_alloc, ecert_request_generate};
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::storage::pkcs12::{
    pkcs12_change_password, pkcs12_create, pkcs12_decode, pkcs12_encode, pkcs12_generate_key,
    pkcs12_get_sign_adapter, pkcs12_get_verify_adapter, pkcs12_select_key, pkcs12_set_certificates,
    pkcs12_store_key, Pkcs12MacType,
};

const OSSL_ECDSA_P12: &[u8] =
    include_bytes!("../../../testdata/storage/ossl_ecdsa_aes_256_cbc_storage_123456.p12");
const CRYPTONITE_CERT: &[u8] =
    include_bytes!("../../../testdata/storage/pkcs12_cert_cryptonite.crt");

fn p384_aid() -> Vec<u8> {
    hex::decode("301006072A8648CE3D020106052B81040022").unwrap()
}

fn sha224_digest_aid() -> Vec<u8> {
    algorithm_identifier_der(OidId::PkiSha224, None).expect("sha224 aid")
}

#[test]
fn pkcs12_create_encode_decode_roundtrip() {
    let store = pkcs12_create(Pkcs12MacType::Sha224, "11111", 2048).expect("create");
    let encoded = pkcs12_encode(&store).expect("encode");
    let decoded = pkcs12_decode(None, &encoded, "11111").expect("decode");
    assert_eq!(decoded.password(), "11111");
}

#[test]
fn pkcs12_openssl_ecdsa_storage_roundtrip() {
    let store = pkcs12_decode(None, OSSL_ECDSA_P12, "123456").expect("decode openssl p12");
    let encoded = pkcs12_encode(&store).expect("encode");
    assert_eq!(encoded, OSSL_ECDSA_P12);
}

#[test]
fn pkcs12_ecdsa_generate_store_change_password_roundtrip() {
    let mut store =
        pkcs12_create(Pkcs12MacType::Sha384, "123456", 1024).expect("create");
    pkcs12_generate_key(&mut store, Some(&p384_aid())).expect("generate");
    pkcs12_store_key(&mut store, Some("key"), None, 1024).expect("store key");
    pkcs12_change_password(&mut store, "123456", "12345").expect("change password");
    let encoded = pkcs12_encode(&store).expect("encode");
    let mut decoded = pkcs12_decode(None, &encoded, "12345").expect("decode");
    pkcs12_select_key(&mut decoded, Some("key"), None).expect("select key");
}

#[test]
fn pkcs12_ecdsa_generate_verify_cert_request() {
    let mut store = pkcs12_create(Pkcs12MacType::Sha384, "123456", 1024).expect("create");
    pkcs12_generate_key(&mut store, Some(&p384_aid())).expect("generate");
    pkcs12_store_key(&mut store, Some("key"), None, 1024).expect("store key");
    pkcs12_select_key(&mut store, Some("key"), None).expect("select key");

    let mut sa = pkcs12_get_sign_adapter(&store).expect("sign adapter");
    sa.set_digest_algorithm(&sha224_digest_aid())
        .expect("set digest sha224");
    let engine = ecert_request_alloc(&sa).expect("alloc cert request engine");
    let mut cert_req = None;
    ecert_request_generate(&engine, &mut cert_req).expect("generate cert request");

    pkcs12_set_certificates(&mut store, &[CRYPTONITE_CERT]).expect("set certificates");
    pkcs12_select_key(&mut store, Some("key"), None).expect("re-select key");
    let sa = pkcs12_get_sign_adapter(&store).expect("sign adapter after set certs");
    sa.sign_data(CRYPTONITE_CERT).expect("sign certificate bytes");

    let mut va = pkcs12_get_verify_adapter(&store).expect("verify adapter");
    va.set_digest_algorithm(&sha224_digest_aid())
        .expect("set verify digest sha224");
    creq_verify(cert_req.as_ref().expect("cert request"), &va).expect("verify cert request");

    pkcs12_change_password(&mut store, "123456", "12345").expect("change password");
    let encoded = pkcs12_encode(&store).expect("encode");
    let mut decoded = pkcs12_decode(None, &encoded, "12345").expect("decode");
    pkcs12_select_key(&mut decoded, Some("key"), None).expect("select key after decode");

    let mut sa = pkcs12_get_sign_adapter(&decoded).expect("sign adapter after decode");
    sa.set_digest_algorithm(&sha224_digest_aid())
        .expect("set digest after decode");
    let engine = ecert_request_alloc(&sa).expect("alloc after decode");
    let mut cert_req2 = None;
    ecert_request_generate(&engine, &mut cert_req2).expect("generate after decode");
    assert!(cert_req2.is_some());
}
