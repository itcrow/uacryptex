//! EnvelopedData engine encrypt/decrypt KAT (pki_example `generate_enveloped_data_static` pattern).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::EnvelopedDataEngine;
use uacryptex_core::pki::crypto::{DhAdapter, MasterPrng};
use uacryptex_core::pki::oid::OidId;

fn load_userfiz() -> Cert {
    Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .expect("userfiz cert")
}

fn load_userur() -> Cert {
    Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userur_certificate.cer"
    ))
    .expect("userur cert")
}

fn userfiz_private_key() -> Vec<u8> {
    include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat").to_vec()
}

fn userur_private_key() -> Vec<u8> {
    include_bytes!("../../../testdata/pki/userur_private_key.dat").to_vec()
}

fn userfiz_dh() -> DhAdapter {
    let cert = load_userfiz();
    DhAdapter::init(&userfiz_private_key(), &cert.spki_algorithm_der().unwrap()).unwrap()
}

fn userur_dh() -> DhAdapter {
    let cert = load_userur();
    DhAdapter::init(&userur_private_key(), &cert.spki_algorithm_der().unwrap()).unwrap()
}

const PLAINTEXT: &[u8] = b"Status message for enveloped data test";

#[test]
fn enveloped_data_engine_generate_decrypt_cfb_without_originator_cert() {
    let originator = load_userfiz();
    let recipient = load_userur();
    let originator_dh = userfiz_dh();
    let recipient_dh = userur_dh();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&originator).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Gost28147Cfb);
    engine.set_save_cert(false);
    engine.set_save_data(true);
    engine.set_prng(prng);
    engine.add_recipient(&recipient);

    let (container, external) = engine.generate().unwrap();
    assert!(external.is_none());
    assert!(!container.has_originator_cert());

    let decrypted = container
        .decrypt_data(None, Some(&originator), &recipient_dh, &recipient)
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn enveloped_data_engine_generate_decrypt_cfb_with_originator_cert() {
    let originator = load_userfiz();
    let recipient = load_userur();
    let originator_dh = userfiz_dh();
    let recipient_dh = userur_dh();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&originator).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Gost28147Cfb);
    engine.set_save_cert(true);
    engine.set_save_data(true);
    engine.set_prng(prng);
    engine.add_recipient(&recipient);

    let (container, _) = engine.generate().unwrap();
    assert!(container.has_originator_cert());

    let decrypted = container
        .decrypt_data(None, None, &recipient_dh, &recipient)
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn enveloped_data_engine_external_ciphertext_path() {
    let originator = load_userfiz();
    let recipient = load_userur();
    let originator_dh = userfiz_dh();
    let recipient_dh = userur_dh();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&originator).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Gost28147Cfb);
    engine.set_save_cert(false);
    engine.set_save_data(false);
    engine.set_prng(prng);
    engine.add_recipient(&recipient);

    let (container, external) = engine.generate().unwrap();
    let external = external.expect("external ciphertext");
    assert!(container
        .inner()
        .encrypted_content_info
        .encrypted_content
        .is_none());

    let decrypted = container
        .decrypt_data(
            Some(&external),
            Some(&originator),
            &recipient_dh,
            &recipient,
        )
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn enveloped_data_engine_generate_decrypt_kalyna256_gcm() {
    let originator = load_userfiz();
    let recipient = load_userur();
    let originator_dh = userfiz_dh();
    let recipient_dh = userur_dh();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&originator).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Dstu7624Gmac256);
    engine.set_save_cert(true);
    engine.set_save_data(true);
    engine.set_prng(prng);
    engine.add_recipient(&recipient);

    let (container, _) = engine.generate().unwrap();
    let decrypted = container
        .decrypt_data(None, None, &recipient_dh, &recipient)
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn enveloped_data_engine_generate_decrypt_kalyna128_gcm() {
    let originator = load_userfiz();
    let recipient = load_userur();
    let originator_dh = userfiz_dh();
    let recipient_dh = userur_dh();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&originator).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Dstu7624Gmac128);
    engine.set_save_cert(true);
    engine.set_save_data(true);
    engine.set_prng(prng);
    engine.add_recipient(&recipient);

    let (container, _) = engine.generate().unwrap();
    let decrypted = container
        .decrypt_data(None, None, &recipient_dh, &recipient)
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn enveloped_data_engine_generate_decrypt_kalyna512_gcm() {
    let originator = load_userfiz();
    let recipient = load_userur();
    let originator_dh = userfiz_dh();
    let recipient_dh = userur_dh();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&originator).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Dstu7624Gmac512);
    engine.set_save_cert(true);
    engine.set_save_data(true);
    engine.set_prng(prng);
    engine.add_recipient(&recipient);

    let (container, _) = engine.generate().unwrap();
    let decrypted = container
        .decrypt_data(None, None, &recipient_dh, &recipient)
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn cipher_adapter_roundtrip_like_cryptonite_manager_utest() {
    use uacryptex_core::pki::crypto::{get_gost28147_aid, CipherAdapter};
    use uacryptex_core::primitives::dstu4145::RandomBytes;

    let cert = load_userfiz();
    let mut prng = MasterPrng::new().unwrap().dstu_prng().unwrap();
    let aid = get_gost28147_aid(&mut prng, OidId::Gost28147Ofb, &cert).unwrap();
    let ca = CipherAdapter::init(&aid).unwrap();
    let ca_copy = ca.clone_state();

    let mut key = [0u8; 32];
    prng.fill(&mut key).unwrap();
    let data = [0u8];
    let enc = ca_copy.encrypt(&key, &data).unwrap();
    let dec = ca_copy.decrypt(&key, &enc).unwrap();
    assert_eq!(dec, data);
}
