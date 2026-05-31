//! CMS EnvelopedData KAT (`cryptonite/src/pkixUtest/c/utest_enveloped_data.c`).

use der::{Decode, Encode};
use uacryptex_core::pki::cms::{
    env_data_init, env_get_content_encryption_aid, EnvelopedData, EnvelopedDataContainer,
};
use uacryptex_core::Error;

const FIXTURE: &[u8] = include_bytes!("../../../testdata/pki/enveloped_data.dat");

#[test]
fn enveloped_data_decode_encode_roundtrip() {
    let decoded = EnvelopedDataContainer::decode(FIXTURE).expect("decode fixture");
    let encoded = decoded.encode().expect("encode");
    let roundtrip = EnvelopedDataContainer::decode(&encoded).expect("re-decode");

    assert_eq!(roundtrip.encode().unwrap(), encoded);

    let direct = EnvelopedData::from_der(&encoded).expect("direct asn decode");
    assert_eq!(direct.to_der().unwrap(), encoded);
}

#[test]
fn enveloped_data_has_no_originator_cert() {
    let decoded = EnvelopedDataContainer::decode(FIXTURE).unwrap();
    assert!(!decoded.has_originator_cert());
}

#[test]
fn enveloped_data_get_originator_cert_errors_without_originator() {
    let decoded = EnvelopedDataContainer::decode(FIXTURE).unwrap();
    assert_eq!(
        decoded.originator_cert().unwrap_err(),
        Error::NoCertificate
    );
}

#[test]
fn env_get_content_encryption_aid_from_fixture() {
    let decoded = EnvelopedDataContainer::decode(FIXTURE).unwrap();
    let aid = env_get_content_encryption_aid(Some(&decoded)).unwrap();
    assert!(!aid.is_empty());
    assert_eq!(
        aid,
        decoded.content_encryption_algorithm_der().unwrap()
    );
}

#[test]
fn env_get_content_encryption_aid_null_param() {
    assert!(env_get_content_encryption_aid(None).is_err());
}

#[test]
fn env_data_init_copies_fields() {
    let source = EnvelopedDataContainer::decode(FIXTURE).unwrap();
    let inner = source.inner().clone();
    let mut target = EnvelopedDataContainer::new();

    env_data_init(
        &mut target,
        inner.version,
        inner.originator_info.clone(),
        inner.recipient_infos.clone(),
        inner.encrypted_content_info.clone(),
        inner.unprotected_attrs.clone(),
    )
    .unwrap();

    assert_eq!(target.encode().unwrap(), source.encode().unwrap());
}
