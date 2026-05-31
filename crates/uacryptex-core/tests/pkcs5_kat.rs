//! PKCS#5 KAT (`storageUtest/c/utest_pkcs5.c`).

use der::asn1::{ObjectIdentifier, OctetString};
use der::Decode;
use uacryptex_core::storage::pkcs5::{
    pkcs5_decrypt_dstu, pkcs5_get_type, EncryptedPrivateKeyInfo, Pkcs5Type,
};
use uacryptex_core::Error;
use x509_cert::spki::AlgorithmIdentifier;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

const UTSET_EPKI_DER: &str = "308201AA3081B006092A864886F70D01050D3081A2304306092A864886F70D01050C30360420A75E8C61FC464EFAB889E6649432B008EE4E19150A83AA6F100F78FA2D7E5BC302022710300E060A2A8624020101010101020500305B060B2A86240201010101010103304C0408C72C952E189D42BD0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040481F43BF7164B530944870E1886E7B849CB18C6552D827D069BF67C986AA6F8308CAD701008A8FE00FA99EB4A3E36F00130C0A8F035AC47BC6A0D8946F423ECE5AF209DE31191F96922C5905E8BA6C71DB6091BD98E797C8B622041E9E9C6DF0FA1418891742E6EB7C39029A4179D6F90E9A9FAFA2877728B981A60E2758742ECE5D56E5BFE12A445E30C1926171714B1EC07D28A02BC924B8FB617F08A41461AFAAAEE88EFFA8F1ACD14C7C090AD27BECD140E34E0615200E41449422E7BFB8243B6C8DDFDBCF7151FF062C9BAAF4BFA95A072CEDE2D83EB01D2D37BE0CC2D0BF9B801D4FDBE51452DF5F3356F163B27CCE527E0858C";

fn load_utest_epki() -> EncryptedPrivateKeyInfo {
    EncryptedPrivateKeyInfo::from_der(&hex(UTSET_EPKI_DER)).expect("decode utest epki")
}

#[test]
fn pkcs5_get_type_dstu() {
    assert_eq!(pkcs5_get_type(&load_utest_epki()), Pkcs5Type::Dstu);
}

#[test]
fn pkcs5_get_type_unknown() {
    let oid = ObjectIdentifier::new("1.1.1").unwrap();
    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifier {
            oid,
            parameters: None,
        },
        encrypted_data: OctetString::new(&[]).unwrap(),
    };
    assert_eq!(pkcs5_get_type(&epki), Pkcs5Type::Unknown);
}

#[test]
fn pkcs5_decrypt_rejects_non_pbes2() {
    let oid = ObjectIdentifier::new("1.1.1").unwrap();
    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifier {
            oid,
            parameters: None,
        },
        encrypted_data: OctetString::new(&[]).unwrap(),
    };
    let err = pkcs5_decrypt_dstu(&epki, "123456").unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)));
}

#[test]
fn pkcs5_decrypt_dstu_utest_vector() {
    let key = pkcs5_decrypt_dstu(&load_utest_epki(), "123456").unwrap();
    assert_eq!(key[0], 0x30);
}
