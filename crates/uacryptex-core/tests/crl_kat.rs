//! CRL KAT (`pkixUtest/c/utest_crl.c`).

use der::Encode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::SignAdapter;
use uacryptex_core::pki::ext::ext_from_der;
use uacryptex_core::Error;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn crl_dat() -> &'static [u8] {
    include_bytes!("../../../testdata/pki/crl.dat")
}

fn load_crl_dat() -> Crl {
    Crl::decode(crl_dat()).expect("decode crl.dat")
}

fn load_czo_full() -> Crl {
    Crl::decode(include_bytes!("../../../testdata/pki/czo_full.crl")).expect("decode CZO-Full")
}

fn load_acsk_cert() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/acsk_cert.cer")).expect("decode acsk cert")
}

fn load_certificate257() -> Cert {
    Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der"))
        .expect("decode certificate257")
}

fn certificate257_private_key() -> Vec<u8> {
    hex("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A")
}

#[test]
fn crl_decode_encode_roundtrip() {
    let crl = load_crl_dat();
    assert_eq!(crl.encode().unwrap(), crl_dat());
}

#[test]
fn crl_get_tbs() {
    let crl = load_crl_dat();
    let expected = hex(
        "308201FC020101300D06092A864886F70D0101050500305F31233021060355040A131A53616D706C65205369676E6572204F7267616\
         E697A6174696F6E311B3019060355040B131253616D706C65205369676E657220556E6974311B30190603550403131253616D706C65\
         205369676E65722043657274170D3133303231383130333230305A170D3133303231383130343230305A30820136303C02031479471\
         70D3133303231383130323231325A3026300A0603551D1504030A010330180603551D180411180F3230313330323138313032323030\
         5A303C0203147948170D3133303231383130323232325A3026300A0603551D1504030A010630180603551D180411180F32303133303\
         231383130323230305A303C0203147949170D3133303231383130323233325A3026300A0603551D1504030A010430180603551D1804\
         11180F32303133303231383130323230305A303C020314794A170D3133303231383130323234325A3026300A0603551D1504030A010\
         130180603551D180411180F32303133303231383130323230305A303C020314794B170D3133303231383130323235315A3026300A06\
         03551D1504030A010530180603551D180411180F32303133303231383130323230305AA02F302D301F0603551D23041830168014BE1\
         201CCAAEA1180DA2EADB2EAC7B5FB9FF9AD34300A0603551D140403020103",
    );
    assert_eq!(crl.tbs().to_der().unwrap(), expected);
}

#[test]
fn crl_set_tbs() {
    let crl = load_crl_dat();
    let mut empty = Crl::new();
    empty.set_tbs(crl.tbs().clone());
    assert_eq!(empty.tbs(), crl.tbs());
}

#[test]
fn crl_get_set_sign_aid() {
    let crl = load_crl_dat();
    let expected = hex("300D06092A864886F70D0101050500");
    assert_eq!(crl.signature_algorithm_der().unwrap(), expected);

    let mut empty = Crl::new();
    empty.set_signature_algorithm(crl.signature_algorithm().clone());
    assert_eq!(empty.signature_algorithm_der().unwrap(), expected);
}

#[test]
fn crl_init_by_sign() {
    let crl = load_crl_dat();
    let rebuilt = Crl::init_by_sign(
        crl.tbs().clone(),
        crl.signature_algorithm().clone(),
        crl.signature().clone(),
    )
    .unwrap();
    assert_eq!(rebuilt.tbs(), crl.tbs());
    assert_eq!(
        rebuilt.signature_algorithm_der().unwrap(),
        crl.signature_algorithm_der().unwrap()
    );
    assert_eq!(rebuilt.signature(), crl.signature());
}

#[test]
fn crl_init_by_adapter() {
    let crl = load_crl_dat();
    let cert = load_certificate257();
    let sa = SignAdapter::init_by_cert(&certificate257_private_key(), &cert).unwrap();
    let rebuilt = Crl::init_by_adapter(crl.tbs().clone(), &sa).unwrap();
    assert_eq!(rebuilt.tbs(), crl.tbs());
    assert_eq!(
        rebuilt.signature_algorithm_der().unwrap(),
        sa.signature_algorithm_der()
    );
}

#[test]
fn crl_get_set_sign() {
    let crl = load_crl_dat();
    let expected = hex(
        "03820101004221BE81F1C37976665BCE21138A68A8B43CBE16C3AF4BDDCB78359290D8D74C6FFE6C6827AE6DDA429801EE1793F0BDA\
         8EECD90B635F60DA4CE4982F79D9FC86E7FD1F12D20F846CD431764E7F95AE82111C62469F84D93506F0B0DBD786153214462AF0A0B\
         92232506D0CC065BAC1AA95B5DE8AEF5BBBBE1214FD389D7FA65276C4CC8693CF16E3D489DE23DBD537AB5D1218517A702B750F38EF\
         51C0B01C6847034D8C7A7EF41206450033CB5A62E0D0782529487589959C046B5EBFFF15B148A3CA3B0CD3BD82E94B794F0372AEBB6\
         16FDE76F9E2A59B12CD813D28E61558C635E1B702D0B0BED0661AF2A403350CB62A4239220C8EE196FB7B42E0C64C9",
    );
    assert_eq!(crl.signature().to_der().unwrap(), expected);

    let mut empty = Crl::new();
    empty.set_signature(crl.signature().clone());
    assert_eq!(empty.signature(), crl.signature());
}

#[test]
fn crl_check_cert_not_revoked() {
    let crl = load_crl_dat();
    let cert = load_acsk_cert();
    assert!(!crl.check_cert(&cert).unwrap());
}

#[test]
fn crl_get_cert_info_not_found() {
    let crl = load_crl_dat();
    let cert = load_acsk_cert();
    assert_eq!(crl.revoked_cert_for_cert(&cert), Err(Error::NotFound));
}

#[test]
fn crl_get_cert_info_by_sn_not_found() {
    let crl = load_crl_dat();
    let cert = load_acsk_cert();
    assert_eq!(
        crl.revoked_cert_by_serial(&cert.serial_number()),
        Err(Error::NotFound)
    );
}

#[test]
fn crl_is_full_and_delta_on_crl_dat() {
    let crl = load_crl_dat();
    assert!(!crl.is_full());
    assert!(!crl.is_delta());
}

#[test]
fn crl_czo_full_number_and_this_update() {
    let crl = load_czo_full();
    assert_eq!(crl.crl_number().unwrap(), hex("4461"));
    assert_eq!(crl.this_update_unix(), 1_473_454_396);
}

#[test]
fn crl_get_distribution_points() {
    let mut crl = load_crl_dat();
    let ext = ext_from_der(&hex(
        "303D0603551D1F043630343032A030A02E862C687474703A2F2F637A6F2E676F762E75612F646F776E6C6F61642F63726C732F435A4F2D46756C6C2E63726C",
    ))
    .unwrap();
    crl.add_crl_extension(ext);
    let urls = crl.distribution_point_urls().unwrap();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0], "http://czo.gov.ua/download/crls/CZO-Full.crl");
}

#[test]
fn crl_empty_alloc_check_cert() {
    let crl = Crl::new();
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/tov_test.der")).unwrap();
    assert!(!crl.check_cert(&cert).unwrap());
}

#[test]
fn crl_empty_alloc_get_cert_info_by_sn() {
    let crl = Crl::new();
    let cert = load_acsk_cert();
    assert_eq!(
        crl.revoked_cert_by_serial(&cert.serial_number()),
        Err(Error::NotFound)
    );
}

#[test]
fn crl_empty_alloc_is_full_and_delta() {
    let crl = Crl::new();
    assert!(!crl.is_full());
    assert!(!crl.is_delta());
}

#[test]
fn crl_czo_full_is_full() {
    let crl = load_czo_full();
    assert!(crl.is_full());
}

#[test]
fn crl_czo_full_check_revoked_cert() {
    let crl = load_czo_full();
    let serial = hex("3004751DEF2C78AE010000000100000017000000");
    let base = Cert::decode(include_bytes!("../../../testdata/pki/tov_test.der")).unwrap();
    let cert = base.with_serial_number(&serial).unwrap();
    assert!(crl.check_cert(&cert).unwrap());
    assert!(crl.revoked_cert_by_serial(&serial).is_ok());
}
