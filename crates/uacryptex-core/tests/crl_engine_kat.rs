//! CRL engine KAT (`pkixUtest/c/utest_crl_engine.c`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::{SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    ecrl_add_revoked_cert, ecrl_alloc, ecrl_generate, ecrl_generate_diff_next_update,
    ecrl_generate_next_update, ecrl_get_description, ecrl_get_template_name, ecrl_get_type,
    ecrl_merge_delta, CrlType,
};
use uacryptex_core::pki::ext::{ext_create_crl_distr_points, CrlReasonCode};
use uacryptex_core::Error;

fn root_key() -> Vec<u8> {
    include_bytes!("../../../testdata/pki/pki_example/root_private_key_ba.dat").to_vec()
}

fn root_cert() -> Cert {
    Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/root_certificate.cer"
    ))
    .unwrap()
}

fn root_adapters() -> (SignAdapter, VerifyAdapter) {
    let cert = root_cert();
    let sa = SignAdapter::init_by_cert(&root_key(), &cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();
    (sa, va)
}

fn load_full_crl() -> Crl {
    Crl::decode(include_bytes!("../../../testdata/pki/pki_example/full.crl")).unwrap()
}

fn load_delta_crl() -> Crl {
    Crl::decode(include_bytes!("../../../testdata/pki/pki_example/delta.crl")).unwrap()
}

#[test]
fn ecrl_generate_full_with_merge() {
    let (sa, va) = root_adapters();
    let prev = load_full_crl();
    let delta = load_delta_crl();

    let extensions = vec![
        ext_create_crl_distr_points(true, &["http://ca.ua/crls/full.crl"]).unwrap(),
    ];

    let mut engine = ecrl_alloc(
        Some(&prev),
        &sa,
        &va,
        Some(extensions),
        "crl_full_templ",
        CrlType::Full,
        "description",
    )
    .unwrap();

    ecrl_merge_delta(&mut engine, &delta).unwrap();
    assert_eq!(ecrl_get_template_name(&engine), "crl_full_templ");
    assert_eq!(ecrl_get_type(&engine), CrlType::Full);
    assert_eq!(ecrl_get_description(&engine), "description");

    let mut crl = None;
    ecrl_generate(&engine, &mut crl).unwrap();
    let crl = crl.unwrap();
    crl.verify(&va).unwrap();
}

#[test]
fn ecrl_generate_delta_add_revoked() {
    let (sa, va) = root_adapters();
    let prev = load_delta_crl();
    let mut engine = ecrl_alloc(
        Some(&prev),
        &sa,
        &va,
        None,
        "crl_delta_templ",
        CrlType::Delta,
        "description",
    )
    .unwrap();

    let revoked_cert =
        Cert::decode(include_bytes!("../../../testdata/pki/pki_example/userur_certificate.cer"))
            .unwrap();
    let revoke_time = 1_359_158_400i64;
    ecrl_add_revoked_cert(
        &mut engine,
        &revoked_cert,
        Some(CrlReasonCode::AaCompromise),
        Some(revoke_time),
    )
    .unwrap();

    let full = load_delta_crl();
    assert!(matches!(
        ecrl_merge_delta(&mut engine, &full),
        Err(Error::InvalidParam(_))
    ));

    let mut crl = None;
    ecrl_generate(&engine, &mut crl).unwrap();
    crl.unwrap().verify(&va).unwrap();
}

#[test]
fn kat_ecrl_generate_next_update() {
    let (sa, va) = root_adapters();
    let prev = load_full_crl();
    let engine = ecrl_alloc(
        Some(&prev),
        &sa,
        &va,
        None,
        "crl_full_templ",
        CrlType::Full,
        "description",
    )
    .unwrap();

    let next_update = 1_480_176_000i64;
    let mut crl = None;
    ecrl_generate_next_update(&engine, next_update, &mut crl).unwrap();
    let crl = crl.unwrap();
    crl.verify(&va).unwrap();
    let next = crl
        .tbs()
        .next_update
        .expect("nextUpdate")
        .to_unix_duration()
        .as_secs() as i64;
    assert_eq!(next, next_update);
}

#[test]
fn kat_ecrl_generate_diff_next_update() {
    let (sa, va) = root_adapters();
    let prev = load_full_crl();
    let engine = ecrl_alloc(
        Some(&prev),
        &sa,
        &va,
        None,
        "crl_full_templ",
        CrlType::Full,
        "description",
    )
    .unwrap();

    let mut crl = None;
    ecrl_generate_diff_next_update(&engine, 60 * 60 * 24 * 7, &mut crl).unwrap();
    crl.unwrap().verify(&va).unwrap();
}
