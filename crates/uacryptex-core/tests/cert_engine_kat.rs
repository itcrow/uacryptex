//! Certificate engine KAT (`pkixUtest/c/utest_cert_engine.c`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    ecert_alloc, ecert_generate, ecert_request_alloc, ecert_request_generate,
    ecert_request_set_subj_alt_name, ecert_request_set_subj_dir_attr, ecert_request_set_subj_name,
};

const SERIAL: [u8; 20] = [
    0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a,
    0xbc, 0xde, 0xff, 0x00,
];

const SUBJECT: &str = concat!(
    "{O=Петров Василь Олександрович ФОП}",
    "{OU=Керiвництво}",
    "{CN=Петров В.О.}",
    "{SRN=Петров}",
    "{GN=Василь Олександрович}",
    "{SN=9834567812}",
    "{C=UA}",
    "{L=Днiпропетровськ}",
    "{ST=Дніпропетровська}",
    "{T=Підприємець}"
);

fn mktime_utc(year: i32, mon: i32, mday: i32, hour: i32) -> i64 {
    let mut y = 1970;
    let mut days = 0i64;
    while y < year {
        days += if is_leap(y) { 366 } else { 365 };
        y += 1;
    }
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 0..(mon - 1) {
        days += month_days[m as usize] as i64;
        if m == 1 && is_leap(year) {
            days += 1;
        }
    }
    days += (mday - 1) as i64;
    days * 86_400 + (hour as i64) * 3_600
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn sign_aid() -> Vec<u8> {
    hex::decode("300d060b2a86240201010101030101").unwrap()
}

fn spki_aid() -> Vec<u8> {
    hex::decode(
        "3060060b2a862402010101010301013051060d2a8624020101010103010102060440a9d6eb45f13c708280c4967b231f5eadf658eba4c037291d38d96bf025ca4e17f8e9720dc615b43a28975f0bc1dea36438b564ea2c179fd0123e6db8fac57904",
    )
    .unwrap()
}

fn generate_dstu_private_key() -> Vec<u8> {
    use uacryptex_core::primitives::dstu4145::{generate_private_key, ParamsId, SystemRandom};
    let params = ParamsId::M257Pb.curve_params().unwrap();
    generate_private_key(&params, &mut SystemRandom).unwrap()
}

fn build_csr(sa: &SignAdapter) -> uacryptex_core::pki::creq::CertificationRequest {
    let mut eng = ecert_request_alloc(sa).expect("request alloc");
    ecert_request_set_subj_name(&mut eng, Some(SUBJECT)).expect("subject");
    ecert_request_set_subj_alt_name(&mut eng, Some("ca.ua"), Some("info@ca.ua")).expect("san");
    ecert_request_set_subj_dir_attr(&mut eng, Some("{1.2.804.2.1.1.1.11.1.4.1.1=292431128}"))
        .expect("sda");
    let mut req = None;
    ecert_request_generate(&eng, &mut req).expect("generate csr");
    req.expect("csr")
}

#[test]
fn ecert_generate_self_signed() {
    let not_before = mktime_utc(2013, 1, 25, 22);
    let not_after = mktime_utc(2023, 1, 25, 22);

    let private_key = generate_dstu_private_key();
    let sa = SignAdapter::init_by_aid(&private_key, &sign_aid(), &spki_aid()).unwrap();
    let da = DigestAdapter::init_default().unwrap();
    let req = build_csr(&sa);

    let engine = ecert_alloc(&sa, da, true).expect("cert engine");
    let mut cert = None;
    ecert_generate(
        &engine,
        &req,
        2,
        &SERIAL,
        not_before,
        not_after,
        Some(&[]),
        &mut cert,
    )
    .expect("generate");
    let cert = cert.expect("certificate");

    assert_eq!(cert.not_before_unix(), not_before);
    assert_eq!(cert.not_after_unix(), not_after);
    assert_eq!(cert.version(), 2);
    cert.verify(&VerifyAdapter::init_by_cert(&cert).unwrap())
        .expect("self verify");
}

#[test]
fn ecert_generate_ca_signed() {
    let not_before = mktime_utc(2013, 1, 25, 22);
    let not_after = mktime_utc(2023, 1, 25, 22);

    let ca_key =
        hex::decode("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A").unwrap();
    let ca_cert = Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der")).unwrap();
    let ca_sa = SignAdapter::init_by_cert(&ca_key, &ca_cert).unwrap();
    let da = DigestAdapter::init_default().unwrap();

    let end_entity_key = generate_dstu_private_key();
    let ee_sa = SignAdapter::init_by_aid(&end_entity_key, &sign_aid(), &spki_aid()).unwrap();
    let req = build_csr(&ee_sa);

    let engine = ecert_alloc(&ca_sa, da, false).expect("cert engine");
    let mut cert = None;
    ecert_generate(
        &engine,
        &req,
        2,
        &SERIAL,
        not_before,
        not_after,
        Some(&[]),
        &mut cert,
    )
    .expect("generate");
    let cert = cert.expect("certificate");

    assert_eq!(cert.not_before_unix(), not_before);
    assert_eq!(cert.not_after_unix(), not_after);
    cert.verify(&VerifyAdapter::init_by_cert(&ca_cert).unwrap())
        .expect("chain verify");
}

#[test]
fn ecert_generate_generalized_time_not_after() {
    let not_before = mktime_utc(2013, 1, 25, 22);
    let not_after = mktime_utc(2053, 1, 25, 22);

    let private_key = generate_dstu_private_key();
    let sa = SignAdapter::init_by_aid(&private_key, &sign_aid(), &spki_aid()).unwrap();
    let da = DigestAdapter::init_default().unwrap();
    let req = build_csr(&sa);

    let engine = ecert_alloc(&sa, da, true).unwrap();
    let mut cert = None;
    ecert_generate(
        &engine, &req, 2, &SERIAL, not_before, not_after, None, &mut cert,
    )
    .unwrap();
    let cert = cert.unwrap();
    assert_eq!(cert.not_after_unix(), not_after);
}
