//! Live PKI hierarchy generation for `pki_example.c` (M257 PB parameter set).

use der::asn1::GeneralizedTime;
use std::time::Duration;
use x509_cert::ext::Extension;

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::creq::CertificationRequest;
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    ecert_alloc, ecert_generate, ecert_request_alloc, ecert_request_generate,
    ecert_request_set_subj_alt_name, ecert_request_set_subj_dir_attr, ecert_request_set_subj_name,
    ecrl_add_revoked_cert_by_sn, ecrl_alloc, ecrl_generate_diff_next_update, etspreq_generate,
    CrlType, OcspRequestEngine,
};
use uacryptex_core::pki::ext::{
    ext_create_auth_info_access, ext_create_auth_key_id_from_cert,
    ext_create_auth_key_id_from_spki, ext_create_basic_constraints, ext_create_cert_policies,
    ext_create_crl_distr_points, ext_create_crl_number, ext_create_delta_crl_indicator,
    ext_create_ext_key_usage, ext_create_freshest_crl, ext_create_key_usage,
    ext_create_private_key_usage, ext_create_qc_statements, ext_create_subj_alt_name_directly,
    ext_create_subj_dir_attr_directly, ext_create_subj_key_id, qc_statement_compliance,
    qc_statement_limit_value, CrlReasonCode, KeyUsageBits, QcStatement,
};
use uacryptex_core::pki::ocsp::OcspReq;
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::pki::tsp::TspReq;
use uacryptex_core::pki::utils::object_identifier_from_text;
use uacryptex_core::storage::pkcs12::{
    pkcs12_create, pkcs12_decode, pkcs12_encode, pkcs12_generate_key, pkcs12_get_sign_adapter,
    pkcs12_select_key, pkcs12_set_certificates, pkcs12_store_key, Pkcs12, Pkcs12MacType,
};
use uacryptex_core::Result;

pub const STORAGE_PASS: &str = "123456";
pub const KEY_PASS: &str = "123456";
pub const KEY_ALIAS: &str = "alias";
const HASH_ROUNDS: u32 = 1024;

const ROOT_SERIAL: [u8; 20] = [
    0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a,
    0xbc, 0xde, 0xff, 0x00,
];
const USERFIZ_SERIAL: [u8; 20] = [
    0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a,
    0xbc, 0xde, 0xff, 0x02,
];
const USERUR_SERIAL: [u8; 20] = [
    0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a,
    0xbc, 0xde, 0xff, 0x03,
];
const OCSP_SERIAL: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xa8, 0x6d, 0x18,
    0xdb, 0xc8, 0xb0, 0x4c,
];

const ROOT_SUBJECT: &str = concat!(
    "{O=ТЕСТ}",
    "{OU=ЦСК}",
    "{CN=ЦСК ТЕСТ}",
    "{SN=UA-123456789-4312}",
    "{C=UA}",
    "{L=Днiпропетровськ}",
    "{ST=Дніпропетровська}"
);

const USERFIZ_SUBJECT: &str = concat!(
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

const USERUR_SUBJECT: &str = concat!(
    "{O=ООО ТЕСТ}",
    "{OU=КЗИ}",
    "{CN=ТЕСТ}",
    "{SN=1234567890555}",
    "{C=UA}",
    "{L=Дniпропетровськ}",
    "{ST=Дніпропетровська}"
);

const OCSP_SUBJECT: &str = concat!(
    "{O=Test}",
    "{OU=ЦСК}",
    "{CN=OCSP-ЦСК Test}",
    "{SN=UA-123456789-4312}",
    "{C=UA}",
    "{L=Дniпропетровськ}",
    "{ST=Дніпропетровська}"
);

pub struct PkiExample {
    pub root: Cert,
    pub userfiz: Cert,
    pub userur: Cert,
    pub ocsp: Cert,
    pub userfiz_store: Vec<u8>,
    pub userur_store: Vec<u8>,
    pub ocsp_store: Vec<u8>,
    pub full_crl: Crl,
    pub delta_crl: Crl,
    pub ocsp_request: OcspReq,
    pub tsp_request: Vec<u8>,
}

impl PkiExample {
    pub fn generate() -> Result<Self> {
        let not_before = mktime_utc(2013, 1, 25, 22);
        let not_after = mktime_utc(2023, 1, 25, 22);
        let revoke_time = not_before;

        let mut root_store = generate_dstu_keypair()?;
        let root = generate_root_certificate(&mut root_store, not_before, not_after)?;
        let root_va = VerifyAdapter::init_by_cert(&root)?;

        let mut userfiz_store = generate_dstu_keypair()?;
        let (userfiz_req, userfiz_sda, _) = build_csr_parts(
            &mut userfiz_store,
            USERFIZ_SUBJECT,
            Some("{1.2.804.2.1.1.1.11.1.4.1.1=292431128}"),
            None,
        )?;
        let userfiz_exts = extgen_user_end_entity(
            &userfiz_store,
            &root,
            userfiz_sda.as_ref(),
            &[qc_statement_compliance()],
        )?;
        let userfiz = generate_end_entity_certificate(
            &mut root_store,
            &root,
            &mut userfiz_store,
            &userfiz_req,
            &USERFIZ_SERIAL,
            userfiz_exts,
            not_before,
            not_after,
        )?;

        let mut userur_store = generate_dstu_keypair()?;
        let (userur_req, userur_sda, _) = build_csr_parts(
            &mut userur_store,
            USERUR_SUBJECT,
            Some("{1.2.804.2.1.1.1.11.1.4.2.1=23456}"),
            None,
        )?;
        let userur_qc = vec![
            qc_statement_compliance(),
            qc_statement_limit_value("UAH", 1000, 0)?,
        ];
        let userur_exts =
            extgen_user_end_entity(&userur_store, &root, userur_sda.as_ref(), &userur_qc)?;
        let userur = generate_end_entity_certificate(
            &mut root_store,
            &root,
            &mut userur_store,
            &userur_req,
            &USERUR_SERIAL,
            userur_exts,
            not_before,
            not_after,
        )?;

        let mut ocsp_store = generate_dstu_keypair()?;
        let (ocsp_req, _, _) = build_csr_parts(&mut ocsp_store, OCSP_SUBJECT, None, None)?;
        let ocsp_exts = extgen_ocsp(&ocsp_store, &root, not_before, not_after)?;
        let ocsp = generate_end_entity_certificate(
            &mut root_store,
            &root,
            &mut ocsp_store,
            &ocsp_req,
            &OCSP_SERIAL,
            ocsp_exts,
            not_before,
            not_after,
        )?;

        let (full_crl, delta_crl) = generate_crls(&mut root_store, &root, &root_va, revoke_time)?;
        let ocsp_request = generate_ocsp_request(&root, &userfiz, &ocsp, &userfiz_store)?;
        let tsp_request = generate_tsp_request()?;

        Ok(Self {
            root,
            userfiz,
            userur,
            ocsp,
            userfiz_store: pkcs12_encode(&userfiz_store)?,
            userur_store: pkcs12_encode(&userur_store)?,
            ocsp_store: pkcs12_encode(&ocsp_store)?,
            full_crl,
            delta_crl,
            ocsp_request,
            tsp_request,
        })
    }

    pub fn root_va(&self) -> Result<VerifyAdapter> {
        VerifyAdapter::init_by_cert(&self.root)
    }

    pub fn userfiz_sign_adapter(&self) -> Result<SignAdapter> {
        sign_adapter_from_store(&self.userfiz_store)
    }

    pub fn ocsp_sign_adapter(&self) -> Result<SignAdapter> {
        sign_adapter_from_store(&self.ocsp_store)
    }

    pub fn userur_sign_adapter(&self) -> Result<SignAdapter> {
        sign_adapter_from_store(&self.userur_store)
    }
}

pub fn sign_adapter_from_store(store_der: &[u8]) -> Result<SignAdapter> {
    let mut store = pkcs12_decode(None, store_der, STORAGE_PASS)?;
    pkcs12_select_key(&mut store, Some(KEY_ALIAS), Some(KEY_PASS))?;
    pkcs12_get_sign_adapter(&store)
}

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

fn generalized_time(unix_secs: i64) -> Result<GeneralizedTime> {
    GeneralizedTime::from_unix_duration(Duration::from_secs(unix_secs as u64))
        .map_err(|e| uacryptex_core::Error::Internal(format!("generalized time: {e}")))
}

fn crl_number_sn(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("valid crl number hex")
}

fn generate_dstu_keypair() -> Result<Pkcs12> {
    let mut store = pkcs12_create(Pkcs12MacType::Gost34311, STORAGE_PASS, HASH_ROUNDS)?;
    pkcs12_generate_key(&mut store, None)?;
    pkcs12_store_key(&mut store, Some(KEY_ALIAS), Some(KEY_PASS), HASH_ROUNDS)?;
    pkcs12_select_key(&mut store, Some(KEY_ALIAS), Some(KEY_PASS))?;
    Ok(store)
}

fn build_csr_parts(
    store: &mut Pkcs12,
    subject: &str,
    subject_attr: Option<&str>,
    dns_email: Option<(&str, &str)>,
) -> Result<(CertificationRequest, Option<Extension>, Option<Extension>)> {
    let sa = pkcs12_get_sign_adapter(store)?;
    let mut eng = ecert_request_alloc(&sa)?;
    ecert_request_set_subj_name(&mut eng, Some(subject))?;
    let san = if let Some((dns, email)) = dns_email {
        ecert_request_set_subj_alt_name(&mut eng, Some(dns), Some(email))?;
        Some(ext_create_subj_alt_name_directly(false, dns, email)?)
    } else {
        None
    };
    let sda = if let Some(attr) = subject_attr {
        ecert_request_set_subj_dir_attr(&mut eng, Some(attr))?;
        Some(ext_create_subj_dir_attr_directly(false, attr)?)
    } else {
        None
    };
    let mut req = None;
    ecert_request_generate(&eng, &mut req)?;
    let req = req.ok_or_else(|| uacryptex_core::Error::Internal("csr missing".into()))?;
    Ok((req, sda, san))
}

fn issue_certificate(
    issuer_store: &mut Pkcs12,
    subject_store: Option<&mut Pkcs12>,
    req: &CertificationRequest,
    serial: &[u8],
    extensions: &[Extension],
    not_before: i64,
    not_after: i64,
    self_signed: bool,
) -> Result<Cert> {
    let da = DigestAdapter::init_default()?;
    let issuer_sa = pkcs12_get_sign_adapter(issuer_store)?;
    let engine = ecert_alloc(&issuer_sa, da, self_signed)?;
    let mut cert = None;
    ecert_generate(
        &engine,
        req,
        2,
        serial,
        not_before,
        not_after,
        Some(extensions),
        &mut cert,
    )?;
    let cert = cert.ok_or_else(|| uacryptex_core::Error::Internal("certificate missing".into()))?;
    let cert_der = cert.encode()?;
    if let Some(subject_store) = subject_store {
        pkcs12_set_certificates(subject_store, &[&cert_der])?;
    } else {
        pkcs12_set_certificates(issuer_store, &[&cert_der])?;
    }
    Ok(cert)
}

fn generate_root_certificate(
    root_store: &mut Pkcs12,
    not_before: i64,
    not_after: i64,
) -> Result<Cert> {
    let (req, _, san) = build_csr_parts(
        root_store,
        ROOT_SUBJECT,
        None,
        Some(("ca.ua", "info@ca.ua")),
    )?;
    let sa = pkcs12_get_sign_adapter(root_store)?;
    let extensions = extgen_root(&sa.spki_der()?, san.as_ref())?;
    let cert = issue_certificate(
        root_store,
        None,
        &req,
        &ROOT_SERIAL,
        &extensions,
        not_before,
        not_after,
        true,
    )?;
    cert.verify(&VerifyAdapter::init_by_cert(&cert)?)?;
    Ok(cert)
}

fn generate_end_entity_certificate(
    issuer_store: &mut Pkcs12,
    issuer_cert: &Cert,
    subject_store: &mut Pkcs12,
    req: &CertificationRequest,
    serial: &[u8],
    extensions: Vec<Extension>,
    not_before: i64,
    not_after: i64,
) -> Result<Cert> {
    let cert = issue_certificate(
        issuer_store,
        Some(subject_store),
        req,
        serial,
        &extensions,
        not_before,
        not_after,
        false,
    )?;
    cert.verify(&VerifyAdapter::init_by_cert(issuer_cert)?)?;
    Ok(cert)
}

fn extgen_root(spki_der: &[u8], san: Option<&Extension>) -> Result<Vec<Extension>> {
    let mut exts = vec![
        ext_create_subj_key_id(false, spki_der)?,
        ext_create_auth_key_id_from_spki(false, spki_der)?,
        ext_create_key_usage(
            true,
            KeyUsageBits::KEY_CERT_SIGN.union(KeyUsageBits::CRL_SIGN),
        )?,
        ext_create_cert_policies(true, &[OidId::PkiUkrEdsCp])?,
        ext_create_basic_constraints(true, None, true, 0)?,
        ext_create_qc_statements(false, &[qc_statement_compliance()])?,
        ext_create_crl_distr_points(true, &["http://ca.ua/crls/full.crl"])?,
        ext_create_freshest_crl(false, &["http://ca.ua/crls/delta.crl"])?,
        ext_create_auth_info_access(false, OidId::OcspOid, &["http://ca.ua/ocsp/"])?,
    ];
    if let Some(san) = san {
        exts.insert(5, san.clone());
    }
    Ok(exts)
}

fn extgen_user_end_entity(
    store: &Pkcs12,
    issuer: &Cert,
    sda: Option<&Extension>,
    qc_statements: &[QcStatement],
) -> Result<Vec<Extension>> {
    let sa = pkcs12_get_sign_adapter(store)?;
    let spki_der = sa.spki_der()?;
    let end_entity_ku = KeyUsageBits::DIGITAL_SIGNATURE
        .union(KeyUsageBits::KEY_ENCIPHERMENT)
        .union(KeyUsageBits::KEY_AGREEMENT);
    let mut exts = vec![
        ext_create_subj_key_id(false, &spki_der)?,
        ext_create_auth_key_id_from_cert(false, issuer)?,
        ext_create_key_usage(true, end_entity_ku)?,
        ext_create_cert_policies(true, &[OidId::PkiUkrEdsCp])?,
        ext_create_basic_constraints(true, None, false, 0)?,
        ext_create_qc_statements(true, qc_statements)?,
        ext_create_crl_distr_points(false, &["http://ca.ua/crls/full.crl"])?,
        ext_create_freshest_crl(false, &["http://ca.ua/crls/delta.crl"])?,
    ];
    if let Some(sda) = sda {
        exts.push(sda.clone());
    }
    Ok(exts)
}

fn extgen_ocsp(
    store: &Pkcs12,
    issuer: &Cert,
    not_before: i64,
    not_after: i64,
) -> Result<Vec<Extension>> {
    let sa = pkcs12_get_sign_adapter(store)?;
    let spki_der = sa.spki_der()?;
    Ok(vec![
        ext_create_subj_key_id(false, &spki_der)?,
        ext_create_auth_key_id_from_cert(false, issuer)?,
        ext_create_private_key_usage(
            false,
            Some(generalized_time(not_before)?),
            Some(generalized_time(not_after)?),
        )?,
        ext_create_key_usage(true, KeyUsageBits::DIGITAL_SIGNATURE)?,
        ext_create_ext_key_usage(true, &[OidId::OcspKeyPurpose])?,
        ext_create_cert_policies(true, &[OidId::PkiUkrEdsCp])?,
        ext_create_basic_constraints(true, None, false, 0)?,
        ext_create_qc_statements(true, &[qc_statement_compliance()])?,
        ext_create_crl_distr_points(false, &["http://ca.ua/crls/full.crl"])?,
        ext_create_freshest_crl(false, &["http://ca.ua/crls/delta.crl"])?,
    ])
}

fn generate_crls(
    root_store: &mut Pkcs12,
    root_cert: &Cert,
    root_va: &VerifyAdapter,
    revoke_time: i64,
) -> Result<(Crl, Crl)> {
    let root_sa = pkcs12_get_sign_adapter(root_store)?;
    let full_exts = vec![
        ext_create_crl_number(false, &crl_number_sn("0123"))?,
        ext_create_freshest_crl(false, &["http://ca.ua/crls/delta.crl"])?,
        ext_create_auth_key_id_from_cert(false, root_cert)?,
    ];
    let mut full_engine = ecrl_alloc(
        None,
        &root_sa,
        root_va,
        Some(full_exts),
        "crl_full_templ",
        CrlType::Full,
        "description",
    )?;
    add_full_crl_revocations(&mut full_engine, revoke_time)?;
    let mut full_crl = None;
    ecrl_generate_diff_next_update(&full_engine, 60 * 60 * 24 * 7, &mut full_crl)?;
    let full_crl = full_crl.expect("full crl");

    let full_crl_number = full_crl.crl_number()?;
    let delta_exts = vec![
        ext_create_crl_number(false, &crl_number_sn("0124"))?,
        ext_create_delta_crl_indicator(true, &full_crl_number)?,
        ext_create_auth_key_id_from_cert(false, root_cert)?,
    ];
    let mut delta_engine = ecrl_alloc(
        Some(&full_crl),
        &root_sa,
        root_va,
        Some(delta_exts),
        "crl_delta_templ",
        CrlType::Delta,
        "description",
    )?;
    add_delta_crl_revocations(&mut delta_engine, revoke_time)?;
    let mut delta_crl = None;
    ecrl_generate_diff_next_update(&delta_engine, 60 * 60 * 24, &mut delta_crl)?;
    let delta_crl = delta_crl.expect("delta crl");

    full_crl.verify(root_va)?;
    delta_crl.verify(root_va)?;
    Ok((full_crl, delta_crl))
}

fn add_full_crl_revocations(
    engine: &mut uacryptex_core::pki::engine::CrlEngine<'_>,
    revoke_time: i64,
) -> Result<()> {
    let entries: [(&str, CrlReasonCode); 5] = [
        ("123", CrlReasonCode::AaCompromise),
        ("456", CrlReasonCode::AffiliationChanged),
        ("789", CrlReasonCode::KeyCompromise),
        ("098", CrlReasonCode::CertificateHold),
        ("463", CrlReasonCode::AaCompromise),
    ];
    for (sn, reason) in entries {
        ecrl_add_revoked_cert_by_sn(engine, sn.as_bytes(), Some(reason), Some(revoke_time))?;
    }
    Ok(())
}

fn add_delta_crl_revocations(
    engine: &mut uacryptex_core::pki::engine::CrlEngine<'_>,
    revoke_time: i64,
) -> Result<()> {
    let entries: [(&str, CrlReasonCode); 5] = [
        ("752", CrlReasonCode::AaCompromise),
        ("3468", CrlReasonCode::AffiliationChanged),
        ("72349072", CrlReasonCode::KeyCompromise),
        ("4902", CrlReasonCode::CertificateHold),
        ("4124802", CrlReasonCode::AaCompromise),
    ];
    for (sn, reason) in entries {
        ecrl_add_revoked_cert_by_sn(engine, sn.as_bytes(), Some(reason), Some(revoke_time))?;
    }
    Ok(())
}

fn generate_ocsp_request(
    root: &Cert,
    userfiz: &Cert,
    ocsp: &Cert,
    userfiz_store: &Pkcs12,
) -> Result<OcspReq> {
    let root_va = VerifyAdapter::init_by_cert(root)?;
    let ocsp_va = VerifyAdapter::init_by_cert(ocsp)?;
    let user_sa = pkcs12_get_sign_adapter(userfiz_store)?;
    let da = DigestAdapter::init_default()?;
    let mut engine = OcspRequestEngine::alloc(true, &root_va, Some(&ocsp_va), Some(&user_sa), &da)?;
    engine.add_cert(userfiz)?;
    let nonce = vec![0xAF; 20];
    engine.generate(Some(&nonce))
}

fn generate_tsp_request() -> Result<Vec<u8>> {
    let da = DigestAdapter::init_default()?;
    let test_data = vec![0xA5; 2048];
    let policy = object_identifier_from_text("1.2.804.2.1.1.1.2.3.1")?;
    let req: TspReq = etspreq_generate(&da, &test_data, None, &policy, false)?;
    req.encode()
}
