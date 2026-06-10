//! X.509 extension KAT (`pkixUtest/c/utest_ext.c`).

use der::asn1::GeneralizedTime;
use der::Decode;
use std::time::Duration;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::creq::creq_get_ext_by_oid;
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::engine::{
    ecert_request_add_ext, ecert_request_alloc, ecert_request_generate,
};
use uacryptex_core::pki::ext::{
    ext_create_any, ext_create_auth_info_access, ext_create_auth_key_id_from_cert,
    ext_create_auth_key_id_from_spki, ext_create_basic_constraints, ext_create_cert_policies,
    ext_create_crl_distr_points, ext_create_crl_id, ext_create_crl_number, ext_create_crl_reason,
    ext_create_delta_crl_indicator, ext_create_ext_key_usage, ext_create_freshest_crl,
    ext_create_invalidity_date, ext_create_key_usage, ext_create_nonce,
    ext_create_private_key_usage, ext_create_private_key_usage_from_cert,
    ext_create_qc_statements, ext_create_subj_alt_name_directly, ext_create_subj_alt_name_dns_email,
    ext_create_subj_info_access, ext_create_subj_key_id, GeneralNameKind,
    ext_from_der, ext_get_value, ext_to_der, exts_add_extension, exts_get_ext_by_oid,
    exts_get_ext_value_by_oid, qc_statement_compliance, qc_statement_limit_value, CrlReasonCode,
    KeyUsageBits,
};
use uacryptex_core::pki::crypto::SignAdapter;
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::Error;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn assert_ext_value_roundtrip(ext: &uacryptex_core::pki::ext::ExtensionValue) {
    let der = ext_to_der(ext).expect("encode extension");
    let decoded = ext_from_der(&der).expect("decode extension");
    assert_eq!(ext_get_value(&decoded), ext_get_value(ext));
}

#[test]
fn ext_create_any_qc_statements() {
    let value = hex("300D300B06092A8624020101010201");
    let ext = ext_create_any(true, OidId::QcStatementsExtension, &value).unwrap();
    assert_eq!(ext_get_value(&ext), value);
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_key_usage_cert_and_crl_sign() {
    let usage = KeyUsageBits::KEY_CERT_SIGN.union(KeyUsageBits::CRL_SIGN);
    let ext = ext_create_key_usage(true, usage).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_basic_constraints_ca_with_path_zero() {
    let ext = ext_create_basic_constraints(true, None, true, 0).unwrap();
    assert_eq!(ext_get_value(&ext), hex("30060101FF020100"));
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_basic_constraints_with_issuer_path_len() {
    // `basic_constr` from utest: pathLen = 2 → output pathLen = 3.
    let ext = ext_create_basic_constraints(true, Some(2), true, 0).unwrap();
    assert_eq!(ext_get_value(&ext), hex("30060101FF020103"));
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_cert_policies_dstu_cp() {
    let ext = ext_create_cert_policies(true, &[OidId::PkiUkrEdsCp]).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_crl_distribution_point() {
    let ext = ext_create_crl_distr_points(true, &["http://ca.ua/crls/full.crl"]).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn freshest_crl_extension() {
    let ext = ext_create_freshest_crl(false, &["http://ca.ua/crls/delta.crl"]).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_auth_info_access_ocsp() {
    let ext = ext_create_auth_info_access(false, OidId::OcspOid, &["http://ca.ua/ocsp/"]).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_subj_info_access_tsp() {
    let ext = ext_create_subj_info_access(false, OidId::TspOid, &["http://ca.ua/time-stamping/"])
        .unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn nonce_extension() {
    let rnd = hex("0123456789ABCDEF");
    let ext = ext_create_nonce(false, &rnd).unwrap();
    assert_eq!(ext_get_value(&ext), hex("04080123456789ABCDEF"));
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_crl_number_and_delta_indicator() {
    let sn = hex("0123");
    let number = ext_create_crl_number(false, &sn).unwrap();
    assert_ext_value_roundtrip(&number);

    let delta = ext_create_delta_crl_indicator(true, &sn).unwrap();
    assert_eq!(ext_get_value(&number), ext_get_value(&delta));
    assert_ext_value_roundtrip(&delta);
}

#[test]
fn ext_create_crl_reason_key_compromise() {
    let ext = ext_create_crl_reason(false, CrlReasonCode::KeyCompromise).unwrap();
    assert_eq!(ext_get_value(&ext), hex("0a0101"));
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_ext_key_usage_ocsp() {
    let ext = ext_create_ext_key_usage(true, &[OidId::OcspKeyPurpose]).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn private_key_usage_period_extension() {
    let not_before =
        GeneralizedTime::from_unix_duration(Duration::from_secs(1_358_956_800)).unwrap();
    let not_after =
        GeneralizedTime::from_unix_duration(Duration::from_secs(1_674_585_600)).unwrap();
    let ext = ext_create_private_key_usage(false, Some(not_before), Some(not_after)).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_any_rejects_empty_value() {
    assert!(matches!(
        ext_create_any(true, OidId::QcStatementsExtension, &[]).unwrap_err(),
        Error::InvalidParam(_)
    ));
}

#[test]
fn ext_create_auth_info_access_rejects_null_uri() {
    assert!(ext_create_auth_info_access(false, OidId::OcspOid, &[""]).is_err());
}

#[test]
fn ext_create_cert_policies_rejects_empty_list() {
    assert!(ext_create_cert_policies(true, &[]).is_err());
}

#[test]
fn invalidity_date_extension() {
    let time = GeneralizedTime::from_unix_duration(Duration::from_secs(1_358_956_800)).unwrap();
    let ext = ext_create_invalidity_date(false, time).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn private_key_usage_rejects_partial_times() {
    let t = GeneralizedTime::from_unix_duration(Duration::from_secs(1_358_956_800)).unwrap();
    assert!(ext_create_private_key_usage(false, Some(t), None).is_err());
    assert!(ext_create_private_key_usage(false, None, Some(t)).is_err());
}

#[test]
fn subject_alt_name_raw_value_from_utest() {
    let value = hex(
        "3081A3A056060C2B0601040181974601010402A0460C4430343635352C20D0BC2E20D09AD0B8D197D0B22C20D09BD18CD0B2D196D0B2D181D18CD0BAD0B020D0BFD0BBD0BED189D0B02C20D0B1D183D0B4D0B8D0BDD0BED0BA2038A022060C2B0601040181974601010401A0120C102B333830283434292032343830303130820E6163736B6964642E676F762E75618115696E666F726D406163736B6964642E676F762E7561",
    );
    let ext = ext_create_any(false, OidId::SubjectAltNameExtension, &value).unwrap();
    assert_eq!(ext_get_value(&ext), value);

    let reference = x509_cert::ext::pkix::SubjectAltName::from_der(&value).unwrap();
    let mut kinds = Vec::new();
    let mut names = Vec::new();
    for gn in &reference.0 {
        match gn {
            x509_cert::ext::pkix::name::GeneralName::OtherName(on) => {
                let text = der::asn1::Utf8StringRef::try_from(&on.value).unwrap();
                kinds.push(GeneralNameKind::OtherName);
                names.push(format!("{}=utf8:{text}", on.type_id));
            }
            x509_cert::ext::pkix::name::GeneralName::DnsName(s) => {
                kinds.push(GeneralNameKind::DnsName);
                names.push(s.to_string());
            }
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(s) => {
                kinds.push(GeneralNameKind::Rfc822Name);
                names.push(s.to_string());
            }
            other => panic!("unexpected general name in utest fixture: {other:?}"),
        }
    }
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let built = ext_create_subj_alt_name_directly(false, &kinds, &name_refs).unwrap();
    assert_eq!(ext_get_value(&built), value);
}

#[test]
fn ext_create_subj_alt_name_dns_email_matches_directly() {
    let direct = ext_create_subj_alt_name_dns_email(false, "ca.ua", "info@ca.ua").unwrap();
    let manual = ext_create_subj_alt_name_directly(
        false,
        &[GeneralNameKind::DnsName, GeneralNameKind::Rfc822Name],
        &["ca.ua", "info@ca.ua"],
    )
    .unwrap();
    assert_eq!(ext_get_value(&direct), ext_get_value(&manual));
}

#[test]
fn ext_create_subj_alt_name_directly_rejects_invalid_params() {
    assert!(ext_create_subj_alt_name_directly(false, &[], &[]).is_err());
    assert!(ext_create_subj_alt_name_directly(
        false,
        &[GeneralNameKind::DnsName],
        &["ca.ua", "info@ca.ua"]
    )
    .is_err());
    assert!(matches!(
        ext_create_subj_alt_name_directly(
            false,
            &[GeneralNameKind::X400Address],
            &["ignored"]
        )
        .unwrap_err(),
        Error::Unsupported(_)
    ));
}

#[test]
fn ext_create_qc_statements_compliance_and_limit() {
    let statements = [
        qc_statement_compliance(),
        qc_statement_limit_value("UAH", 1000, 0).unwrap(),
    ];
    let ext = ext_create_qc_statements(true, &statements).unwrap();
    assert_ext_value_roundtrip(&ext);
    assert!(!ext_get_value(&ext).is_empty());
}

#[test]
fn ext_create_subj_key_id_from_tov_spki() {
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/tov_test.der")).unwrap();
    let spki = cert.spki_der().unwrap();
    let ext = ext_create_subj_key_id(false, &spki).unwrap();
    assert_eq!(
        ext_get_value(&ext),
        cert.extension_value(OidId::SubjectKeyIdentifierExtension)
            .unwrap()
    );
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_auth_key_id_from_tov_spki() {
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/tov_test.der")).unwrap();
    let spki = cert.spki_der().unwrap();
    let ext = ext_create_auth_key_id_from_spki(false, &spki).unwrap();
    let value = ext_get_value(&ext);
    assert!(!value.is_empty());
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_auth_key_id_from_tov_issuer_ski() {
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/tov_test.der")).unwrap();
    let ext = ext_create_auth_key_id_from_cert(false, &cert).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_crl_id_from_czo_full() {
    let crl = Crl::decode(include_bytes!("../../../testdata/pki/czo_full.crl")).unwrap();
    let crl_number = crl.crl_number().unwrap();
    let crl_time = GeneralizedTime::from_unix_duration(Duration::from_secs(
        crl.this_update_unix() as u64,
    ))
    .unwrap();
    let ext = ext_create_crl_id(
        false,
        Some("http://czo.gov.ua/download/crls/CZO-Full.crl"),
        Some(&crl_number),
        Some(crl_time),
    )
    .unwrap();
    assert_eq!(ext.extn_id.to_string(), "1.3.6.1.5.5.7.48.1.3");
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn ext_create_private_key_usage_from_certificate257_validity() {
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der")).unwrap();
    let ext = ext_create_private_key_usage_from_cert(false, &cert).unwrap();
    assert_ext_value_roundtrip(&ext);
}

#[test]
fn exts_collection_helpers() {
    let sn = hex("0123");
    let number = ext_create_crl_number(false, &sn).unwrap();
    let reason = ext_create_crl_reason(false, CrlReasonCode::KeyCompromise).unwrap();
    let mut exts = Vec::new();
    exts_add_extension(&mut exts, &number);
    exts_add_extension(&mut exts, &reason);

    let found = exts_get_ext_by_oid(&exts, OidId::CrlNumberExtension).unwrap();
    assert_eq!(ext_get_value(&found), ext_get_value(&number));

    let value = exts_get_ext_value_by_oid(&exts, OidId::CrlReasonExtension).unwrap();
    assert_eq!(value, ext_get_value(&reason));

    assert!(exts_get_ext_by_oid(&exts, OidId::NonceExtension).is_err());
}

#[test]
fn creq_get_ext_by_oid_from_generated_request() {
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der")).unwrap();
    let private_key = hex("7B66B62C23673C1299B84AE4AACFBBCA1C50FC134A846EF2E24A37407D01D32A");
    let sa = SignAdapter::init_by_cert(&private_key, &cert).unwrap();
    let subj_dir_attr = hex(
        "304F301A060C2A8624020101010B01040201310A13083131313131313131301C060C2A8624020101010B01040101310C130A313131313131313131313013060C2A8624020101010B010407013103130130",
    );
    let req_ext = ext_create_any(false, OidId::SubjectDirectoryAttributesExtension, &subj_dir_attr)
        .unwrap();

    let mut engine = ecert_request_alloc(&sa).unwrap();
    ecert_request_add_ext(&mut engine, req_ext.clone()).unwrap();
    let mut request = None;
    ecert_request_generate(&engine, &mut request).unwrap();
    let request = request.unwrap();

    let found = creq_get_ext_by_oid(&request, OidId::SubjectDirectoryAttributesExtension).unwrap();
    assert_eq!(ext_get_value(&found), ext_get_value(&req_ext));
}
