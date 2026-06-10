//! CAdES profile helpers (C / T / X / LT / A — incremental).

use der::asn1::{Int, ObjectIdentifier};

use crate::pki::cert::Cert;
use crate::pki::cms::builder::{build_signed_data, build_signed_data_with_stores};
use crate::pki::cms::ets::{
    archive_timestamp_imprint, cades_c_timestamp_imprint, cades_refs_timestamp_imprint, cert_values,
    complete_certificate_refs, complete_revocation_refs, revocation_values_from_ocsp,
};
use crate::pki::cms::signed_data::SignedDataContainer;
use crate::pki::cms::signer_info::{
    archive_time_stamp_token_attribute, cert_crl_timestamp_token_attribute,
    cert_values_attribute, complete_certificate_refs_attribute,
    complete_revocation_refs_attribute, esc_time_stamp_token_attribute,
    revocation_values_attribute, signature_time_stamp_token_attribute,
};
use crate::pki::crl::Crl;
use crate::pki::crypto::{DigestAdapter, SignAdapter};
use crate::pki::engine::{
    default_tsp_digest_aids, etspreq_generate, etspresp_generate, TspAdapterMap,
};
use crate::pki::oid::OidId;
use crate::{Error, Result};

const DEFAULT_TSP_POLICY_OID: &str = "1.2.804.2.1.1.1.2.3.1";

fn timestamp_token_attribute(
    data: &[u8],
    tsp_sa: &SignAdapter,
    serial: &Int,
    current_time: i64,
    policy_oid: Option<&str>,
    attr_builder: fn(&crate::pki::cms::types::ContentInfo) -> Result<x509_cert::attr::Attribute>,
) -> Result<x509_cert::attr::Attribute> {
    let policy = policy_oid.unwrap_or(DEFAULT_TSP_POLICY_OID);
    let da = DigestAdapter::init_default()?;
    let policy = ObjectIdentifier::new(policy)
        .map_err(|e| crate::Error::Internal(format!("policy oid: {e}")))?;
    let tsp_req = etspreq_generate(&da, data, None, &policy, true)?;

    let mut tsp_map = TspAdapterMap::new();
    let tsp_cert = tsp_sa.cert()?;
    let tsp_da = DigestAdapter::init_by_cert(tsp_cert)?;
    tsp_map.add(tsp_da, tsp_sa.clone_state()?);
    let digest_aids = default_tsp_digest_aids()?;
    let tsp_resp = etspresp_generate(
        &tsp_map,
        &tsp_req.encode()?,
        serial,
        &digest_aids,
        current_time,
    )?;
    let token = tsp_resp.time_stamp_token()?;
    attr_builder(&token)
}

/// Build CMS SignedData with CAdES-C (BES + certificate/revocation refs).
pub fn build_content_info_cades_c(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    ref_crl: &Crl,
) -> Result<Vec<u8>> {
    let da = DigestAdapter::init_default()?;
    let cert_refs = complete_certificate_refs(ref_cert, &da)?;
    let rev_refs = complete_revocation_refs(ref_crl, &da)?;
    let cert_attr = complete_certificate_refs_attribute(&cert_refs)?;
    let rev_attr = complete_revocation_refs_attribute(&rev_refs)?;

    let container = build_signed_data(sa, content, content_type)?;
    container
        .with_signer_unsigned_attr(0, cert_attr)?
        .with_signer_unsigned_attr(0, rev_attr)?
        .encode_content_info()
}

fn apply_cades_c_attrs(
    container: SignedDataContainer,
    ref_cert: &Cert,
    ref_crl: &Crl,
) -> Result<SignedDataContainer> {
    let da = DigestAdapter::init_default()?;
    let cert_refs = complete_certificate_refs(ref_cert, &da)?;
    let rev_refs = complete_revocation_refs(ref_crl, &da)?;
    let cert_attr = complete_certificate_refs_attribute(&cert_refs)?;
    let rev_attr = complete_revocation_refs_attribute(&rev_refs)?;
    container
        .with_signer_unsigned_attr(0, cert_attr)?
        .with_signer_unsigned_attr(0, rev_attr)
}

fn build_cades_xl_base(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    ref_crl: &Crl,
    validation_crls: &[Crl],
    ocsp_response: &[u8],
) -> Result<SignedDataContainer> {
    let container = build_signed_data_with_stores(
        sa,
        content,
        content_type,
        std::slice::from_ref(ref_cert),
        validation_crls,
    )?;
    let container = apply_cades_c_attrs(container, ref_cert, ref_crl)?;
    apply_cades_x_attrs(container, ref_cert, ocsp_response)
}

fn apply_cades_x_attrs(
    container: SignedDataContainer,
    ref_cert: &Cert,
    ocsp_response: &[u8],
) -> Result<SignedDataContainer> {
    let cert_vals = cert_values(ref_cert)?;
    let rev_vals = revocation_values_from_ocsp(ocsp_response)?;
    let cert_attr = cert_values_attribute(&cert_vals)?;
    let rev_attr = revocation_values_attribute(&rev_vals)?;
    container
        .with_signer_unsigned_attr(0, cert_attr)?
        .with_signer_unsigned_attr(0, rev_attr)
}

/// Build CMS SignedData with CAdES-X (BES + certificate/revocation values).
pub fn build_content_info_cades_x(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    ocsp_response: &[u8],
) -> Result<Vec<u8>> {
    let container = build_signed_data(sa, content, content_type)?;
    apply_cades_x_attrs(container, ref_cert, ocsp_response)?.encode_content_info()
}

/// Build CMS SignedData with CAdES-LT (X + validation data embedded in SignedData).
pub fn build_content_info_cades_lt(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    validation_crls: &[Crl],
    ocsp_response: &[u8],
) -> Result<Vec<u8>> {
    let ref_crl = validation_crls.first().ok_or_else(|| {
        Error::InvalidParam("validation CRL list must not be empty".into())
    })?;
    build_cades_xl_base(
        sa,
        content,
        content_type,
        ref_cert,
        ref_crl,
        validation_crls,
        ocsp_response,
    )?
    .encode_content_info()
}

/// Build CMS SignedData with CAdES-X Long Type 1 (LT + id-aa-ets-escTimeStamp).
#[allow(clippy::too_many_arguments)]
pub fn build_content_info_cades_xl_type1(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    validation_crls: &[Crl],
    ocsp_response: &[u8],
    tsp_sa: &SignAdapter,
    serial: &Int,
    current_time: i64,
    policy_oid: Option<&str>,
) -> Result<Vec<u8>> {
    let ref_crl = validation_crls.first().ok_or_else(|| {
        Error::InvalidParam("validation CRL list must not be empty".into())
    })?;
    let container = build_cades_xl_base(
        sa,
        content,
        content_type,
        ref_cert,
        ref_crl,
        validation_crls,
        ocsp_response,
    )?;
    let imprint = cades_c_timestamp_imprint(&container, 0)?;
    let attr = timestamp_token_attribute(
        &imprint,
        tsp_sa,
        serial,
        current_time,
        policy_oid,
        esc_time_stamp_token_attribute,
    )?;
    container
        .with_signer_unsigned_attr(0, attr)?
        .encode_content_info()
}

/// Build CMS SignedData with CAdES-X Long Type 2 (LT + id-aa-ets-certCRLTimestamp).
#[allow(clippy::too_many_arguments)]
pub fn build_content_info_cades_xl_type2(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    validation_crls: &[Crl],
    ocsp_response: &[u8],
    tsp_sa: &SignAdapter,
    serial: &Int,
    current_time: i64,
    policy_oid: Option<&str>,
) -> Result<Vec<u8>> {
    let ref_crl = validation_crls.first().ok_or_else(|| {
        Error::InvalidParam("validation CRL list must not be empty".into())
    })?;
    let container = build_cades_xl_base(
        sa,
        content,
        content_type,
        ref_cert,
        ref_crl,
        validation_crls,
        ocsp_response,
    )?;
    let imprint = cades_refs_timestamp_imprint(&container, 0)?;
    let attr = timestamp_token_attribute(
        &imprint,
        tsp_sa,
        serial,
        current_time,
        policy_oid,
        cert_crl_timestamp_token_attribute,
    )?;
    container
        .with_signer_unsigned_attr(0, attr)?
        .encode_content_info()
}

/// Build CMS SignedData with CAdES-A (LT + id-aa-ets-archiveTimeStamp).
#[allow(clippy::too_many_arguments)]
pub fn build_content_info_cades_a(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    ref_cert: &Cert,
    validation_crls: &[Crl],
    ocsp_response: &[u8],
    tsp_sa: &SignAdapter,
    serial: &Int,
    current_time: i64,
    policy_oid: Option<&str>,
) -> Result<Vec<u8>> {
    let container = build_signed_data_with_stores(
        sa,
        content,
        content_type,
        std::slice::from_ref(ref_cert),
        validation_crls,
    )?;
    let container = apply_cades_x_attrs(container, ref_cert, ocsp_response)?;
    let imprint = archive_timestamp_imprint(&container, 0)?;
    let attr = timestamp_token_attribute(
        &imprint,
        tsp_sa,
        serial,
        current_time,
        policy_oid,
        archive_time_stamp_token_attribute,
    )?;
    container
        .with_signer_unsigned_attr(0, attr)?
        .encode_content_info()
}

/// Build CMS SignedData with CAdES-T (BES + id-aa-signatureTimeStampToken).
pub fn build_content_info_cades_t(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    tsp_sa: &SignAdapter,
    serial: &Int,
    current_time: i64,
    policy_oid: Option<&str>,
) -> Result<Vec<u8>> {
    let container = build_signed_data(sa, content, content_type)?;
    let sinfo = container
        .inner()
        .signer_info(0)
        .ok_or_else(|| crate::Error::Unsupported("CMS has no signers".into()))?;
    let signature = sinfo.signature.as_bytes();
    let attr = timestamp_token_attribute(
        signature,
        tsp_sa,
        serial,
        current_time,
        policy_oid,
        signature_time_stamp_token_attribute,
    )?;
    container
        .with_signer_unsigned_attr(0, attr)?
        .encode_content_info()
}
