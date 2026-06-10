//! Certificate request engine (`certificate_request_engine.c`).

use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::request::{CertReqInfo, Version};

use crate::pki::creq::{
    cert_req_attributes_from_extensions, cert_req_public_key_from_spki, creq_init_by_adapter,
    CertificationRequest,
};
use crate::pki::crypto::SignAdapter;
use crate::pki::ext::{
    ext_create_subj_alt_name_dns_email, ext_create_subj_dir_attr_directly, ext_create_subj_key_id,
};
use crate::pki::utils::name_from_subject_string;
use crate::Result;

/// Cryptonite `CertificateRequestEngine`.
pub struct CertificateRequestEngine<'a> {
    sign_adapter: &'a SignAdapter,
    subject: Name,
    subj_alt_name: Option<Extension>,
    subj_dir_attr: Option<Extension>,
    extensions: Vec<Extension>,
}

/// `ecert_request_alloc`.
pub fn ecert_request_alloc(sign_adapter: &SignAdapter) -> Result<CertificateRequestEngine<'_>> {
    Ok(CertificateRequestEngine {
        sign_adapter,
        subject: Name::default(),
        subj_alt_name: None,
        subj_dir_attr: None,
        extensions: Vec::new(),
    })
}

/// `ecert_request_set_subj_name`.
pub fn ecert_request_set_subj_name(
    engine: &mut CertificateRequestEngine<'_>,
    subject_name: Option<&str>,
) -> Result<()> {
    engine.subject = match subject_name {
        Some(name) => name_from_subject_string(name)?,
        None => Name::default(),
    };
    Ok(())
}

/// `ecert_request_set_subj_alt_name`.
pub fn ecert_request_set_subj_alt_name(
    engine: &mut CertificateRequestEngine<'_>,
    dns: Option<&str>,
    email: Option<&str>,
) -> Result<()> {
    engine.subj_alt_name = match (dns, email) {
        (Some(dns), Some(email)) => Some(ext_create_subj_alt_name_dns_email(false, dns, email)?),
        _ => None,
    };
    Ok(())
}

/// `ecert_request_set_subj_dir_attr`.
pub fn ecert_request_set_subj_dir_attr(
    engine: &mut CertificateRequestEngine<'_>,
    subject_attr: Option<&str>,
) -> Result<()> {
    engine.subj_dir_attr = match subject_attr {
        Some(attr) => Some(ext_create_subj_dir_attr_directly(false, attr)?),
        None => None,
    };
    Ok(())
}

/// `ecert_request_add_ext`.
pub fn ecert_request_add_ext(
    engine: &mut CertificateRequestEngine<'_>,
    extension: Extension,
) -> Result<()> {
    engine.extensions.push(extension);
    Ok(())
}

/// `ecert_request_generate`.
pub fn ecert_request_generate(
    engine: &CertificateRequestEngine<'_>,
    out: &mut Option<CertificationRequest>,
) -> Result<()> {
    let spki_der = engine.sign_adapter.spki_der()?;
    let mut extensions = engine.extensions.clone();
    if let Some(ext) = &engine.subj_alt_name {
        extensions.push(ext.clone());
    }
    if let Some(ext) = &engine.subj_dir_attr {
        extensions.push(ext.clone());
    }
    extensions.push(ext_create_subj_key_id(false, &spki_der)?);

    let info = CertReqInfo {
        version: Version::V1,
        subject: engine.subject.clone(),
        public_key: cert_req_public_key_from_spki(&spki_der)?,
        attributes: cert_req_attributes_from_extensions(extensions)?,
    };
    *out = Some(creq_init_by_adapter(info, engine.sign_adapter)?);
    Ok(())
}
