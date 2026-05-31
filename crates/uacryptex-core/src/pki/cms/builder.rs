//! CMS SignedData builder (`signed_data_engine.c` MVP).

use crate::pki::cms::engine::{SignedDataEngine, SignerInfoEngine};
use crate::pki::cms::signed_data::SignedDataContainer;
use crate::pki::crypto::{DigestAdapter, SignAdapter};
use crate::pki::oid::OidId;
use crate::Result;

/// Sign encapsulated content and build a single-signer CMS SignedData (CAdES-BES subset).
pub fn build_signed_data(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
) -> Result<SignedDataContainer> {
    build_signed_data_with_stores(sa, content, content_type, &[], &[])
}

/// Like [`build_signed_data`] but embeds extra certificates and CRLs (CAdES-LT validation data).
pub fn build_signed_data_with_stores(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
    extra_certs: &[crate::pki::cert::Cert],
    extra_crls: &[crate::pki::crl::Crl],
) -> Result<SignedDataContainer> {
    use der::Decode;
    use x509_cert::crl::CertificateList;

    let cert = sa.cert()?;
    let data_da = DigestAdapter::init_by_cert(cert)?;
    let signer = SignerInfoEngine::new(sa, data_da, None)?;
    let mut engine = SignedDataEngine::new(signer);
    engine.set_data(content_type, content, true)?;
    engine.add_cert(cert.clone())?;
    for c in extra_certs {
        engine.add_cert(c.clone())?;
    }
    for crl in extra_crls {
        let list = CertificateList::from_der(&crl.encode()?)
            .map_err(|e| crate::Error::Internal(format!("crl decode for signed data: {e}")))?;
        engine.add_crl(list)?;
    }
    engine.generate()
}

/// Convenience: build and return PKCS#7 ContentInfo DER.
pub fn build_content_info(
    sa: &SignAdapter,
    content: &[u8],
    content_type: OidId,
) -> Result<Vec<u8>> {
    build_signed_data(sa, content, content_type)?.encode_content_info()
}
