//! Issuer name/key hashing for OCSP CertID (`ocsp_request_engine.c`).

use der::Encode;
use x509_cert::Certificate;

use crate::pki::cert::Cert;
use crate::pki::crypto::DigestAdapter;
use crate::Result;

/// Hash `data` with the digest algorithm from `algorithm_der`.
pub fn digest_bytes(algorithm_der: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut da = DigestAdapter::init_by_aid(algorithm_der)?;
    da.update(data)?;
    da.finalize()
}

/// `(name_hash, key_hash)` for OCSP CertID using issuer certificate subject and public key.
pub fn issuer_id_hashes(cert: &Cert, digest_aid: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    issuer_id_hashes_from_certificate(cert.inner_certificate(), digest_aid)
}

pub(crate) fn issuer_id_hashes_from_certificate(
    cert: &Certificate,
    digest_aid: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let subject_der = cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| crate::Error::Internal(format!("issuer name encode: {e}")))?;
    let key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let name_hash = digest_bytes(digest_aid, &subject_der)?;
    let key_hash = digest_bytes(digest_aid, key_bytes)?;
    Ok((name_hash, key_hash))
}
