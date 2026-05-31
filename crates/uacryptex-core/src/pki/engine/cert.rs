//! Certificate issuance engine (`cert_engine.c`).

use der::Decode;
use x509_cert::certificate::{TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Validity;

use crate::pki::cert::Cert;
use crate::pki::creq::CertificationRequest;
use crate::pki::crypto::{DigestAdapter, SignAdapter};
use crate::pki::utils::pkix_time_from_unix;
use crate::{Error, Result};

/// Cryptonite `CertificateEngine`.
pub struct CertificateEngine<'a> {
    sign_adapter: &'a SignAdapter,
    _digest_adapter: DigestAdapter,
    is_self_signed: bool,
}

/// `ecert_alloc`.
pub fn ecert_alloc(
    sign_adapter: &SignAdapter,
    digest_adapter: DigestAdapter,
    is_self_signed: bool,
) -> Result<CertificateEngine<'_>> {
    if !is_self_signed && !sign_adapter.has_cert() {
        return Err(Error::NoCertificate);
    }
    Ok(CertificateEngine {
        sign_adapter,
        _digest_adapter: digest_adapter,
        is_self_signed,
    })
}

/// `ecert_generate`.
pub fn ecert_generate(
    engine: &CertificateEngine<'_>,
    request: &CertificationRequest,
    version: u8,
    serial_number: &[u8],
    not_before: i64,
    not_after: i64,
    extensions: Option<&[Extension]>,
    out: &mut Option<Cert>,
) -> Result<()> {
    let cert_version = match version {
        0 => Version::V1,
        1 => Version::V2,
        2 => Version::V3,
        _ => {
            return Err(Error::InvalidParam(format!(
                "unsupported certificate version: {version}"
            )));
        }
    };

    let signature = if engine.is_self_signed {
        request.algorithm.clone()
    } else {
        AlgorithmIdentifierOwned::from_der(engine.sign_adapter.signature_algorithm_der())
            .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?
    };

    let (issuer, subject) = if engine.is_self_signed {
        (
            request.info.subject.clone(),
            request.info.subject.clone(),
        )
    } else {
        let issuer_cert = engine.sign_adapter.cert()?;
        (
            issuer_cert.subject().clone(),
            request.info.subject.clone(),
        )
    };

    let validity = Validity {
        not_before: pkix_time_from_unix(not_before)?,
        not_after: pkix_time_from_unix(not_after)?,
    };

    let serial = SerialNumber::new(serial_number)
        .map_err(|e| Error::Internal(format!("serial number: {e}")))?;

    let tbs = TbsCertificate {
        version: cert_version,
        serial_number: serial,
        signature,
        issuer,
        validity,
        subject,
        subject_public_key_info: request.info.public_key.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: extensions.map(|exts| exts.to_vec()),
    };

    *out = Some(Cert::init_by_adapter(tbs, engine.sign_adapter)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkix_time_uses_generalized_after_limit() {
        let time = pkix_time_from_unix(2_524_608_000).unwrap();
        assert!(matches!(time, x509_cert::time::Time::GeneralTime(_)));
    }
}
