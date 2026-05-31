//! CMS EnvelopedData API (`cryptonite/src/pkix/c/api/enveloped_data.c`).

use der::asn1::SetOfVec;
use der::{Decode, Encode};
use x509_cert::spki::AlgorithmIdentifier;

use super::enveloped_types::EnvelopedData;
use crate::pki::cert::Cert;
use crate::pki::crypto::DhAdapter;
use crate::{Error, Result};

/// Parsed EnvelopedData container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopedDataContainer {
    inner: EnvelopedData,
}

impl EnvelopedDataContainer {
    /// `env_data_alloc`.
    pub fn new() -> Self {
        Self {
            inner: EnvelopedData {
                version: 0,
                originator_info: None,
                recipient_infos: super::enveloped_types::RecipientInfos(
                    SetOfVec::try_from(Vec::<super::enveloped_types::RecipientInfo>::new())
                        .expect("empty recipient infos"),
                ),
                encrypted_content_info: super::enveloped_types::EncryptedContentInfo {
                    content_type: der::asn1::ObjectIdentifier::new("1.2.840.113549.1.7.1")
                        .expect("data oid"),
                    content_encryption_algorithm: AlgorithmIdentifier {
                        oid: der::asn1::ObjectIdentifier::new("1.2.804.2.1.1.1.1.1.1.3")
                            .expect("cfb oid"),
                        parameters: None,
                    },
                    encrypted_content: None,
                },
                unprotected_attrs: None,
            },
        }
    }

    /// Build from parsed or generated ASN.1 value.
    pub fn from_inner(inner: EnvelopedData) -> Self {
        Self { inner }
    }

    /// `env_data_decode` — accepts PKCS#7 ContentInfo or bare EnvelopedData DER.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let normalized = crate::pki::utils::ber_to_der(der).unwrap_or_else(|_| der.to_vec());
        if let Ok(ci) = super::types::ContentInfo::from_der(&normalized) {
            let enveloped_oid = crate::pki::ext::object_identifier(crate::pki::oid::OidId::EnvelopedData)?;
            if ci.content_type != enveloped_oid {
                return Err(Error::Unsupported(format!(
                    "unsupported CMS content type: {}",
                    ci.content_type
                )));
            }
            let content = ci.content.ok_or_else(|| {
                Error::InvalidParam("ContentInfo missing EnvelopedData content".into())
            })?;
            let inner = content.decode_as::<EnvelopedData>().map_err(|e| {
                Error::Internal(format!("EnvelopedData decode: {e}"))
            })?;
            return Ok(Self { inner });
        }

        let inner = EnvelopedData::from_der(&normalized)
            .or_else(|_| EnvelopedData::from_der(der))
            .map_err(|e| Error::Internal(format!("enveloped data decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `env_data_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("enveloped data encode: {e}")))
    }

    /// `env_data_has_originator_cert`.
    pub fn has_originator_cert(&self) -> bool {
        self.inner
            .originator_info
            .as_ref()
            .and_then(|oi| oi.certs.as_ref())
            .is_some_and(|certs| !certs.0.is_empty())
    }

    /// `env_data_get_originator_cert`.
    pub fn originator_cert(&self) -> Result<Cert> {
        let certs = self
            .inner
            .originator_info
            .as_ref()
            .and_then(|oi| oi.certs.as_ref())
            .ok_or(Error::NoCertificate)?;
        let last = certs
            .0
            .as_slice()
            .last()
            .ok_or(Error::NoCertificate)?;
        match last {
            super::types::CertificateChoices::Certificate(cert) => {
                Cert::decode(&cert.to_der().map_err(|e| {
                    Error::Internal(format!("originator cert encode: {e}"))
                })?)
            }
        }
    }

    /// `env_get_content_encryption_aid`.
    pub fn content_encryption_algorithm_der(&self) -> Result<Vec<u8>> {
        self.inner
            .encrypted_content_info
            .content_encryption_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("content encryption aid encode: {e}")))
    }

    /// Underlying structure (for engine assembly).
    pub fn inner(&self) -> &EnvelopedData {
        &self.inner
    }

    /// Replace inner value after generation.
    pub fn set_inner(&mut self, inner: EnvelopedData) {
        self.inner = inner;
    }

    /// `env_decrypt_data`.
    pub fn decrypt_data(
        &self,
        external_ciphertext: Option<&[u8]>,
        originator_cert: Option<&Cert>,
        recipient_dh: &DhAdapter,
        recipient_cert: &Cert,
    ) -> Result<Vec<u8>> {
        super::enveloped_decrypt::decrypt_data(
            &self.inner,
            external_ciphertext,
            originator_cert,
            recipient_dh,
            recipient_cert,
        )
    }
}

impl Default for EnvelopedDataContainer {
    fn default() -> Self {
        Self::new()
    }
}

/// `env_data_init`.
pub fn env_data_init(
    container: &mut EnvelopedDataContainer,
    version: u32,
    originator_info: Option<super::enveloped_types::OriginatorInfo>,
    recipient_infos: super::enveloped_types::RecipientInfos,
    encrypted_content_info: super::enveloped_types::EncryptedContentInfo,
    unprotected_attrs: Option<x509_cert::attr::Attributes>,
) -> Result<()> {
    container.inner = EnvelopedData {
        version,
        originator_info,
        recipient_infos,
        encrypted_content_info,
        unprotected_attrs,
    };
    Ok(())
}

/// Build PKCS#7 ContentInfo wrapping EnvelopedData.
pub fn encode_content_info(container: &EnvelopedDataContainer) -> Result<Vec<u8>> {
    use crate::pki::ext::object_identifier;
    use crate::pki::oid::OidId;

    let oid = object_identifier(OidId::EnvelopedData)?;
    let content = container.encode()?;
    let any = der::Any::from_der(&content)
        .map_err(|e| Error::Internal(format!("enveloped content any: {e}")))?;
    let ci = super::types::ContentInfo {
        content_type: oid,
        content: Some(any),
    };
    ci.to_der()
        .map_err(|e| Error::Internal(format!("content info encode: {e}")))
}

/// `env_get_content_encryption_aid` as standalone guard.
pub fn env_get_content_encryption_aid(
    container: Option<&EnvelopedDataContainer>,
) -> Result<Vec<u8>> {
    let container = container.ok_or_else(|| Error::InvalidParam("null enveloped data".into()))?;
    container.content_encryption_algorithm_der()
}
