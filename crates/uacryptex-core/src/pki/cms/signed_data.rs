//! CMS SignedData API (`signed_data.c`).

use der::asn1::SetOfVec;
use der::{Any, Decode, Encode};
use x509_cert::crl::CertificateList;
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cert::Cert;
use crate::pki::cms::signer_info::{
    verify_signer_info, verify_signer_info_without_data, verify_signing_cert_v2,
};
use crate::pki::cms::types::{
    ContentInfo, RevocationInfoChoice, RevocationInfoChoices, SignedData,
};
use crate::pki::crypto::{DigestAdapter, VerifyAdapter};
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// Parsed CMS SignedData container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDataContainer {
    inner: SignedData,
}

impl SignedDataContainer {
    /// `sdata_decode` — accepts ContentInfo or bare SignedData DER.
    pub fn decode(der: &[u8]) -> Result<Self> {
        if let Ok(ci) = ContentInfo::from_der(der) {
            let signed_data_oid = object_identifier(OidId::SignedData)?;
            if ci.content_type != signed_data_oid {
                return Err(Error::Unsupported(format!(
                    "unsupported CMS content type: {}",
                    ci.content_type
                )));
            }
            let content = ci.content.ok_or_else(|| {
                Error::InvalidParam("ContentInfo missing SignedData content".into())
            })?;
            let inner = content.decode_as::<SignedData>().map_err(|e| {
                Error::Internal(format!("SignedData decode: {e}"))
            })?;
            return Ok(Self { inner });
        }

        let inner = SignedData::from_der(der)
            .map_err(|e| Error::Internal(format!("SignedData decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `sdata_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("SignedData encode: {e}")))
    }

    /// Encode as PKCS#7 ContentInfo wrapper.
    pub fn encode_content_info(&self) -> Result<Vec<u8>> {
        let signed_data_oid = object_identifier(OidId::SignedData)?;
        let content = Any::encode_from(&self.inner).map_err(|e| {
            Error::Internal(format!("SignedData any encode: {e}"))
        })?;
        let ci = ContentInfo {
            content_type: signed_data_oid,
            content: Some(content),
        };
        ci.to_der()
            .map_err(|e| Error::Internal(format!("ContentInfo encode: {e}")))
    }

    /// `sdata_get_version`.
    pub fn version(&self) -> u32 {
        self.inner.version
    }

    /// `sdata_get_data`.
    pub fn encapsulated_content(&self) -> Result<Vec<u8>> {
        self.inner.encap_content_info.content_bytes()
    }

    /// `sdata_get_digest_aid_by_idx`.
    pub fn digest_algorithm_der(&self, index: usize) -> Result<Vec<u8>> {
        let aid = self.inner.digest_algorithms.get(index).ok_or_else(|| {
            Error::InvalidParam("digest algorithm index out of bounds".into())
        })?;
        aid.to_der()
            .map_err(|e| Error::Internal(format!("digest aid encode: {e}")))
    }

    pub fn signer_count(&self) -> usize {
        self.inner.signer_infos.len()
    }

    /// `sdata_verify_internal_data_by_adapter`.
    pub fn verify_internal_data(
        &self,
        da: &DigestAdapter,
        va: &VerifyAdapter,
        index: usize,
    ) -> Result<()> {
        let sinfo = self.inner.signer_info(index).ok_or_else(|| {
            Error::InvalidParam("signer info index out of bounds".into())
        })?;
        let content = self.encapsulated_content()?;
        verify_signer_info(sinfo, &content, da, va)
    }

    /// `sdata_verify_without_data_by_adapter`.
    pub fn verify_without_data(&self, va: &VerifyAdapter, index: usize) -> Result<()> {
        let sinfo = self.inner.signer_info(index).ok_or_else(|| {
            Error::InvalidParam("signer info index out of bounds".into())
        })?;
        verify_signer_info_without_data(sinfo, va)
    }

    /// `sdata_verify_external_data_by_adapter`.
    pub fn verify_external_data(
        &self,
        data: &[u8],
        da: &DigestAdapter,
        va: &VerifyAdapter,
        index: usize,
    ) -> Result<()> {
        let sinfo = self.inner.signer_info(index).ok_or_else(|| {
            Error::InvalidParam("signer info index out of bounds".into())
        })?;
        verify_signer_info(sinfo, data, da, va)
    }

    pub fn inner(&self) -> &SignedData {
        &self.inner
    }

    /// `sdata_has_certs`.
    pub fn has_certs(&self) -> bool {
        self.inner
            .certificates
            .as_ref()
            .is_some_and(|c| !c.0.is_empty())
    }

    /// `sdata_has_crls`.
    pub fn has_crls(&self) -> bool {
        self.inner.crls.as_ref().is_some_and(|c| !c.0.is_empty())
    }

    /// `sdata_get_crl_by_idx` — returns CRL bytes (DER).
    pub fn crl_der(&self, index: usize) -> Result<Vec<u8>> {
        let crls = self.inner.crls.as_ref().ok_or_else(|| {
            Error::Unsupported("SignedData has no CRLs".into())
        })?;
        match crls.0.get(index) {
            Some(RevocationInfoChoice::Crl(crl)) => crl
                .to_der()
                .map_err(|e| Error::Internal(format!("CRL encode: {e}"))),
            None => Err(Error::InvalidParam("CRL index out of bounds".into())),
        }
    }

    /// `sdata_verify_signing_cert_by_adapter`.
    pub fn verify_signing_cert(
        &self,
        ess_da: &DigestAdapter,
        cert: &Cert,
        index: usize,
    ) -> Result<()> {
        let sinfo = self.inner.signer_info(index).ok_or_else(|| {
            Error::InvalidParam("signer info index out of bounds".into())
        })?;
        verify_signing_cert_v2(sinfo, ess_da, cert)
    }

    /// Return a copy with an extra unsigned attribute on signer `index`.
    pub fn with_signer_unsigned_attr(
        self,
        index: usize,
        attr: x509_cert::attr::Attribute,
    ) -> Result<Self> {
        use x509_cert::attr::Attributes;

        let mut inner = self.inner;
        let mut signer_infos: Vec<crate::pki::cms::types::SignerInfo> =
            inner.signer_infos.iter().cloned().collect();
        let sinfo = signer_infos.get_mut(index).ok_or_else(|| {
            Error::InvalidParam("signer info index out of bounds".into())
        })?;
        let mut attrs: Vec<x509_cert::attr::Attribute> = sinfo
            .unsigned_attrs
            .as_ref()
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default();
        attrs.push(attr);
        sinfo.unsigned_attrs = Some(Attributes::try_from(attrs).map_err(|e| {
            Error::Internal(format!("unsigned attributes set: {e}"))
        })?);
        inner.signer_infos = crate::pki::cms::types::SignerInfos(
            SetOfVec::try_from(signer_infos).map_err(|e| {
                Error::Internal(format!("signer infos set: {e}"))
            })?,
        );
        Ok(Self { inner })
    }
}

/// Build SignedData from components (used by builder/tests).
pub fn signed_data_from_parts(
    version: u32,
    digest_algorithms: Vec<AlgorithmIdentifier<Any>>,
    encap_content_info: crate::pki::cms::types::EncapsulatedContentInfo,
    certificates: Option<Vec<Cert>>,
    crls: Option<Vec<CertificateList>>,
    signer_infos: Vec<crate::pki::cms::types::SignerInfo>,
) -> Result<SignedDataContainer> {
    let mut unique_digests = Vec::new();
    for aid in digest_algorithms {
        if !unique_digests.iter().any(|existing| existing == &aid) {
            unique_digests.push(aid);
        }
    }
    let digest_algorithms = SetOfVec::try_from(unique_digests).map_err(|e| {
        Error::Internal(format!("digest algorithms set: {e}"))
    })?;
    let signer_infos = SetOfVec::try_from(signer_infos).map_err(|e| {
        Error::Internal(format!("signer infos set: {e}"))
    })?;

    let certificates = certificates.map(|certs| {
        let choices: Vec<crate::pki::cms::types::CertificateChoices> = certs
            .into_iter()
            .filter_map(|c| {
                x509_cert::Certificate::from_der(&c.encode().ok()?).ok().map(
                    crate::pki::cms::types::CertificateChoices::Certificate,
                )
            })
            .collect();
        SetOfVec::try_from(choices).map(crate::pki::cms::types::CertificateSet)
    });

    let certificates = match certificates {
        Some(Ok(set)) => Some(set),
        Some(Err(e)) => {
            return Err(Error::Internal(format!("certificate set: {e}")));
        }
        None => None,
    };

    let crls = crls.map(|items| {
        let choices: Vec<RevocationInfoChoice> = items
            .into_iter()
            .map(RevocationInfoChoice::Crl)
            .collect();
        SetOfVec::try_from(choices).map(RevocationInfoChoices)
    });
    let crls = match crls {
        Some(Ok(set)) => Some(set),
        Some(Err(e)) => return Err(Error::Internal(format!("CRL set: {e}"))),
        None => None,
    };

    Ok(SignedDataContainer {
        inner: SignedData {
            version,
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos: crate::pki::cms::types::SignerInfos(signer_infos),
        },
    })
}
