//! SignedData builder engine (`signed_data_engine.c`).

use x509_cert::crl::CertificateList;

use crate::pki::cert::Cert;
use crate::pki::cms::engine::signer_info::SignerInfoEngine;
use crate::pki::cms::signed_data::{signed_data_from_parts, SignedDataContainer};
use crate::pki::cms::types::EncapsulatedContentInfo;
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// CMS SignedData generator (`SignedDataEngine`).
pub struct SignedDataEngine<'a> {
    signers: Vec<SignerInfoEngine<'a>>,
    certs: Vec<Cert>,
    crls: Vec<CertificateList>,
    encap_content_info: Option<EncapsulatedContentInfo>,
    encap_data: Option<Vec<u8>>,
    encap_hash_data: Option<Vec<u8>>,
}

impl<'a> SignedDataEngine<'a> {
    /// `esigned_data_alloc`.
    pub fn new(signer: SignerInfoEngine<'a>) -> Self {
        Self {
            signers: vec![signer],
            certs: Vec::new(),
            crls: Vec::new(),
            encap_content_info: None,
            encap_data: None,
            encap_hash_data: None,
        }
    }

    /// `esigned_data_set_data`.
    pub fn set_data(
        &mut self,
        content_type: OidId,
        data: &[u8],
        internal: bool,
    ) -> Result<()> {
        let econtent_type = object_identifier(content_type)?;
        let econtent = if internal {
            Some(der::asn1::OctetString::new(data).map_err(|e| {
                Error::Internal(format!("content octet string: {e}"))
            })?)
        } else {
            None
        };
        self.encap_content_info = Some(EncapsulatedContentInfo {
            econtent_type,
            econtent,
        });
        self.encap_data = Some(data.to_vec());
        self.encap_hash_data = None;
        Ok(())
    }

    /// `esigned_data_set_hash_data`.
    pub fn set_hash_data(&mut self, content_type: OidId, hash: &[u8]) -> Result<()> {
        let econtent_type = object_identifier(content_type)?;
        self.encap_content_info = Some(EncapsulatedContentInfo {
            econtent_type,
            econtent: None,
        });
        self.encap_data = None;
        self.encap_hash_data = Some(hash.to_vec());
        Ok(())
    }

    /// `esigned_data_set_content_info`.
    pub fn set_content_info(&mut self, info: &EncapsulatedContentInfo) -> Result<()> {
        self.encap_content_info = Some(info.clone());
        self.encap_data = info
            .econtent
            .as_ref()
            .map(|os| os.as_bytes().to_vec());
        self.encap_hash_data = None;
        Ok(())
    }

    /// `esigned_data_add_cert`.
    pub fn add_cert(&mut self, cert: Cert) -> Result<()> {
        self.certs.push(cert);
        Ok(())
    }

    /// `esigned_data_add_crl`.
    pub fn add_crl(&mut self, crl: CertificateList) -> Result<()> {
        self.crls.push(crl);
        Ok(())
    }

    /// `esigned_data_add_signer`.
    pub fn add_signer(&mut self, signer: SignerInfoEngine<'a>) {
        self.signers.push(signer);
    }

    /// `esigned_data_generate`.
    pub fn generate(&mut self) -> Result<SignedDataContainer> {
        let encap = self.encap_content_info.clone().ok_or_else(|| {
            Error::InvalidParam("signed data engine: encapsulated content not set".into())
        })?;

        let (data, hash) = if let Some(d) = &self.encap_data {
            (Some(d.clone()), None)
        } else if let Some(h) = &self.encap_hash_data {
            (None, Some(h.clone()))
        } else if let Some(content) = &encap.econtent {
            (Some(content.as_bytes().to_vec()), None)
        } else {
            return Err(Error::InvalidParam(
                "signed data engine: no content for signers".into(),
            ));
        };

        let mut digest_algorithms = Vec::new();
        let mut signer_infos = Vec::new();

        for signer in &mut self.signers {
            signer.set_content(&encap.econtent_type, data.clone(), hash.clone());
            let sinfo = signer.generate()?;
            digest_algorithms.push(sinfo.digest_alg.clone());
            signer_infos.push(sinfo);
        }

        let version = signed_data_version(&encap.econtent_type);
        let crls = if self.crls.is_empty() {
            None
        } else {
            Some(self.crls.clone())
        };
        let certificates = if self.certs.is_empty() {
            None
        } else {
            Some(self.certs.clone())
        };

        signed_data_from_parts(
            version,
            digest_algorithms,
            encap,
            certificates,
            crls,
            signer_infos,
        )
    }
}

fn signed_data_version(content_type: &der::asn1::ObjectIdentifier) -> u32 {
    if object_identifier(OidId::Data)
        .map(|data| &data == content_type)
        .unwrap_or(false)
    {
        1
    } else {
        3
    }
}
