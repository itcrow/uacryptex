//! SignerInfo builder engine (`signer_info_engine.c`).

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cert::Cert;
use crate::pki::cms::signer_info::{
    content_type_attribute, message_digest_attribute, signing_certificate_v2_attribute,
};
use crate::pki::cms::types::{IssuerAndSerialNumber, SignerIdentifier, SignerInfo};
use crate::pki::crypto::{DigestAdapter, SignAdapter};
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::{Error, Result};

const SIGNER_INFO_VERSION: u32 = 1;

/// CMS SignerInfo generator (`SignerInfoEngine`).
pub struct SignerInfoEngine<'a> {
    sa: &'a SignAdapter,
    data_da: DigestAdapter,
    ess_da: DigestAdapter,
    signer_cert: Cert,
    sid: SignerIdentifier,
    add_bes_attrs: bool,
    signed_attrs: Option<Attributes>,
    unsigned_attrs: Option<Attributes>,
    data_type_oid: Option<ObjectIdentifier>,
    data: Option<Vec<u8>>,
    hash_data: Option<Vec<u8>>,
}

impl<'a> SignerInfoEngine<'a> {
    /// `esigner_info_alloc`.
    pub fn new(
        sa: &'a SignAdapter,
        data_da: DigestAdapter,
        ess_da: Option<DigestAdapter>,
    ) -> Result<Self> {
        let signer_cert = sa.cert()?.clone();
        let issuer = signer_cert.inner_certificate().tbs_certificate.issuer.clone();
        let serial_number = signer_cert
            .inner_certificate()
            .tbs_certificate
            .serial_number
            .clone();
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer,
            serial_number,
        });

        Ok(Self {
            sa,
            ess_da: ess_da.unwrap_or_else(|| data_da.clone_state().expect("digest adapter clone")),
            data_da,
            signer_cert,
            sid,
            add_bes_attrs: true,
            signed_attrs: None,
            unsigned_attrs: None,
            data_type_oid: None,
            data: None,
            hash_data: None,
        })
    }

    /// `esigner_info_set_bes_attrs`.
    pub fn set_bes_attrs(&mut self, flag: bool) {
        self.add_bes_attrs = flag;
    }

    /// `esigner_info_set_signed_attrs` — DER round-trip for SET sorting.
    pub fn set_signed_attrs(&mut self, signed_attrs: &Attributes) -> Result<()> {
        self.signed_attrs = Some(normalize_attributes(signed_attrs)?);
        Ok(())
    }

    /// `esigner_info_add_signed_attr`.
    pub fn add_signed_attr(&mut self, signed_attr: &Attribute) -> Result<()> {
        let mut attrs: Vec<Attribute> = self
            .signed_attrs
            .as_ref()
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default();
        attrs.push(signed_attr.clone());
        self.signed_attrs = Some(attributes_from_vec(attrs)?);
        Ok(())
    }

    /// `esigner_info_set_unsigned_attrs`.
    pub fn set_unsigned_attrs(&mut self, unsigned_attrs: &Attributes) -> Result<()> {
        self.unsigned_attrs = Some(unsigned_attrs.clone());
        Ok(())
    }

    /// `esigner_info_add_unsigned_attr`.
    pub fn add_unsigned_attr(&mut self, unsigned_attr: &Attribute) -> Result<()> {
        let mut attrs: Vec<Attribute> = self
            .unsigned_attrs
            .as_ref()
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default();
        attrs.push(unsigned_attr.clone());
        self.unsigned_attrs = Some(attributes_from_vec(attrs)?);
        Ok(())
    }

    /// `esigner_info_set_data`.
    pub fn set_data(&mut self, data_type: OidId, data: &[u8]) -> Result<()> {
        self.data_type_oid = Some(object_identifier(data_type)?);
        self.data = Some(data.to_vec());
        self.hash_data = None;
        Ok(())
    }

    /// `esigner_info_set_hash_data`.
    pub fn set_hash_data(&mut self, data_type: OidId, hash: &[u8]) -> Result<()> {
        self.data_type_oid = Some(object_identifier(data_type)?);
        self.hash_data = Some(hash.to_vec());
        self.data = None;
        Ok(())
    }

    /// Configure content from SignedData engine before `generate`.
    pub(crate) fn set_content(
        &mut self,
        content_type: &ObjectIdentifier,
        data: Option<Vec<u8>>,
        hash: Option<Vec<u8>>,
    ) {
        self.data_type_oid = Some(*content_type);
        self.data = data;
        self.hash_data = hash;
    }

    /// `esigner_info_generate`.
    pub fn generate(&self) -> Result<SignerInfo> {
        let signed_attrs = self.build_signed_attrs()?;
        let signed_attrs_der = signed_attrs
            .to_der()
            .map_err(|e| Error::Internal(format!("signed attributes encode: {e}")))?;

        let signature = self.sa.sign_data(&signed_attrs_der)?;
        let signature_os = OctetString::new(signature).map_err(|e| {
            Error::Internal(format!("signature octet string: {e}"))
        })?;

        let digest_alg = AlgorithmIdentifier::<Any>::from_der(self.data_da.algorithm_der())
            .map_err(|e| Error::Internal(format!("digest aid decode: {e}")))?;
        let signature_algorithm =
            AlgorithmIdentifier::<Any>::from_der(self.sa.signature_algorithm_der()).map_err(|e| {
                Error::Internal(format!("signature aid decode: {e}"))
            })?;

        Ok(SignerInfo {
            version: SIGNER_INFO_VERSION,
            sid: self.sid.clone(),
            digest_alg,
            signed_attrs: Some(signed_attrs),
            signature_algorithm,
            signature: signature_os,
            unsigned_attrs: self.unsigned_attrs.clone(),
        })
    }

    fn build_signed_attrs(&self) -> Result<Attributes> {
        if self.add_bes_attrs {
            let content_digest = self.content_digest()?;
            let data_type = self.data_type_oid.as_ref().ok_or_else(|| {
                Error::InvalidParam("signer info engine: content type not set".into())
            })?;

            let mut attrs = vec![
                content_type_attribute(data_type_from_oid(data_type)?)?,
                message_digest_attribute(&content_digest)?,
                signing_certificate_v2_attribute(&self.signer_cert, &self.ess_da)?,
            ];

            if let Some(extra) = &self.signed_attrs {
                for attr in extra.iter() {
                    attrs.push(attr.clone());
                }
            }

            attrs.sort_by(|a, b| {
                a.to_der()
                    .unwrap_or_default()
                    .cmp(&b.to_der().unwrap_or_default())
            });
            normalize_attributes(&attributes_from_vec(attrs)?)
        } else {
            let attrs = self.signed_attrs.as_ref().ok_or_else(|| {
                Error::InvalidParam("signer info engine: signed attributes not set".into())
            })?;
            normalize_attributes(attrs)
        }
    }

    fn content_digest(&self) -> Result<Vec<u8>> {
        if let Some(hash) = &self.hash_data {
            return Ok(hash.clone());
        }
        if let Some(data) = &self.data {
            let mut hasher = self.data_da.clone_state()?;
            hasher.update(data)?;
            return hasher.finalize();
        }
        Err(Error::InvalidParam(
            "signer info engine: neither data nor hash set".into(),
        ))
    }
}

fn attributes_from_vec(attrs: Vec<Attribute>) -> Result<Attributes> {
    SetOfVec::try_from(attrs).map_err(|e| Error::Internal(format!("attributes set: {e}")))
}

fn normalize_attributes(attrs: &Attributes) -> Result<Attributes> {
    let der = attrs
        .to_der()
        .map_err(|e| Error::Internal(format!("attributes encode: {e}")))?;
    Attributes::from_der(&der).map_err(|e| Error::Internal(format!("attributes decode: {e}")))
}

fn data_type_from_oid(oid: &ObjectIdentifier) -> Result<OidId> {
    let data = object_identifier(OidId::Data)?;
    if oid == &data {
        return Ok(OidId::Data);
    }
    let tst_info = object_identifier(OidId::CtTstInfo)?;
    if oid == &tst_info {
        return Ok(OidId::CtTstInfo);
    }
    Err(Error::Unsupported(format!(
        "unsupported CMS content type OID: {oid}"
    )))
}
