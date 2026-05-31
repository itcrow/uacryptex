//! PFX content extraction (`pfx_get_contents`, ContentInfo helpers).

use der::asn1::{Any, BmpString, ObjectIdentifier, OctetString, Uint};
use der::{Encode, Sequence};
use x509_cert::attr::{Attribute, Attributes};

use crate::pki::cms::ContentInfo;
use crate::pki::oid::{oid_matches_str, oid_to_str, OidId};
use crate::storage::pkcs5::{pkcs5_decrypt_dstu, EncryptedPrivateKeyInfo};
use crate::storage::pkcs12::types::{
    decode_authenticated_safe, decode_safe_contents, EncryptedContentInfo, EncryptedData, Pfx,
    SafeBag, SafeContents,
};
use crate::{Error, Result};

const FRIENDLY_NAME_OID: &str = "1.2.840.113549.1.9.20";
const KEY_BAG_OID: &str = "1.2.840.113549.1.12.10.1.1";
const PKCS8_SHROUDED_KEY_BAG_OID: &str = "1.2.840.113549.1.12.10.1.2";
const CERT_BAG_OID: &str = "1.2.840.113549.1.12.10.1.3";
const X509_CERTIFICATE_OID: &str = "1.2.840.113549.1.9.22.1";

/// PKCS#12 `CertBag`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct CertBag {
    pub cert_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub cert_value: Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CinfoType {
    Data,
    Signed,
    Digested,
    Encrypted,
    Enveloped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeBagType {
    KeyBag,
    Pkcs8ShroudedKeyBag,
    CertBag,
    Other,
}

pub fn cinfo_type(cinfo: &ContentInfo) -> CinfoType {
    let oid = cinfo.content_type.to_string();
    if oid_matches_str(OidId::Data, &oid) {
        CinfoType::Data
    } else if oid_matches_str(OidId::SignedData, &oid) {
        CinfoType::Signed
    } else if oid_matches_str(OidId::DigOid, &oid) {
        CinfoType::Digested
    } else if oid_matches_str(OidId::EncOid, &oid) {
        CinfoType::Encrypted
    } else if oid_matches_str(OidId::EnvelopedData, &oid) {
        CinfoType::Enveloped
    } else {
        CinfoType::Unknown
    }
}

pub fn cinfo_get_data(cinfo: &ContentInfo) -> Result<Vec<u8>> {
    if cinfo_type(cinfo) != CinfoType::Data {
        return Err(Error::Unsupported("ContentInfo is not data".into()));
    }
    let content = cinfo
        .content
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("ContentInfo content missing".into()))?;
    let octets = content
        .decode_as::<OctetString>()
        .map_err(|e| Error::Internal(format!("ContentInfo data decode: {e}")))?;
    Ok(octets.as_bytes().to_vec())
}

pub fn cinfo_get_encrypted_data(cinfo: &ContentInfo) -> Result<EncryptedData> {
    if cinfo_type(cinfo) != CinfoType::Encrypted {
        return Err(Error::Unsupported("ContentInfo is not encryptedData".into()));
    }
    let content = cinfo
        .content
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("ContentInfo content missing".into()))?;
    content
        .decode_as::<EncryptedData>()
        .map_err(|e| Error::Internal(format!("EncryptedData decode: {e}")))
}

pub fn safebag_type(bag: &SafeBag) -> SafeBagType {
    let oid = bag.bag_id.to_string();
    if oid == KEY_BAG_OID {
        SafeBagType::KeyBag
    } else if oid == PKCS8_SHROUDED_KEY_BAG_OID {
        SafeBagType::Pkcs8ShroudedKeyBag
    } else if oid == CERT_BAG_OID {
        SafeBagType::CertBag
    } else {
        SafeBagType::Other
    }
}

pub fn safebag_alias(bag: &SafeBag, index: usize) -> Result<String> {
    if let Some(attrs) = &bag.bag_attributes {
        if let Some(attr) = find_attribute(attrs, FRIENDLY_NAME_OID) {
            if let Some(any) = attr.values.iter().next() {
                let bmp = any
                    .decode_as::<BmpString>()
                    .map_err(|e| Error::Internal(format!("friendlyName decode: {e}")))?;
                return Ok(bmp.to_string());
            }
        }
    }
    Ok(format!("key{}", index + 1))
}

fn find_attribute<'a>(attrs: &'a Attributes, oid: &str) -> Option<&'a Attribute> {
    attrs
        .iter()
        .find(|attr| attr.oid.to_string() == oid)
}

fn encrypted_content_to_epki(info: &EncryptedContentInfo) -> Result<EncryptedPrivateKeyInfo> {
    let encrypted = info
        .encrypted_content
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("encryptedContent missing".into()))?;
    Ok(EncryptedPrivateKeyInfo {
        encryption_algorithm: info.content_encryption_algorithm.clone(),
        encrypted_data: encrypted.clone(),
    })
}

/// One AuthenticatedSafe element (plain or encrypted wrapper).
#[derive(Debug, Clone)]
pub struct ContentsEntry {
    pub bags: SafeContents,
    /// When true, encode as encryptedData ContentInfo.
    pub needs_encrypted_envelope: bool,
    /// PBES2 template from decode for byte-stable re-encode.
    pub encrypted_template: Option<EncryptedPrivateKeyInfo>,
}

/// `pfx_get_contents`.
pub fn pfx_get_contents(pfx: &Pfx, password: &str) -> Result<Vec<ContentsEntry>> {
    let auth_data = cinfo_get_data(&pfx.auth_safe)?;
    let auth_safe = decode_authenticated_safe(&auth_data)?;
    let mut out = Vec::new();
    for cinfo in auth_safe {
        match cinfo_type(&cinfo) {
            CinfoType::Data => {
                let data = cinfo_get_data(&cinfo)?;
                let bags = decode_safe_contents(&data)?;
                out.push(ContentsEntry {
                    bags,
                    needs_encrypted_envelope: false,
                    encrypted_template: None,
                });
            }
            CinfoType::Encrypted => {
                let enc = cinfo_get_encrypted_data(&cinfo)?;
                let epki = encrypted_content_to_epki(&enc.encrypted_content_info)?;
                let plain = pkcs5_decrypt_dstu(&epki, password)?;
                let bags = decode_safe_contents(&plain)?;
                out.push(ContentsEntry {
                    bags,
                    needs_encrypted_envelope: true,
                    encrypted_template: Some(epki),
                });
            }
            CinfoType::Signed => {
                return Err(Error::Unsupported(
                    "AuthenticatedSafe signedData not supported".into(),
                ));
            }
            _ => {
                return Err(Error::Unsupported(
                    "unsupported AuthenticatedSafe ContentInfo type".into(),
                ));
            }
        }
    }
    Ok(out)
}

pub fn auth_safe_octets(pfx: &Pfx) -> Result<Vec<u8>> {
    cinfo_get_data(&pfx.auth_safe)
}

/// Extract X.509 certificate DER from a cert SafeBag value.
pub fn cert_bag_x509_der(bag_value: &Any) -> Result<Vec<u8>> {
    let bag: CertBag = bag_value
        .decode_as()
        .map_err(|e| Error::Internal(format!("CertBag decode: {e}")))?;
    if bag.cert_id.to_string() != X509_CERTIFICATE_OID {
        return Err(Error::Unsupported("unsupported CertBag certId".into()));
    }
    let octets = bag
        .cert_value
        .decode_as::<OctetString>()
        .map_err(|e| Error::Internal(format!("CertBag certValue decode: {e}")))?;
    Ok(octets.as_bytes().to_vec())
}

pub fn encode_content_info_data(data: &[u8]) -> Result<ContentInfo> {
    let octets = OctetString::new(data).map_err(|e| Error::Internal(format!("octets: {e}")))?;
    Ok(ContentInfo {
        content_type: ObjectIdentifier::new(
            &oid_to_str(OidId::Data).ok_or_else(|| Error::Internal("data OID".into()))?,
        )
        .map_err(|e| Error::Internal(format!("data OID: {e}")))?,
        content: Some(
            Any::encode_from(&octets)
                .map_err(|e| Error::Internal(format!("content any: {e}")))?,
        ),
    })
}

pub fn encode_content_info_encrypted(epki: &EncryptedPrivateKeyInfo) -> Result<ContentInfo> {
    use crate::storage::pkcs12::types::{EncryptedContentInfo, EncryptedData};
    let enc = EncryptedData {
        version: Uint::new(&[0u8]).map_err(|e| Error::Internal(format!("version: {e}")))?,
        encrypted_content_info: EncryptedContentInfo {
            content_type: ObjectIdentifier::new(
                &oid_to_str(OidId::Data).ok_or_else(|| Error::Internal("data OID".into()))?,
            )
            .map_err(|e| Error::Internal(format!("data OID: {e}")))?,
            content_encryption_algorithm: epki.encryption_algorithm.clone(),
            encrypted_content: Some(epki.encrypted_data.clone()),
        },
    };
    Ok(ContentInfo {
        content_type: ObjectIdentifier::new(
            &oid_to_str(OidId::EncOid).ok_or_else(|| Error::Internal("enc OID".into()))?,
        )
        .map_err(|e| Error::Internal(format!("enc OID: {e}")))?,
        content: Some(
            Any::encode_from(&enc).map_err(|e| Error::Internal(format!("enc any: {e}")))?,
        ),
    })
}

pub fn encode_authenticated_safe(cinfos: &[ContentInfo]) -> Result<Vec<u8>> {
    cinfos
        .to_vec()
        .to_der()
        .map_err(|e| Error::Internal(format!("AuthenticatedSafe encode: {e}")))
}
