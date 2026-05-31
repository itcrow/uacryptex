//! PKCS#12 / PFX ASN.1 types.

use der::asn1::{Any, ObjectIdentifier, OctetString, Uint};
use der::{Decode, Sequence};
use x509_cert::attr::Attributes;
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cms::ContentInfo;
use crate::{Error, Result};

/// `PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData MacData OPTIONAL }`
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct Pfx {
    pub version: Uint,
    pub auth_safe: ContentInfo,
    #[asn1(optional = "true")]
    pub mac_data: Option<MacData>,
}

/// `MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }`
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct MacData {
    pub mac: DigestInfo,
    pub mac_salt: OctetString,
    #[asn1(optional = "true")]
    pub iterations: Option<Uint>,
}

/// PKCS#7 `DigestInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct DigestInfo {
    pub digest_algorithm: AlgorithmIdentifier<Any>,
    pub digest: OctetString,
}

/// `AuthenticatedSafe ::= SEQUENCE OF ContentInfo`
pub fn decode_authenticated_safe(der: &[u8]) -> Result<Vec<ContentInfo>> {
    Vec::<ContentInfo>::from_der(der).map_err(|e| Error::Internal(format!("AuthenticatedSafe decode: {e}")))
}

/// `SafeContents ::= SEQUENCE OF SafeBag`
pub fn decode_safe_contents(der: &[u8]) -> Result<Vec<SafeBag>> {
    Vec::<SafeBag>::from_der(der).map_err(|e| Error::Internal(format!("SafeContents decode: {e}")))
}

/// Backward-compatible wrappers.
pub type AuthenticatedSafe = Vec<ContentInfo>;
pub type SafeContents = Vec<SafeBag>;

/// `SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY, bagAttributes SET OF Attribute OPTIONAL }`
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct SafeBag {
    pub bag_id: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub bag_value: Any,
    #[asn1(optional = "true")]
    pub bag_attributes: Option<Attributes>,
}

/// `EncryptedData ::= SEQUENCE { version CMSVersion, encryptedContentInfo EncryptedContentInfo, ... }`
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct EncryptedData {
    pub version: Uint,
    pub encrypted_content_info: EncryptedContentInfo,
}

/// `EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm, encryptedContent [0] }`
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct EncryptedContentInfo {
    pub content_type: ObjectIdentifier,
    pub content_encryption_algorithm: AlgorithmIdentifier<Any>,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    pub encrypted_content: Option<OctetString>,
}

pub fn decode_pfx(der: &[u8]) -> Result<Pfx> {
    Pfx::from_der(der).map_err(|e| Error::Internal(format!("PFX decode: {e}")))
}
