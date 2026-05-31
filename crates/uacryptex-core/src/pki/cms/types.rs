//! CMS ASN.1 types (RFC 5652).

use core::cmp::Ordering;

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Choice, DerOrd, Encode, Sequence, ValueOrd};
use x509_cert::attr::Attributes;
use x509_cert::certificate::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::impl_newtype;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifier;

use crate::{Error, Result};

/// CMS `version` INTEGER.
pub type CmsVersion = u32;

/// `DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier`
pub type DigestAlgorithmIdentifiers = SetOfVec<AlgorithmIdentifier<Any>>;

/// `SignerInfos ::= SET OF SignerInfo`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInfos(pub SetOfVec<SignerInfo>);

impl SignerInfos {
    pub fn iter(&self) -> impl Iterator<Item = &SignerInfo> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&SignerInfo> {
        self.0.get(index)
    }
}

impl_newtype!(SignerInfos, SetOfVec<SignerInfo>);

/// `CertificateSet ::= SET OF CertificateChoices`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSet(pub SetOfVec<CertificateChoices>);

impl CertificateSet {
    pub fn iter(&self) -> impl Iterator<Item = &CertificateChoices> {
        self.0.iter()
    }
}

impl_newtype!(CertificateSet, SetOfVec<CertificateChoices>);

/// `CertificateChoices ::= CHOICE { certificate Certificate, ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum CertificateChoices {
    Certificate(Certificate),
}

impl ValueOrd for CertificateChoices {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// `RevocationInfoChoice ::= CHOICE { crl CertificateList, ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum RevocationInfoChoice {
    Crl(CertificateList),
}

impl ValueOrd for RevocationInfoChoice {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// `RevocationInfoChoices ::= SET OF RevocationInfoChoice`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationInfoChoices(pub SetOfVec<RevocationInfoChoice>);

impl RevocationInfoChoices {
    pub fn iter(&self) -> impl Iterator<Item = &RevocationInfoChoice> {
        self.0.iter()
    }
}

impl_newtype!(RevocationInfoChoices, SetOfVec<RevocationInfoChoice>);

/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber CertificateSerialNumber }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: SerialNumber,
}

/// `SignerIdentifier ::= CHOICE { issuerAndSerialNumber ..., subjectKeyIdentifier [0] ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl ValueOrd for SignerIdentifier {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// `EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct EncapsulatedContentInfo {
    pub econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub econtent: Option<OctetString>,
}

/// `SignedData ::= SEQUENCE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<CertificateSet>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<RevocationInfoChoices>,
    pub signer_infos: SignerInfos,
}

/// `SignerInfo ::= SEQUENCE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SignerInfo {
    pub version: CmsVersion,
    pub sid: SignerIdentifier,
    pub digest_alg: AlgorithmIdentifier<Any>,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub signed_attrs: Option<Attributes>,
    pub signature_algorithm: AlgorithmIdentifier<Any>,
    pub signature: OctetString,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unsigned_attrs: Option<Attributes>,
}

/// `ContentInfo ::= SEQUENCE { contentType ContentType, content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct ContentInfo {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub content: Option<Any>,
}

impl EncapsulatedContentInfo {
    /// Extract encapsulated octets when present.
    pub fn content_bytes(&self) -> Result<Vec<u8>> {
        self.econtent
            .as_ref()
            .map(|os| os.as_bytes().to_vec())
            .ok_or_else(|| Error::Unsupported("SignedData has no encapsulated content".into()))
    }
}

impl SignedData {
    pub fn signer_info(&self, index: usize) -> Option<&SignerInfo> {
        self.signer_infos.get(index)
    }
}
