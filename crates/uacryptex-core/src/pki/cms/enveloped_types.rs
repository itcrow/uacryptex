//! CMS EnvelopedData ASN.1 (RFC 5652 / Cryptonite `EnvelopedData.h`).

use core::cmp::Ordering;

use der::asn1::{BitString, OctetString, SetOfVec};
use der::{Any, Choice, DerOrd, Encode, Sequence, ValueOrd};
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::impl_newtype;
use x509_cert::spki::AlgorithmIdentifier;

use super::types::{CertificateSet, CmsVersion, IssuerAndSerialNumber, RevocationInfoChoices};

/// `RecipientInfos ::= SET OF RecipientInfo`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientInfos(pub SetOfVec<RecipientInfo>);

impl_newtype!(RecipientInfos, SetOfVec<RecipientInfo>);

/// `RecipientInfo ::= CHOICE { ktri, kari, ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum RecipientInfo {
    Ktri(KeyTransRecipientInfo),
    #[asn1(context_specific = "1", constructed = "true")]
    Kari(KeyAgreeRecipientInfo),
}

impl ValueOrd for RecipientInfo {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// `KeyTransRecipientInfo ::= SEQUENCE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct KeyTransRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub key_encryption_algorithm: AlgorithmIdentifier<Any>,
    pub encrypted_key: OctetString,
}

/// `RecipientIdentifier ::= CHOICE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
pub enum RecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

/// `KeyAgreeRecipientInfo ::= SEQUENCE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct KeyAgreeRecipientInfo {
    pub version: CmsVersion,
    pub originator: OriginatorIdentifierOrKey,
    #[asn1(optional = "true")]
    pub ukm: Option<OctetString>,
    pub key_encryption_algorithm: AlgorithmIdentifier<Any>,
    pub recipient_encrypted_keys: RecipientEncryptedKeys,
}

/// `OriginatorIdentifierOrKey ::= CHOICE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
pub enum OriginatorIdentifierOrKey {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    #[asn1(context_specific = "1", constructed = "true")]
    OriginatorKey(OriginatorPublicKey),
}

/// `OriginatorPublicKey ::= SEQUENCE { algorithm, publicKey }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct OriginatorPublicKey {
    pub algorithm: AlgorithmIdentifier<Any>,
    pub public_key: BitString,
}

/// `RecipientEncryptedKeys ::= SET OF RecipientEncryptedKey`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEncryptedKeys(pub SetOfVec<RecipientEncryptedKey>);

impl_newtype!(RecipientEncryptedKeys, SetOfVec<RecipientEncryptedKey>);

/// `RecipientEncryptedKey ::= SEQUENCE { rid, encryptedKey }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct RecipientEncryptedKey {
    pub rid: KeyAgreeRecipientIdentifier,
    pub encrypted_key: OctetString,
}

/// `KeyAgreeRecipientIdentifier ::= CHOICE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Choice, ValueOrd)]
pub enum KeyAgreeRecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", constructed = "true")]
    RKeyId(RecipientKeyIdentifier),
}

/// `RecipientKeyIdentifier ::= SEQUENCE { subjectKeyIdentifier, ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct RecipientKeyIdentifier {
    pub subject_key_identifier: SubjectKeyIdentifier,
    #[asn1(optional = "true")]
    pub date: Option<der::asn1::GeneralizedTime>,
}

/// `EncryptedContentInfo ::= SEQUENCE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct EncryptedContentInfo {
    pub content_type: der::asn1::ObjectIdentifier,
    pub content_encryption_algorithm: AlgorithmIdentifier<Any>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub encrypted_content: Option<OctetString>,
}

/// `OriginatorInfo ::= SEQUENCE { certs, crls }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct OriginatorInfo {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certs: Option<CertificateSet>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<RevocationInfoChoices>,
}

/// `EnvelopedData ::= SEQUENCE { ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct EnvelopedData {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<OriginatorInfo>,
    pub recipient_infos: RecipientInfos,
    pub encrypted_content_info: EncryptedContentInfo,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unprotected_attrs: Option<Attributes>,
}
