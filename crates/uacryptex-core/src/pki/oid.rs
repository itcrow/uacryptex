//! PKIX object identifiers (`cryptonite/src/pkix/c/api/oids.c`).

#![allow(clippy::too_many_lines)]

/// Cryptonite `OidId` (`oids.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum OidId {
    /// `1.2.804.2.1.1.1`
    Pki = 0,
    /// `1.2.804.2.1.1.1.1`
    PkiAlg = 1,
    /// `1.2.804.2.1.1.1.1.2`
    PkiHash = 2,
    /// `1.2.804.2.1.1.1.1.2.1`
    PkiGost3411 = 3,
    /// `1.2.804.2.1.1.1.1.1.2`
    PkiHmacGost3411 = 4,
    /// `1.2.804.2.1.1.1.1.3`
    PkiAsym = 5,
    /// `1.2.804.2.1.1.1.1.3.1`
    PkiDstu4145WithGost3411 = 6,
    /// `1.2.804.2.1.1.1.1.3.1.1`
    PkiDstu4145PbLe = 7,
    /// `1.2.804.2.1.1.1.1.3.1.1.1`
    PkiSpecialCurvesPb = 8,
    /// `1.2.804.2.1.1.1.1.3.1.1.1.1`
    PkiDstu4145PbBe = 9,
    /// `1.2.804.2.1.1.1.1.3.1.1.2`
    PkiNamedCurvesPb = 10,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.0`
    PkiM163Pb = 11,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.1`
    PkiM167Pb = 12,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.2`
    PkiM173Pb = 13,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.3`
    PkiM179Pb = 14,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.4`
    PkiM191Pb = 15,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.5`
    PkiM233Pb = 16,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.6`
    PkiM257Pb = 17,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.7`
    PkiM307Pb = 18,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.8`
    PkiM367Pb = 19,
    /// `1.2.804.2.1.1.1.1.3.1.1.2.9`
    PkiM431Pb = 20,
    /// `1.2.804.2.1.1.1.1.3.1.2`
    PkiDstu4145OnbLe = 21,
    /// `1.2.804.2.1.1.1.1.3.1.2.1`
    PkiSpecialCurvesOnb = 22,
    /// `1.2.804.2.1.1.1.1.3.1.2.1.1`
    PkiDstu4145OnbBe = 23,
    /// `1.2.804.2.1.1.1.1.3.1.2.2`
    PkiNamedCurvesOnb = 24,
    /// `1.2.804.2.1.1.1.1.3.1.2.2.0`
    PkiM173Onb = 25,
    /// `1.2.804.2.1.1.1.1.3.1.2.2.1`
    PkiM179Onb = 26,
    /// `1.2.804.2.1.1.1.1.3.1.2.2.2`
    PkiM191Onb = 27,
    /// `1.2.804.2.1.1.1.1.3.1.2.2.3`
    PkiM233Onb = 28,
    /// `1.2.804.2.1.1.1.1.3.1.2.2.4`
    PkiM431Onb = 29,
    /// `1.3.14.3.2.26`
    PkiSha1 = 30,
    /// `2.16.840.1.101.3.4.2.4`
    PkiSha224 = 31,
    /// `2.16.840.1.101.3.4.2.1`
    PkiSha256 = 32,
    /// `2.16.840.1.101.3.4.2.2`
    PkiSha384 = 33,
    /// `2.16.840.1.101.3.4.2.3`
    PkiSha512 = 34,
    /// `1.2.804.2.1.1.1.1.3.2`
    Gost34310WithGost34311 = 35,
    /// `1.2.804.2.1.1.1.1.1.1`
    Gost28147Dstu = 36,
    /// `1.2.643.2.2.21`
    Gost28147Gost = 37,
    /// `1.2.804.2.1.1.1.1.1.1.2`
    Gost28147Ofb = 38,
    /// `1.2.804.2.1.1.1.1.1.1.3`
    Gost28147Cfb = 39,
    /// `1.2.804.2.1.1.1.1.1.1.5`
    Gost28147Wrap = 40,
    /// `1.2.804.2.1.1.1.1.3.4`
    DhSinglePassCofactorDhGost34311kdfScheme = 41,
    /// `1.2.804.2.1.1.1.2`
    PkiCp = 42,
    /// `1.2.804.2.1.1.1.2.1`
    PkiUkrEdsCp = 43,
    /// `1.2.804.2.1.1.1.2.3`
    PkiTspPolicy = 44,
    /// `1.2.804.2.1.1.1.2.3.1`
    PkiTspPolicyDstuPb = 45,
    /// `1.2.804.2.1.1.1.2.3.2`
    PkiTspPolicyGost = 46,
    /// `1.2.804.2.1.1.1.2.3.3`
    PkiTspPolicyDstuOnb = 47,
    /// `1.2.804.2.1.1.1.3`
    PkiEku = 48,
    /// `1.2.804.2.1.1.1.3.9`
    PkiEkuStamp = 49,
    /// `1.2.804.2.1.1.1.11`
    PkiDev = 50,
    /// `2.5.29.21`
    CeCrlReason = 51,
    /// `1.2.840.113549.1.7.1`
    Data = 52,
    /// `1.2.840.113549.1.7.2`
    SignedData = 53,
    /// `1.2.840.113549.1.7.3`
    EnvelopedData = 54,
    /// `1.2.840.113549.1.7.5`
    DigOid = 55,
    /// `1.2.840.113549.1.7.6`
    EncOid = 56,
    /// `1.2.840.113549.1.9.1`
    Email = 57,
    /// `1.2.840.113549.1.9.2`
    UnstructuredName = 58,
    /// `1.2.840.113549.1.9.3`
    ContentType = 59,
    /// `1.2.840.113549.1.9.4`
    MessageDigest = 60,
    /// `1.2.840.113549.1.9.5`
    SigningTime = 61,
    /// `1.2.840.113549.1.9.6`
    CounterSignature = 62,
    /// `1.2.840.113549.1.9.7`
    ChallengePassword = 63,
    /// `1.2.840.113549.1.9.8`
    UnstructuredAddress = 64,
    /// `1.2.840.113549.1.9.9`
    ExtendedCertAttr = 65,
    /// `1.2.840.113549.1.9.13`
    SigningDescription = 66,
    /// `1.2.840.113549.1.9.14`
    ExtensionRequest = 67,
    /// `1.2.840.113549.1.9.15`
    Capabilities = 68,
    /// `1.2.840.113549.1.9.16`
    OidRegistry = 69,
    /// `1.2.840.113549.1.9.20`
    Friendlyname = 70,
    /// `1.2.840.113549.1.9.21`
    Localkey = 71,
    /// `1.2.840.113549.1.9.22`
    CertTypes = 72,
    /// `1.2.840.113549.1.9.22`
    CrlTypes = 73,
    /// `1.2.840.113549.1.9.16.2.12`
    AaSigningCertificate = 74,
    /// `1.2.840.113549.1.9.16.2.47`
    AaSigningCertificateV2 = 75,
    /// `1.2.840.113549.1.9.16.2.15`
    AaEtsSigPolicy = 76,
    /// `1.2.840.113549.1.9.16.5.1`
    SpqEtsUri = 77,
    /// `1.2.840.113549.1.9.16.5.2`
    SpqEtsUnitice = 78,
    /// `1.2.840.113549.1.9.16.2.20`
    AaEtsContentTimeStamp = 79,
    /// `1.2.840.113549.1.9.16.2.14`
    AaSignatureTimeStampToken = 80,
    /// `1.2.840.113549.1.9.16.1.4`
    CtTstInfo = 81,
    /// `1.2.840.113549.1.9.16.2.21`
    AaEtsCertificateRefs = 82,
    /// `1.2.840.113549.1.9.16.2.22`
    AaEtsRevocationRefs = 83,
    /// `1.2.840.113549.1.9.16.2.23`
    AaEtsCertValues = 84,
    /// `1.2.840.113549.1.9.16.2.24`
    AaEtsRevocationValues = 85,
    /// `1.2.840.113549.1.9.16.2.27`
    AaEtsArchiveTimeStamp = 161,
    /// `2.5.29.9`
    SubjectDirectoryAttributesExtension = 86,
    /// `2.5.29.14`
    SubjectKeyIdentifierExtension = 87,
    /// `2.5.29.15`
    KeyUsageExtension = 88,
    /// `2.5.29.16`
    PrivateKeyUsagePeriodExtension = 89,
    /// `2.5.29.17`
    SubjectAltNameExtension = 90,
    /// `2.5.29.18`
    IssuerAltNameExtension = 91,
    /// `2.5.29.19`
    BasicConstraintsExtension = 92,
    /// `2.5.29.20`
    CrlNumberExtension = 93,
    /// `2.5.29.21`
    CrlReasonExtension = 94,
    /// `2.5.29.23`
    HoldInstructionCodeExtension = 95,
    /// `2.5.29.24`
    InvalidityDateExtension = 96,
    /// `2.5.29.27`
    DeltaCrlIndicatorExtension = 97,
    /// `2.5.29.29`
    CertificateIssuerExtension = 98,
    /// `2.5.29.31`
    CrlDistributionPointsExtension = 99,
    /// `2.5.29.32`
    CertificatePoliciesExtension = 100,
    /// `2.5.29.35`
    AuthorityKeyIdentifierExtension = 101,
    /// `2.5.29.37`
    ExtKeyUsageExtension = 102,
    /// `2.5.29.46`
    FreshestCrlExtension = 103,
    /// `1.3.6.1.5.5.7.1.1`
    AuthorityInfoAccessExtension = 104,
    /// `1.3.6.1.5.5.7.1.3`
    QcStatementsExtension = 105,
    /// `1.3.6.1.5.5.7.1.11`
    SubjectInfoAccessExtension = 106,
    /// `1.3.6.1.5.5.7.48.1`
    OcspOid = 107,
    /// `1.3.6.1.5.5.7.48.2`
    CaissuersOid = 108,
    /// `1.3.6.1.5.5.7.48.3`
    TspOid = 109,
    /// `1.3.6.1.5.5.7.48.1.1`
    BasicResponse = 110,
    /// `1.3.6.1.5.5.7.48.1.2`
    NonceExtension = 111,
    /// `1.3.6.1.5.5.7.48.1.3`
    CrlIdExtension = 112,
    /// `1.3.6.1.5.5.7.48.1.4`
    AcceptableResponsesExtension = 113,
    /// `1.3.6.1.5.5.7.48.1.6`
    ArchiveCutoffExtension = 114,
    /// `1.3.6.1.5.5.7.48.1.7`
    ServiceLocatorExtension = 115,
    /// `2.5.4.2`
    KnowledgeInformation = 116,
    /// `2.5.4.3`
    CommonName = 117,
    /// `2.5.4.4`
    Surname = 118,
    /// `2.5.4.5`
    SerialNumber = 119,
    /// `2.5.4.6`
    CountryName = 120,
    /// `2.5.4.7`
    LocalityName = 121,
    /// `2.5.4.8`
    StateName = 122,
    /// `2.5.4.9`
    StreetName = 123,
    /// `2.5.4.10`
    OrganizationName = 124,
    /// `2.5.4.11`
    OrganizationUnit = 125,
    /// `2.5.4.12`
    Title = 126,
    /// `2.5.4.13`
    Description = 127,
    /// `2.5.4.15`
    BusinessCategory = 128,
    /// `2.5.4.17`
    PostalCode = 129,
    /// `2.5.4.18`
    PostOfficeBox = 130,
    /// `2.5.4.19`
    DeliveryName = 131,
    /// `2.5.4.42`
    GivenName = 132,
    /// `1.3.6.1.5.5.7.3.9`
    OcspKeyPurpose = 133,
    /// `1.2.840.113549.1.5.13`
    Pbes2 = 134,
    /// `1.2.840.113549.1.12.1.3`
    PbeWithSha1TdesCbc = 135,
    /// `1.2.840.113549.3.7`
    DesEde3Cbc = 136,
    /// `1.2.840.113549.1.5.12`
    Kdf = 137,
    /// `1.2.840.10045.2.1`
    EcPublicKeyType = 138,
    /// `1.2.840.10045.3.1.1`
    EcdsaSecp192R1 = 139,
    /// `1.2.840.10045.3.1.7`
    EcdsaSecp256R1 = 140,
    /// `1.3.132.0.33`
    EcdsaSecp224R1 = 141,
    /// `1.3.132.0.34`
    EcdsaSecp384R1 = 142,
    /// `1.3.132.0.35`
    EcdsaSecp521R1 = 143,
    /// `1.3.132.0.10`
    EcdsaSecp256K1 = 144,
    /// `1.2.840.10045.4.1`
    EcdsaWithSha1 = 150,
    /// `1.2.840.10045.4.3.1`
    EcdsaWithSha224 = 151,
    /// `1.2.840.10045.4.3.2`
    EcdsaWithSha256 = 152,
    /// `1.2.840.10045.4.3.3`
    EcdsaWithSha384 = 153,
    /// `1.2.840.10045.4.3.4`
    EcdsaWithSha512 = 154,
    /// `2.16.840.1.101.3.4.1.42`
    Aes256Cbc = 155,
    /// `1.2.840.113549.2.7`
    PkiHmacSha1 = 156,
    /// `0.4.0.1862.1`
    EtsiQcs = 157,
    /// `0.4.0.1862.1.2`
    EtsiQcsQcLimitValue = 158,
    /// `1.2.398.3.10.1.1.1.1`
    PkiGost3410 = 159,
    /// `1.2.398.3.10.1.1.1.2`
    Gost3410Kz = 160,
}

#[derive(Debug, Clone, Copy)]
struct OidDef {
    id: OidId,
    components: &'static [u32],
}

const OID_REGISTRY: &[OidDef] = &[
    OidDef { id: OidId::Pki, components: &[1, 2, 804, 2, 1, 1, 1] },
    OidDef { id: OidId::PkiAlg, components: &[1, 2, 804, 2, 1, 1, 1, 1] },
    OidDef { id: OidId::PkiHash, components: &[1, 2, 804, 2, 1, 1, 1, 1, 2] },
    OidDef { id: OidId::PkiGost3411, components: &[1, 2, 804, 2, 1, 1, 1, 1, 2, 1] },
    OidDef { id: OidId::PkiHmacGost3411, components: &[1, 2, 804, 2, 1, 1, 1, 1, 1, 2] },
    OidDef { id: OidId::PkiAsym, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3] },
    OidDef { id: OidId::PkiDstu4145WithGost3411, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1] },
    OidDef { id: OidId::PkiDstu4145PbLe, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1] },
    OidDef { id: OidId::PkiSpecialCurvesPb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1] },
    OidDef { id: OidId::PkiDstu4145PbBe, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 1, 1] },
    OidDef { id: OidId::PkiNamedCurvesPb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2] },
    OidDef { id: OidId::PkiM163Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 0] },
    OidDef { id: OidId::PkiM167Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 1] },
    OidDef { id: OidId::PkiM173Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 2] },
    OidDef { id: OidId::PkiM179Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 3] },
    OidDef { id: OidId::PkiM191Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 4] },
    OidDef { id: OidId::PkiM233Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 5] },
    OidDef { id: OidId::PkiM257Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6] },
    OidDef { id: OidId::PkiM307Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 7] },
    OidDef { id: OidId::PkiM367Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 8] },
    OidDef { id: OidId::PkiM431Pb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 9] },
    OidDef { id: OidId::PkiDstu4145OnbLe, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2] },
    OidDef { id: OidId::PkiSpecialCurvesOnb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 1] },
    OidDef { id: OidId::PkiDstu4145OnbBe, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 1, 1] },
    OidDef { id: OidId::PkiNamedCurvesOnb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2] },
    OidDef { id: OidId::PkiM173Onb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 0] },
    OidDef { id: OidId::PkiM179Onb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 1] },
    OidDef { id: OidId::PkiM191Onb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 2] },
    OidDef { id: OidId::PkiM233Onb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 3] },
    OidDef { id: OidId::PkiM431Onb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 4] },
    OidDef { id: OidId::PkiSha1, components: &[1, 3, 14, 3, 2, 26] },
    OidDef { id: OidId::PkiSha224, components: &[2, 16, 840, 1, 101, 3, 4, 2, 4] },
    OidDef { id: OidId::PkiSha256, components: &[2, 16, 840, 1, 101, 3, 4, 2, 1] },
    OidDef { id: OidId::PkiSha384, components: &[2, 16, 840, 1, 101, 3, 4, 2, 2] },
    OidDef { id: OidId::PkiSha512, components: &[2, 16, 840, 1, 101, 3, 4, 2, 3] },
    OidDef { id: OidId::Gost34310WithGost34311, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 2] },
    OidDef { id: OidId::Gost28147Dstu, components: &[1, 2, 804, 2, 1, 1, 1, 1, 1, 1] },
    OidDef { id: OidId::Gost28147Gost, components: &[1, 2, 643, 2, 2, 21] },
    OidDef { id: OidId::Gost28147Ofb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 2] },
    OidDef { id: OidId::Gost28147Cfb, components: &[1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3] },
    OidDef { id: OidId::Gost28147Wrap, components: &[1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 5] },
    OidDef { id: OidId::DhSinglePassCofactorDhGost34311kdfScheme, components: &[1, 2, 804, 2, 1, 1, 1, 1, 3, 4] },
    OidDef { id: OidId::PkiCp, components: &[1, 2, 804, 2, 1, 1, 1, 2] },
    OidDef { id: OidId::PkiUkrEdsCp, components: &[1, 2, 804, 2, 1, 1, 1, 2, 1] },
    OidDef { id: OidId::PkiTspPolicy, components: &[1, 2, 804, 2, 1, 1, 1, 2, 3] },
    OidDef { id: OidId::PkiTspPolicyDstuPb, components: &[1, 2, 804, 2, 1, 1, 1, 2, 3, 1] },
    OidDef { id: OidId::PkiTspPolicyGost, components: &[1, 2, 804, 2, 1, 1, 1, 2, 3, 2] },
    OidDef { id: OidId::PkiTspPolicyDstuOnb, components: &[1, 2, 804, 2, 1, 1, 1, 2, 3, 3] },
    OidDef { id: OidId::PkiEku, components: &[1, 2, 804, 2, 1, 1, 1, 3] },
    OidDef { id: OidId::PkiEkuStamp, components: &[1, 2, 804, 2, 1, 1, 1, 3, 9] },
    OidDef { id: OidId::PkiDev, components: &[1, 2, 804, 2, 1, 1, 1, 11] },
    OidDef { id: OidId::CeCrlReason, components: &[2, 5, 29, 21] },
    OidDef { id: OidId::Data, components: &[1, 2, 840, 113549, 1, 7, 1] },
    OidDef { id: OidId::SignedData, components: &[1, 2, 840, 113549, 1, 7, 2] },
    OidDef { id: OidId::EnvelopedData, components: &[1, 2, 840, 113549, 1, 7, 3] },
    OidDef { id: OidId::DigOid, components: &[1, 2, 840, 113549, 1, 7, 5] },
    OidDef { id: OidId::EncOid, components: &[1, 2, 840, 113549, 1, 7, 6] },
    OidDef { id: OidId::Email, components: &[1, 2, 840, 113549, 1, 9, 1] },
    OidDef { id: OidId::UnstructuredName, components: &[1, 2, 840, 113549, 1, 9, 2] },
    OidDef { id: OidId::ContentType, components: &[1, 2, 840, 113549, 1, 9, 3] },
    OidDef { id: OidId::MessageDigest, components: &[1, 2, 840, 113549, 1, 9, 4] },
    OidDef { id: OidId::SigningTime, components: &[1, 2, 840, 113549, 1, 9, 5] },
    OidDef { id: OidId::CounterSignature, components: &[1, 2, 840, 113549, 1, 9, 6] },
    OidDef { id: OidId::ChallengePassword, components: &[1, 2, 840, 113549, 1, 9, 7] },
    OidDef { id: OidId::UnstructuredAddress, components: &[1, 2, 840, 113549, 1, 9, 8] },
    OidDef { id: OidId::ExtendedCertAttr, components: &[1, 2, 840, 113549, 1, 9, 9] },
    OidDef { id: OidId::SigningDescription, components: &[1, 2, 840, 113549, 1, 9, 13] },
    OidDef { id: OidId::ExtensionRequest, components: &[1, 2, 840, 113549, 1, 9, 14] },
    OidDef { id: OidId::Capabilities, components: &[1, 2, 840, 113549, 1, 9, 15] },
    OidDef { id: OidId::OidRegistry, components: &[1, 2, 840, 113549, 1, 9, 16] },
    OidDef { id: OidId::Friendlyname, components: &[1, 2, 840, 113549, 1, 9, 20] },
    OidDef { id: OidId::Localkey, components: &[1, 2, 840, 113549, 1, 9, 21] },
    OidDef { id: OidId::CertTypes, components: &[1, 2, 840, 113549, 1, 9, 22] },
    OidDef { id: OidId::CrlTypes, components: &[1, 2, 840, 113549, 1, 9, 22] },
    OidDef { id: OidId::AaSigningCertificate, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 12] },
    OidDef { id: OidId::AaSigningCertificateV2, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 47] },
    OidDef { id: OidId::AaEtsSigPolicy, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 15] },
    OidDef { id: OidId::SpqEtsUri, components: &[1, 2, 840, 113549, 1, 9, 16, 5, 1] },
    OidDef { id: OidId::SpqEtsUnitice, components: &[1, 2, 840, 113549, 1, 9, 16, 5, 2] },
    OidDef { id: OidId::AaEtsContentTimeStamp, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 20] },
    OidDef { id: OidId::AaSignatureTimeStampToken, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 14] },
    OidDef { id: OidId::CtTstInfo, components: &[1, 2, 840, 113549, 1, 9, 16, 1, 4] },
    OidDef { id: OidId::AaEtsCertificateRefs, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 21] },
    OidDef { id: OidId::AaEtsRevocationRefs, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 22] },
    OidDef { id: OidId::AaEtsCertValues, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 23] },
    OidDef { id: OidId::AaEtsRevocationValues, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 24] },
    OidDef { id: OidId::AaEtsArchiveTimeStamp, components: &[1, 2, 840, 113549, 1, 9, 16, 2, 27] },
    OidDef { id: OidId::SubjectDirectoryAttributesExtension, components: &[2, 5, 29, 9] },
    OidDef { id: OidId::SubjectKeyIdentifierExtension, components: &[2, 5, 29, 14] },
    OidDef { id: OidId::KeyUsageExtension, components: &[2, 5, 29, 15] },
    OidDef { id: OidId::PrivateKeyUsagePeriodExtension, components: &[2, 5, 29, 16] },
    OidDef { id: OidId::SubjectAltNameExtension, components: &[2, 5, 29, 17] },
    OidDef { id: OidId::IssuerAltNameExtension, components: &[2, 5, 29, 18] },
    OidDef { id: OidId::BasicConstraintsExtension, components: &[2, 5, 29, 19] },
    OidDef { id: OidId::AuthorityKeyIdentifierExtension, components: &[2, 5, 29, 35] },
    OidDef { id: OidId::CrlNumberExtension, components: &[2, 5, 29, 20] },
    OidDef { id: OidId::CrlReasonExtension, components: &[2, 5, 29, 21] },
    OidDef { id: OidId::HoldInstructionCodeExtension, components: &[2, 5, 29, 23] },
    OidDef { id: OidId::InvalidityDateExtension, components: &[2, 5, 29, 24] },
    OidDef { id: OidId::DeltaCrlIndicatorExtension, components: &[2, 5, 29, 27] },
    OidDef { id: OidId::CertificateIssuerExtension, components: &[2, 5, 29, 29] },
    OidDef { id: OidId::CrlDistributionPointsExtension, components: &[2, 5, 29, 31] },
    OidDef { id: OidId::CertificatePoliciesExtension, components: &[2, 5, 29, 32] },
    OidDef { id: OidId::ExtKeyUsageExtension, components: &[2, 5, 29, 37] },
    OidDef { id: OidId::FreshestCrlExtension, components: &[2, 5, 29, 46] },
    OidDef { id: OidId::AuthorityInfoAccessExtension, components: &[1, 3, 6, 1, 5, 5, 7, 1, 1] },
    OidDef { id: OidId::QcStatementsExtension, components: &[1, 3, 6, 1, 5, 5, 7, 1, 3] },
    OidDef { id: OidId::SubjectInfoAccessExtension, components: &[1, 3, 6, 1, 5, 5, 7, 1, 11] },
    OidDef { id: OidId::OcspOid, components: &[1, 3, 6, 1, 5, 5, 7, 48, 1] },
    OidDef { id: OidId::CaissuersOid, components: &[1, 3, 6, 1, 5, 5, 7, 48, 2] },
    OidDef { id: OidId::TspOid, components: &[1, 3, 6, 1, 5, 5, 7, 48, 3] },
    OidDef { id: OidId::BasicResponse, components: &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1] },
    OidDef { id: OidId::NonceExtension, components: &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2] },
    OidDef { id: OidId::AcceptableResponsesExtension, components: &[1, 3, 6, 1, 5, 5, 7, 48, 1, 4] },
    OidDef { id: OidId::ArchiveCutoffExtension, components: &[1, 3, 6, 1, 5, 5, 7, 48, 1, 6] },
    OidDef { id: OidId::ServiceLocatorExtension, components: &[1, 3, 6, 1, 5, 5, 7, 48, 1, 7] },
    OidDef { id: OidId::KnowledgeInformation, components: &[2, 5, 4, 2] },
    OidDef { id: OidId::CommonName, components: &[2, 5, 4, 3] },
    OidDef { id: OidId::Surname, components: &[2, 5, 4, 4] },
    OidDef { id: OidId::SerialNumber, components: &[2, 5, 4, 5] },
    OidDef { id: OidId::CountryName, components: &[2, 5, 4, 6] },
    OidDef { id: OidId::LocalityName, components: &[2, 5, 4, 7] },
    OidDef { id: OidId::StateName, components: &[2, 5, 4, 8] },
    OidDef { id: OidId::StreetName, components: &[2, 5, 4, 9] },
    OidDef { id: OidId::OrganizationName, components: &[2, 5, 4, 10] },
    OidDef { id: OidId::OrganizationUnit, components: &[2, 5, 4, 11] },
    OidDef { id: OidId::Title, components: &[2, 5, 4, 12] },
    OidDef { id: OidId::Description, components: &[2, 5, 4, 13] },
    OidDef { id: OidId::BusinessCategory, components: &[2, 5, 4, 15] },
    OidDef { id: OidId::PostalCode, components: &[2, 5, 4, 17] },
    OidDef { id: OidId::PostOfficeBox, components: &[2, 5, 4, 18] },
    OidDef { id: OidId::DeliveryName, components: &[2, 5, 4, 19] },
    OidDef { id: OidId::GivenName, components: &[2, 5, 4, 42] },
    OidDef { id: OidId::OcspKeyPurpose, components: &[1, 3, 6, 1, 5, 5, 7, 3, 9] },
    OidDef { id: OidId::Pbes2, components: &[1, 2, 840, 113549, 1, 5, 13] },
    OidDef { id: OidId::PbeWithSha1TdesCbc, components: &[1, 2, 840, 113549, 1, 12, 1, 3] },
    OidDef { id: OidId::DesEde3Cbc, components: &[1, 2, 840, 113549, 3, 7] },
    OidDef { id: OidId::Kdf, components: &[1, 2, 840, 113549, 1, 5, 12] },
    OidDef { id: OidId::EcPublicKeyType, components: &[1, 2, 840, 10045, 2, 1] },
    OidDef { id: OidId::EcdsaSecp192R1, components: &[1, 2, 840, 10045, 3, 1, 1] },
    OidDef { id: OidId::EcdsaSecp256R1, components: &[1, 2, 840, 10045, 3, 1, 7] },
    OidDef { id: OidId::EcdsaSecp224R1, components: &[1, 3, 132, 0, 33] },
    OidDef { id: OidId::EcdsaSecp384R1, components: &[1, 3, 132, 0, 34] },
    OidDef { id: OidId::EcdsaSecp521R1, components: &[1, 3, 132, 0, 35] },
    OidDef { id: OidId::EcdsaSecp256K1, components: &[1, 3, 132, 0, 10] },
    OidDef { id: OidId::EcdsaWithSha1, components: &[1, 2, 840, 10045, 4, 1] },
    OidDef { id: OidId::EcdsaWithSha224, components: &[1, 2, 840, 10045, 4, 3, 1] },
    OidDef { id: OidId::EcdsaWithSha256, components: &[1, 2, 840, 10045, 4, 3, 2] },
    OidDef { id: OidId::EcdsaWithSha384, components: &[1, 2, 840, 10045, 4, 3, 3] },
    OidDef { id: OidId::EcdsaWithSha512, components: &[1, 2, 840, 10045, 4, 3, 4] },
    OidDef { id: OidId::Aes256Cbc, components: &[2, 16, 840, 1, 101, 3, 4, 1, 42] },
    OidDef { id: OidId::PkiHmacSha1, components: &[1, 2, 840, 113549, 2, 7] },
    OidDef { id: OidId::EtsiQcs, components: &[0, 4, 0, 1862, 1] },
    OidDef { id: OidId::EtsiQcsQcLimitValue, components: &[0, 4, 0, 1862, 1, 2] },
    OidDef { id: OidId::PkiGost3410, components: &[1, 2, 398, 3, 10, 1, 1, 1, 1] },
    OidDef { id: OidId::Gost3410Kz, components: &[1, 2, 398, 3, 10, 1, 1, 1, 2] },
];

const SUPPORTED_EXTENSIONS: &[OidId] = &[
    OidId::SubjectDirectoryAttributesExtension,
    OidId::SubjectKeyIdentifierExtension,
    OidId::KeyUsageExtension,
    OidId::PrivateKeyUsagePeriodExtension,
    OidId::SubjectAltNameExtension,
    OidId::IssuerAltNameExtension,
    OidId::BasicConstraintsExtension,
    OidId::CrlNumberExtension,
    OidId::CrlReasonExtension,
    OidId::HoldInstructionCodeExtension,
    OidId::InvalidityDateExtension,
    OidId::DeltaCrlIndicatorExtension,
    OidId::CertificateIssuerExtension,
    OidId::CrlDistributionPointsExtension,
    OidId::CertificatePoliciesExtension,
    OidId::AuthorityKeyIdentifierExtension,
    OidId::ExtKeyUsageExtension,
    OidId::FreshestCrlExtension,
    OidId::AuthorityInfoAccessExtension,
    OidId::QcStatementsExtension,
    OidId::SubjectInfoAccessExtension,
    OidId::NonceExtension,
    OidId::CrlIdExtension,
    OidId::AcceptableResponsesExtension,
    OidId::ArchiveCutoffExtension,
    OidId::ServiceLocatorExtension,
];

const SUPPORTED_NAME_ATTRS: &[(&str, OidId)] = &[
    ("C", OidId::CountryName),
    ("SN", OidId::SerialNumber),
    ("KI", OidId::KnowledgeInformation),
    ("CN", OidId::CommonName),
    ("SRN", OidId::Surname),
    ("L", OidId::LocalityName),
    ("ST", OidId::StateName),
    ("STR", OidId::StreetName),
    ("O", OidId::OrganizationName),
    ("OU", OidId::OrganizationUnit),
    ("T", OidId::Title),
    ("DE", OidId::Description),
    ("BC", OidId::BusinessCategory),
    ("PC", OidId::PostalCode),
    ("PB", OidId::PostOfficeBox),
    ("PDON", OidId::DeliveryName),
    ("GN", OidId::GivenName),
    ("E", OidId::Email),
];

/// Numeric OID components for a registered identifier.
pub fn oid_components(id: OidId) -> Option<&'static [u32]> {
    OID_REGISTRY
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.components)
}

/// Dot-decimal OID string (e.g. `1.2.804.2.1.1.1`).
pub fn oid_to_str(id: OidId) -> Option<String> {
    let components = oid_components(id)?;
    Some(
        components
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Parse dot-decimal OID into numeric components.
pub fn parse_oid_str(s: &str) -> Option<Vec<u32>> {
    if s.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for part in s.split('.') {
        out.push(part.parse().ok()?);
    }
    Some(out)
}

/// Lookup registered OID by dot-decimal string (`oids_get_oid_numbers_by_str`).
pub fn oid_from_str(s: &str) -> Option<OidId> {
    let parsed = parse_oid_str(s)?;
    OID_REGISTRY
        .iter()
        .find(|entry| entry.components == parsed.as_slice())
        .map(|entry| entry.id)
}

/// Compare registered OID to dot-decimal string.
pub fn oid_matches_str(id: OidId, s: &str) -> bool {
    oid_from_str(s) == Some(id)
}

/// `oids_get_supported_extention`.
pub fn supported_extension(index: usize) -> Option<OidId> {
    SUPPORTED_EXTENSIONS.get(index).copied()
}

/// `oids_get_supported_name_attr`.
pub fn supported_name_attr(index: usize) -> Option<(&'static str, OidId)> {
    SUPPORTED_NAME_ATTRS.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_extension_0_matches_utest() {
        let id = supported_extension(0).expect("extension 0");
        assert_eq!(id, OidId::SubjectDirectoryAttributesExtension);
        assert!(oid_matches_str(id, "2.5.29.9"));
    }

    #[test]
    fn supported_extension_out_of_range_returns_none() {
        assert_eq!(supported_extension(26), None);
    }

    #[test]
    fn oid_from_str_pki_root_matches_utest() {
        assert_eq!(oid_from_str("1.2.804.2.1.1.1"), Some(OidId::Pki));
    }

    #[test]
    fn oid_from_str_pki_alg_matches_utest() {
        assert_eq!(oid_from_str("1.2.804.2.1.1.1.1"), Some(OidId::PkiAlg));
    }

    #[test]
    fn oid_by_id_pki_hash_matches_utest() {
        assert!(oid_matches_str(OidId::PkiHash, "1.2.804.2.1.1.1.1.2"));
    }

    #[test]
    fn dstu4145_m163_pb_oid() {
        assert!(oid_matches_str(OidId::PkiM163Pb, "1.2.804.2.1.1.1.1.3.1.1.2.0"));
    }

    #[test]
    fn cms_signed_data_oid() {
        assert!(oid_matches_str(OidId::SignedData, "1.2.840.113549.1.7.2"));
    }

    #[test]
    fn gost3411_oid() {
        assert!(oid_matches_str(OidId::PkiGost3411, "1.2.804.2.1.1.1.1.2.1"));
    }

    #[test]
    fn sha256_oid() {
        assert!(oid_matches_str(OidId::PkiSha256, "2.16.840.1.101.3.4.2.1"));
    }

    #[test]
    fn basic_constraints_extension_oid() {
        assert!(oid_matches_str(
            OidId::BasicConstraintsExtension,
            "2.5.29.19"
        ));
    }

    #[test]
    fn name_attr_common_name() {
        let (short, id) = supported_name_attr(3).expect("CN attr");
        assert_eq!(short, "CN");
        assert_eq!(id, OidId::CommonName);
        assert!(oid_matches_str(id, "2.5.4.3"));
    }
}

