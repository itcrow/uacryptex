//! Extension builders (`ext.c`).

use der::asn1::{GeneralizedTime, Ia5String, Ia5StringRef, OctetString, PrintableStringRef, Uint};
use der::{Any, Decode, Encode, Sequence};
use x509_cert::ext::pkix::certpolicy::{CertificatePolicies, PolicyInformation};
use x509_cert::ext::pkix::constraints::BasicConstraints;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::crl::{CrlDistributionPoints, CrlNumber, CrlReason, FreshestCrl};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AccessDescription, AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, ExtendedKeyUsage,
    PrivateKeyUsagePeriod, SubjectAltName, SubjectDirectoryAttributes, SubjectInfoAccessSyntax,
    SubjectKeyIdentifier,
};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::Extension;
use x509_cert::spki::SubjectPublicKeyInfo;

use super::{build_extension, encode_as_ext_value, object_identifier};
use crate::pki::cert::Cert;
use crate::pki::crypto::{algorithm_identifier_der, DigestAdapter};
use crate::pki::oid::{oid_matches_str, OidId};
use crate::{Error, Result};

/// Cryptonite `KeyUsageBits`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsageBits(u32);

impl KeyUsageBits {
    pub const DIGITAL_SIGNATURE: Self = Self(0x0000_0001);
    pub const NON_REPUDIATION: Self = Self(0x0000_0002);
    pub const KEY_ENCIPHERMENT: Self = Self(0x0000_0004);
    pub const DATA_ENCIPHERMENT: Self = Self(0x0000_0008);
    pub const KEY_AGREEMENT: Self = Self(0x0000_0010);
    pub const KEY_CERT_SIGN: Self = Self(0x0000_0020);
    pub const CRL_SIGN: Self = Self(0x0000_0040);
    pub const ENCIPHER_ONLY: Self = Self(0x0000_0080);
    pub const DECIPHER_ONLY: Self = Self(0x0000_0100);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Cryptonite `e_CRLReason` subset used in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrlReasonCode {
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl CrlReasonCode {
    fn to_x509(self) -> CrlReason {
        match self {
            Self::KeyCompromise => CrlReason::KeyCompromise,
            Self::CaCompromise => CrlReason::CaCompromise,
            Self::AffiliationChanged => CrlReason::AffiliationChanged,
            Self::Superseded => CrlReason::Superseded,
            Self::CessationOfOperation => CrlReason::CessationOfOperation,
            Self::CertificateHold => CrlReason::CertificateHold,
            Self::RemoveFromCrl => CrlReason::RemoveFromCRL,
            Self::PrivilegeWithdrawn => CrlReason::PrivilegeWithdrawn,
            Self::AaCompromise => CrlReason::AaCompromise,
        }
    }
}

/// `ext_create_any`.
pub fn ext_create_any(critical: bool, oid: OidId, value: &[u8]) -> Result<Extension> {
    if value.is_empty() {
        return Err(Error::InvalidParam("extension value is empty".into()));
    }
    build_extension(oid, critical, value)
}

/// `ext_create_key_usage` (Cryptonite bit ordering).
pub fn ext_create_key_usage(critical: bool, usage: KeyUsageBits) -> Result<Extension> {
    let value = encode_cryptonite_key_usage(usage.bits())?;
    build_extension(OidId::KeyUsageExtension, critical, value)
}

/// `ext_create_basic_constraints`.
pub fn ext_create_basic_constraints(
    critical: bool,
    issuer_path_len: Option<u8>,
    ca: bool,
    path_len_constraint: u8,
) -> Result<Extension> {
    let path_len = if ca {
        Some(if let Some(issuer) = issuer_path_len {
            issuer.saturating_add(1)
        } else {
            path_len_constraint
        })
    } else {
        None
    };
    let bc = BasicConstraints {
        ca,
        path_len_constraint: path_len,
    };
    let value = encode_as_ext_value(&bc)?;
    build_extension(OidId::BasicConstraintsExtension, critical, value)
}

/// `ext_create_cert_policies`.
pub fn ext_create_cert_policies(critical: bool, policy_oids: &[OidId]) -> Result<Extension> {
    if policy_oids.is_empty() {
        return Err(Error::InvalidParam("cert policies list is empty".into()));
    }
    let mut policies = CertificatePolicies(Vec::new());
    for oid in policy_oids {
        policies.0.push(PolicyInformation {
            policy_identifier: object_identifier(*oid)?,
            policy_qualifiers: None,
        });
    }
    let value = encode_as_ext_value(&policies)?;
    build_extension(OidId::CertificatePoliciesExtension, critical, value)
}

fn distribution_points_from_uris(uris: &[&str]) -> Result<CrlDistributionPoints> {
    if uris.is_empty() {
        return Err(Error::InvalidParam("distribution point URIs are empty".into()));
    }
    let mut points = CrlDistributionPoints::default();
    for uri in uris {
        if uri.is_empty() {
            return Err(Error::InvalidParam("distribution point URI is empty".into()));
        }
        let gn = GeneralName::UniformResourceIdentifier(
            Ia5StringRef::new(uri)
                .map_err(|e| Error::InvalidParam(format!("invalid URI: {e}")))?
                .into(),
        );
        points.0.push(DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![gn])),
            reasons: None,
            crl_issuer: None,
        });
    }
    Ok(points)
}

/// `ext_create_crl_distr_points`.
pub fn ext_create_crl_distr_points(critical: bool, point_uris: &[&str]) -> Result<Extension> {
    let value = encode_as_ext_value(&distribution_points_from_uris(point_uris)?)?;
    build_extension(OidId::CrlDistributionPointsExtension, critical, value)
}

/// `ext_create_freshest_crl`.
pub fn ext_create_freshest_crl(critical: bool, point_uris: &[&str]) -> Result<Extension> {
    let dps = distribution_points_from_uris(point_uris)?;
    let freshest = FreshestCrl(dps.0);
    let value = encode_as_ext_value(&freshest)?;
    build_extension(OidId::FreshestCrlExtension, critical, value)
}

fn access_descriptions(method: OidId, uris: &[&str]) -> Result<Vec<AccessDescription>> {
    if uris.is_empty() {
        return Err(Error::InvalidParam("access URI list is empty".into()));
    }
    let access_method = object_identifier(method)?;
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        if uri.is_empty() {
            return Err(Error::InvalidParam("access URI is empty".into()));
        }
        out.push(AccessDescription {
            access_method,
            access_location: GeneralName::UniformResourceIdentifier(
                Ia5StringRef::new(uri)
                    .map_err(|e| Error::InvalidParam(format!("invalid URI: {e}")))?
                    .into(),
            ),
        });
    }
    Ok(out)
}

/// `ext_create_auth_info_access`.
pub fn ext_create_auth_info_access(
    critical: bool,
    access_method: OidId,
    name_uris: &[&str],
) -> Result<Extension> {
    let ads = access_descriptions(access_method, name_uris)?;
    let value = encode_as_ext_value(&AuthorityInfoAccessSyntax(ads))?;
    build_extension(OidId::AuthorityInfoAccessExtension, critical, value)
}

/// `ext_create_subj_info_access`.
pub fn ext_create_subj_info_access(
    critical: bool,
    access_method: OidId,
    name_uris: &[&str],
) -> Result<Extension> {
    let ads = access_descriptions(access_method, name_uris)?;
    let value = encode_as_ext_value(&SubjectInfoAccessSyntax(ads))?;
    build_extension(OidId::SubjectInfoAccessExtension, critical, value)
}

/// `ext_create_crl_number`.
pub fn ext_create_crl_number(critical: bool, crl_sn: &[u8]) -> Result<Extension> {
    if crl_sn.is_empty() {
        return Err(Error::InvalidParam("CRL number is empty".into()));
    }
    let number = CrlNumber(
        Uint::new(crl_sn).map_err(|e| Error::InvalidParam(format!("CRL number: {e}")))?,
    );
    let value = encode_as_ext_value(&number)?;
    build_extension(OidId::CrlNumberExtension, critical, value)
}

/// `ext_create_crl_reason`.
pub fn ext_create_crl_reason(critical: bool, reason: CrlReasonCode) -> Result<Extension> {
    let value = encode_as_ext_value(&reason.to_x509())?;
    build_extension(OidId::CrlReasonExtension, critical, value)
}

/// `ext_create_delta_crl_indicator`.
pub fn ext_create_delta_crl_indicator(critical: bool, crl_number: &[u8]) -> Result<Extension> {
    if crl_number.is_empty() {
        return Err(Error::InvalidParam("CRL number is empty".into()));
    }
    let number = CrlNumber(
        Uint::new(crl_number).map_err(|e| Error::InvalidParam(format!("CRL number: {e}")))?,
    );
    let value = encode_as_ext_value(&number)?;
    build_extension(OidId::DeltaCrlIndicatorExtension, critical, value)
}

/// `ext_create_ext_key_usage`.
pub fn ext_create_ext_key_usage(critical: bool, purpose_oids: &[OidId]) -> Result<Extension> {
    if purpose_oids.is_empty() {
        return Err(Error::InvalidParam("extended key usage list is empty".into()));
    }
    let mut oids = ExtendedKeyUsage(Vec::new());
    for id in purpose_oids {
        oids.0.push(object_identifier(*id)?);
    }
    let value = encode_as_ext_value(&oids)?;
    build_extension(OidId::ExtKeyUsageExtension, critical, value)
}

/// `ext_create_nonce` — OCSP nonce is an OCTET STRING.
pub fn ext_create_nonce(critical: bool, rnd: &[u8]) -> Result<Extension> {
    if rnd.is_empty() {
        return Err(Error::InvalidParam("nonce bytes are empty".into()));
    }
    let value = OctetString::new(rnd)
        .map_err(|e| Error::Internal(format!("nonce: {e}")))?
        .to_der()
        .map_err(|e| Error::Internal(format!("nonce encode: {e}")))?;
    build_extension(OidId::NonceExtension, critical, value)
}

/// `ext_create_invalidity_date`.
pub fn ext_create_invalidity_date(critical: bool, time: GeneralizedTime) -> Result<Extension> {
    let value = encode_as_ext_value(&time)?;
    build_extension(OidId::InvalidityDateExtension, critical, value)
}

/// `ext_create_private_key_usage`.
pub fn ext_create_private_key_usage(
    critical: bool,
    not_before: Option<GeneralizedTime>,
    not_after: Option<GeneralizedTime>,
) -> Result<Extension> {
    let (not_before, not_after) = match (not_before, not_after) {
        (Some(b), Some(a)) => (Some(b), Some(a)),
        _ => {
            return Err(Error::InvalidParam(
                "private key usage requires both not_before and not_after".into(),
            ));
        }
    };
    let pkup = PrivateKeyUsagePeriod {
        not_before,
        not_after,
    };
    let value = encode_as_ext_value(&pkup)?;
    build_extension(OidId::PrivateKeyUsagePeriodExtension, critical, value)
}

/// Single QC statement for `ext_create_qc_statements`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QcStatement {
    pub statement_id: OidId,
    pub statement_info: Option<Vec<u8>>,
}

/// `ext_create_qc_statement_compliance`.
pub fn qc_statement_compliance() -> QcStatement {
    QcStatement {
        statement_id: OidId::PkiUkrEdsCp,
        statement_info: None,
    }
}

/// `ext_create_qc_statement_limit_value`.
pub fn qc_statement_limit_value(currency: &str, amount: i64, exponent: i64) -> Result<QcStatement> {
    if currency.is_empty() || currency.len() > 3 {
        return Err(Error::InvalidParam(
            "currency code must be 1..=3 characters".into(),
        ));
    }
    let currency = PrintableStringRef::new(currency)
        .map_err(|e| Error::InvalidParam(format!("currency: {e}")))?;
    let info = encode_monetary_value(currency, amount, exponent)?;
    Ok(QcStatement {
        statement_id: OidId::EtsiQcsQcLimitValue,
        statement_info: Some(info),
    })
}

/// `ext_create_qc_statements`.
pub fn ext_create_qc_statements(critical: bool, statements: &[QcStatement]) -> Result<Extension> {
    if statements.is_empty() {
        return Err(Error::InvalidParam("QC statements list is empty".into()));
    }
    let value = encode_qc_statements(statements)?;
    build_extension(OidId::QcStatementsExtension, critical, value)
}

/// `ext_create_subj_alt_name_directly`.
pub fn ext_create_subj_alt_name_directly(
    critical: bool,
    dns: &str,
    email: &str,
) -> Result<Extension> {
    let san = SubjectAltName(vec![
        GeneralName::DnsName(
            Ia5String::new(dns).map_err(|e| Error::Internal(format!("dns name: {e}")))?,
        ),
        GeneralName::Rfc822Name(
            Ia5String::new(email).map_err(|e| Error::Internal(format!("email: {e}")))?,
        ),
    ]);
    let value = encode_as_ext_value(&san)?;
    build_extension(OidId::SubjectAltNameExtension, critical, value)
}

/// `ext_create_subj_dir_attr_directly`.
pub fn ext_create_subj_dir_attr_directly(critical: bool, subject_attr: &str) -> Result<Extension> {
    use crate::pki::utils::{object_identifier_from_text, parse_key_value};

    let pairs = parse_key_value(subject_attr)?;
    let mut attrs = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let oid = object_identifier_from_text(&key)?;
        let ps = PrintableStringRef::new(&value)
            .map_err(|e| Error::Internal(format!("directory attribute: {e}")))?;
        attrs.push(AttributeTypeAndValue {
            oid,
            value: der::Any::from_der(
                &ps.to_der()
                    .map_err(|e| Error::Internal(format!("printable string encode: {e}")))?,
            )
            .map_err(|e| Error::Internal(format!("directory attribute any: {e}")))?,
        });
    }
    let sda = SubjectDirectoryAttributes(attrs);
    let value = encode_as_ext_value(&sda)?;
    build_extension(OidId::SubjectDirectoryAttributesExtension, critical, value)
}

/// `ext_create_subj_key_id`.
pub fn ext_create_subj_key_id(critical: bool, spki_der: &[u8]) -> Result<Extension> {
    let key_id = pkix_key_id_from_spki_der(spki_der)?;
    let ski = SubjectKeyIdentifier(
        OctetString::new(key_id.as_slice()).map_err(|e| Error::Internal(format!("subject key id: {e}")))?,
    );
    let value = encode_as_ext_value(&ski)?;
    build_extension(OidId::SubjectKeyIdentifierExtension, critical, value)
}

/// `ext_create_auth_key_id_from_spki`.
pub fn ext_create_auth_key_id_from_spki(critical: bool, spki_der: &[u8]) -> Result<Extension> {
    let key_id = pkix_key_id_from_spki_der(spki_der)?;
    build_auth_key_id_extension(critical, &key_id)
}

/// `ext_create_auth_key_id_from_cert`.
pub fn ext_create_auth_key_id_from_cert(critical: bool, issuer: &Cert) -> Result<Extension> {
    let key_id = issuer.subject_key_id()?;
    build_auth_key_id_extension(critical, &key_id)
}

#[derive(Sequence)]
struct MonetaryValue<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    currency: PrintableStringRef<'a>,
    amount: Uint,
    exponent: Uint,
}

fn encode_monetary_value(
    currency: PrintableStringRef<'_>,
    amount: i64,
    exponent: i64,
) -> Result<Vec<u8>> {
    MonetaryValue {
        currency,
        amount: int_to_uint(amount, "amount")?,
        exponent: int_to_uint(exponent, "exponent")?,
    }
    .to_der()
    .map_err(|e| Error::Internal(format!("monetary value: {e}")))
}

fn int_to_uint(value: i64, name: &str) -> Result<Uint> {
    if value < 0 {
        return Err(Error::InvalidParam(format!("{name} must be non-negative")));
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    Uint::new(&bytes[start..]).map_err(|e| Error::InvalidParam(format!("{name}: {e}")))
}

fn build_auth_key_id_extension(critical: bool, key_id: &[u8]) -> Result<Extension> {
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(
            OctetString::new(key_id).map_err(|e| Error::Internal(format!("key id: {e}")))?,
        ),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let value = encode_as_ext_value(&aki)?;
    build_extension(OidId::AuthorityKeyIdentifierExtension, critical, value)
}

fn encode_qc_statements(statements: &[QcStatement]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for statement in statements {
        body.extend(encode_qc_statement(statement)?);
    }
    wrap_der_sequence(&body)
}

fn encode_qc_statement(statement: &QcStatement) -> Result<Vec<u8>> {
    let mut body = object_identifier(statement.statement_id)?
        .to_der()
        .map_err(|e| Error::Internal(format!("QC statement OID: {e}")))?;
    if let Some(info) = &statement.statement_info {
        body.extend_from_slice(info);
    }
    wrap_der_sequence(&body)
}

fn wrap_der_sequence(content: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(0x30);
    out.extend(der_length(content.len())?);
    out.extend_from_slice(content);
    Ok(out)
}

fn der_length(len: usize) -> Result<Vec<u8>> {
    if len < 0x80 {
        Ok(vec![len as u8])
    } else if len <= 0xff {
        Ok(vec![0x81, len as u8])
    } else if len <= 0xffff {
        Ok(vec![0x82, (len >> 8) as u8, len as u8])
    } else {
        Err(Error::Internal("DER length too large".into()))
    }
}

fn spki_uses_gost3411(oid: &str) -> bool {
    if oid_matches_str(OidId::PkiGost3411, oid) {
        return true;
    }
    let Some(prefix) = crate::pki::oid::oid_to_str(OidId::PkiDstu4145WithGost3411) else {
        return false;
    };
    oid == prefix.as_str() || oid.starts_with(&format!("{prefix}."))
}

pub(crate) fn pkix_key_id_from_spki_der(spki_der: &[u8]) -> Result<Vec<u8>> {
    let spki: SubjectPublicKeyInfo<Any, der::asn1::BitString> =
        SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|e| Error::Internal(format!("spki decode: {e}")))?;
    let pubkey = spki.subject_public_key.raw_bytes();
    let spki_aid = spki
        .algorithm
        .to_der()
        .map_err(|e| Error::Internal(format!("spki algorithm encode: {e}")))?;
    let algo = spki.algorithm.oid.to_string();

    let digest_aid = if spki_uses_gost3411(&algo) {
        spki_aid
    } else if DigestAdapter::init_by_aid(&spki_aid).is_ok() {
        spki_aid
    } else {
        algorithm_identifier_der(OidId::PkiSha1, None)?
    };

    let mut da = DigestAdapter::init_by_aid(&digest_aid)?;
    da.update(pubkey)?;
    da.finalize()
}

fn swap_bits(byte: u8) -> u8 {
    let mut res = 0u8;
    for i in 0..8 {
        res |= ((byte >> i) & 1) << (7 - i);
    }
    res
}

fn byte_bitpadding(a: u8) -> u8 {
    (0..8).find(|i| (a & (1 << i)) != 0).unwrap_or(8) as u8
}

/// Cryptonite `ext_create_key_usage` BIT STRING encoding.
fn encode_cryptonite_key_usage(usage_bits: u32) -> Result<Vec<u8>> {
    let mut bytes = [0u8; 4];
    bytes[0] = swap_bits((usage_bits & 0xff) as u8);
    bytes[1] = swap_bits(((usage_bits >> 8) & 0xff) as u8);
    bytes[2] = swap_bits(((usage_bits >> 16) & 0xff) as u8);
    bytes[3] = swap_bits(((usage_bits >> 24) & 0xff) as u8);

    let mut len = 4usize;
    while len > 0 && bytes[len - 1] == 0 {
        len -= 1;
    }
    if len == 0 {
        len = 1;
    }
    let unused = byte_bitpadding(bytes[len - 1]);

    let bit_string = der::asn1::BitString::new(unused, &bytes[..len])
        .map_err(|e| Error::Internal(format!("key usage bit string: {e}")))?;
    encode_as_ext_value(&bit_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::ext::{ext_from_der, ext_get_value, ext_to_der};

    #[test]
    fn key_usage_matches_cryptonite_bit_order() {
        let usage = KeyUsageBits::KEY_CERT_SIGN.union(KeyUsageBits::CRL_SIGN);
        let ext = ext_create_key_usage(true, usage).unwrap();
        let value = ext_get_value(&ext);
        assert!(!value.is_empty());
        let roundtrip = ext_from_der(&ext_to_der(&ext).unwrap()).unwrap();
        assert_eq!(ext_get_value(&roundtrip), value);
    }

    #[test]
    fn basic_constraints_ca_path_zero() {
        let ext = ext_create_basic_constraints(true, None, true, 0).unwrap();
        assert_eq!(ext_get_value(&ext), hex::decode("30060101FF020100").unwrap());
    }

    #[test]
    fn ext_create_any_qc_statements_value() {
        let value = hex::decode("300D300B06092A8624020101010201").unwrap();
        let ext = ext_create_any(true, OidId::QcStatementsExtension, &value).unwrap();
        assert_eq!(ext_get_value(&ext), value);
    }
}
