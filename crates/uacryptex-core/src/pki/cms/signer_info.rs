//! SignerInfo verification (`signer_info.c`).

use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cert::Cert;
use crate::pki::cms::ess::SigningCertificateV2;
use crate::pki::cms::types::{IssuerAndSerialNumber, SignerIdentifier, SignerInfo};
use crate::pki::crypto::{DigestAdapter, VerifyAdapter};
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// RFC 5126 imprint bytes: DER(attrType) || DER(attrValues SET), without outer SEQUENCE.
pub(crate) fn attribute_imprint(attr: &Attribute) -> Result<Vec<u8>> {
    let mut out = attr
        .oid
        .to_der()
        .map_err(|e| Error::Internal(format!("attribute oid encode: {e}")))?;
    out.extend_from_slice(
        &attr
            .values
            .to_der()
            .map_err(|e| Error::Internal(format!("attribute values encode: {e}")))?,
    );
    Ok(out)
}

pub(crate) fn unsigned_attr_imprint(attrs: &Attributes, target: OidId) -> Result<Option<Vec<u8>>> {
    let oid = object_identifier(target)?;
    let Some(attr) = attrs.iter().find(|attr| attr.oid == oid) else {
        return Ok(None);
    };
    attribute_imprint(attr).map(Some)
}

pub(crate) fn unsigned_attr_value_bytes(
    attrs: &Attributes,
    target: OidId,
) -> Result<Option<Vec<u8>>> {
    let oid = object_identifier(target)?;
    let Some(attr) = attrs.iter().find(|attr| attr.oid == oid) else {
        return Ok(None);
    };
    let value = attr
        .values
        .get(0)
        .ok_or_else(|| Error::Internal(format!("unsigned attribute {:?} has no value", target)))?;
    Ok(Some(value.value().to_vec()))
}

pub(crate) fn signed_attributes_der(attrs: &Attributes) -> Result<Vec<u8>> {
    attrs
        .to_der()
        .map_err(|e| Error::Internal(format!("signed attributes encode: {e}")))
}

pub(crate) fn signature_octets(
    signature: &OctetString,
    signature_algorithm_der: &[u8],
) -> Result<Vec<u8>> {
    signature_bytes(signature, signature_algorithm_der)
}

/// `cert_check_sid`.
pub fn cert_matches_signer_id(cert: &Cert, sid: &SignerIdentifier) -> Result<bool> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => {
            let issuer = cert
                .issuer_der()
                .map_err(|e| Error::Internal(e.to_string()))?;
            let cert_issuer = x509_cert::name::Name::from_der(&issuer)
                .map_err(|e| Error::Internal(format!("issuer decode: {e}")))?;
            let cert_serial = cert
                .inner_certificate()
                .tbs_certificate
                .serial_number
                .clone();
            Ok(cert_issuer == isn.issuer && cert_serial == isn.serial_number)
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let cert_ski = cert.subject_key_id()?;
            Ok(cert_ski.as_slice() == ski.0.as_bytes())
        }
    }
}

fn signed_attr_by_oid(attrs: &Attributes, target: OidId) -> Result<Option<&Attribute>> {
    let oid = object_identifier(target)?;
    Ok(attrs.iter().find(|attr| attr.oid == oid))
}

fn message_digest_from_attrs(attrs: &Attributes) -> Result<Vec<u8>> {
    let attr = signed_attr_by_oid(attrs, OidId::MessageDigest)?
        .ok_or_else(|| Error::Unsupported("signer info missing message-digest attribute".into()))?;
    let value = attr
        .values
        .get(0)
        .ok_or_else(|| Error::Internal("message-digest attribute has no value".into()))?;
    let os = value
        .decode_as::<OctetString>()
        .map_err(|e| Error::Internal(format!("message-digest decode: {e}")))?;
    Ok(os.as_bytes().to_vec())
}

fn encode_signed_attrs(attrs: &Attributes) -> Result<Vec<u8>> {
    signed_attributes_der(attrs)
}

fn signature_bytes(signature: &OctetString, signature_algorithm_der: &[u8]) -> Result<Vec<u8>> {
    use crate::pki::crypto::{is_dstu4145_signature_oid, is_ecdsa_signature_oid};
    use x509_cert::spki::AlgorithmIdentifier;

    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(signature_algorithm_der)
        .map_err(|e| Error::Internal(format!("signature algorithm decode: {e}")))?;
    let sign_oid = aid.oid.to_string();

    if is_dstu4145_signature_oid(&sign_oid) || is_ecdsa_signature_oid(&sign_oid) {
        return Ok(signature.as_bytes().to_vec());
    }
    Err(Error::Unsupported(format!(
        "unsupported CMS signature algorithm: {sign_oid}"
    )))
}

/// `verify_core` — verify encapsulated/external content with signed attributes.
pub fn verify_signer_info(
    sinfo: &SignerInfo,
    content: &[u8],
    da: &DigestAdapter,
    va: &VerifyAdapter,
) -> Result<()> {
    let cert = va.cert()?;
    if !cert_matches_signer_id(cert, &sinfo.sid)? {
        return Err(Error::InvalidParam(
            "signer identifier does not match certificate".into(),
        ));
    }

    let signed_attrs = sinfo.signed_attrs.as_ref().ok_or_else(|| {
        Error::Unsupported("detached CMS without signed attributes is not supported".into())
    })?;

    let expected_digest = message_digest_from_attrs(signed_attrs)?;
    let mut hasher = da.clone_state()?;
    hasher.update(content)?;
    let digest = hasher.finalize()?;
    if digest != expected_digest {
        return Err(Error::VerifyFailed);
    }

    let signed_attrs_der = encode_signed_attrs(signed_attrs)?;
    let sign = signature_bytes(
        &sinfo.signature,
        &sinfo
            .signature_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?,
    )?;
    va.verify_data(&signed_attrs_der, &sign)
}

/// `sinfo_verify_without_data` — verify signature over signed attributes only.
pub fn verify_signer_info_without_data(sinfo: &SignerInfo, va: &VerifyAdapter) -> Result<()> {
    let cert = va.cert()?;
    if !cert_matches_signer_id(cert, &sinfo.sid)? {
        return Err(Error::InvalidParam(
            "signer identifier does not match certificate".into(),
        ));
    }
    let signed_attrs = sinfo
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Unsupported("signer info has no signed attributes".into()))?;
    let signed_attrs_der = encode_signed_attrs(signed_attrs)?;
    let sign = signature_bytes(
        &sinfo.signature,
        &sinfo
            .signature_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?,
    )?;
    va.verify_data(&signed_attrs_der, &sign)
}

/// Build `SignerIdentifier` from certificate (SKI when present, else issuer+serial).
pub fn signer_identifier_from_cert(cert: &Cert) -> Result<SignerIdentifier> {
    if let Ok(ski_bytes) = cert.subject_key_id() {
        let ski = SubjectKeyIdentifier(
            OctetString::new(ski_bytes)
                .map_err(|e| Error::Internal(format!("subject key id octet string: {e}")))?,
        );
        return Ok(SignerIdentifier::SubjectKeyIdentifier(ski));
    }

    let issuer = cert.inner_certificate().tbs_certificate.issuer.clone();
    let serial_number = cert
        .inner_certificate()
        .tbs_certificate
        .serial_number
        .clone();
    Ok(SignerIdentifier::IssuerAndSerialNumber(
        IssuerAndSerialNumber {
            issuer,
            serial_number,
        },
    ))
}

/// Create a CMS attribute with one value.
pub fn attribute_with_value(oid: OidId, value: Any) -> Result<Attribute> {
    let attr_oid = object_identifier(oid)?;
    let values = SetOfVec::try_from(vec![value])
        .map_err(|e| Error::Internal(format!("attribute values set: {e}")))?;
    Ok(Attribute {
        oid: attr_oid,
        values,
    })
}

/// Create content-type attribute.
pub fn content_type_attribute(content_type: OidId) -> Result<Attribute> {
    let oid = object_identifier(content_type)?;
    let value = Any::from_der(
        &oid.to_der()
            .map_err(|e| Error::Internal(format!("content type oid encode: {e}")))?,
    )
    .map_err(|e| Error::Internal(format!("content type any: {e}")))?;
    attribute_with_value(OidId::ContentType, value)
}

/// Create message-digest attribute.
pub fn message_digest_attribute(digest: &[u8]) -> Result<Attribute> {
    let os = OctetString::new(digest).map_err(|e| Error::Internal(format!("digest os: {e}")))?;
    let value = Any::from_der(
        &os.to_der()
            .map_err(|e| Error::Internal(format!("digest os encode: {e}")))?,
    )
    .map_err(|e| Error::Internal(format!("digest any: {e}")))?;
    attribute_with_value(OidId::MessageDigest, value)
}

/// Create signing-certificate-v2 attribute (`OID_AA_SIGNING_CERTIFICATE_V2_ID`).
pub fn signing_certificate_v2_attribute(cert: &Cert, ess_da: &DigestAdapter) -> Result<Attribute> {
    use crate::pki::cms::ess::signing_certificate_v2;

    let scv2 = signing_certificate_v2(cert, ess_da)?;
    let value = Any::encode_from(&scv2)
        .map_err(|e| Error::Internal(format!("signing certificate v2 encode: {e}")))?;
    attribute_with_value(OidId::AaSigningCertificateV2, value)
}

/// Create id-aa-ets-certificateRefs unsigned attribute (CAdES-C).
pub fn complete_certificate_refs_attribute(
    refs: &crate::pki::cms::ets::CompleteCertificateRefs,
) -> Result<Attribute> {
    let value = Any::encode_from(refs)
        .map_err(|e| Error::Internal(format!("complete certificate refs encode: {e}")))?;
    attribute_with_value(OidId::AaEtsCertificateRefs, value)
}

/// Create id-aa-ets-revocationRefs unsigned attribute (CAdES-C).
pub fn complete_revocation_refs_attribute(
    refs: &crate::pki::cms::ets::CompleteRevocationRefs,
) -> Result<Attribute> {
    let value = Any::encode_from(refs)
        .map_err(|e| Error::Internal(format!("complete revocation refs encode: {e}")))?;
    attribute_with_value(OidId::AaEtsRevocationRefs, value)
}

/// Create id-aa-ets-certValues unsigned attribute (CAdES-X).
pub fn cert_values_attribute(values: &crate::pki::cms::ets::CertValues) -> Result<Attribute> {
    let value = Any::encode_from(values)
        .map_err(|e| Error::Internal(format!("cert values encode: {e}")))?;
    attribute_with_value(OidId::AaEtsCertValues, value)
}

/// Create id-aa-ets-revocationValues unsigned attribute (CAdES-X).
pub fn revocation_values_attribute(
    values: &crate::pki::cms::ets::RevocationValues,
) -> Result<Attribute> {
    let value = Any::encode_from(values)
        .map_err(|e| Error::Internal(format!("revocation values encode: {e}")))?;
    attribute_with_value(OidId::AaEtsRevocationValues, value)
}

/// Create id-aa-ets-archiveTimeStamp unsigned attribute (CAdES-A).
pub fn archive_time_stamp_token_attribute(
    token: &crate::pki::cms::types::ContentInfo,
) -> Result<Attribute> {
    let value = Any::encode_from(token)
        .map_err(|e| Error::Internal(format!("archive timestamp token encode: {e}")))?;
    attribute_with_value(OidId::AaEtsArchiveTimeStamp, value)
}

/// Create id-aa-signatureTimeStampToken unsigned attribute (CAdES-T).
pub fn signature_time_stamp_token_attribute(
    token: &crate::pki::cms::types::ContentInfo,
) -> Result<Attribute> {
    let value = Any::encode_from(token)
        .map_err(|e| Error::Internal(format!("timestamp token encode: {e}")))?;
    attribute_with_value(OidId::AaSignatureTimeStampToken, value)
}

/// Create id-aa-ets-escTimeStamp unsigned attribute (CAdES-X Type 1 / X-L Type 1).
pub fn esc_time_stamp_token_attribute(
    token: &crate::pki::cms::types::ContentInfo,
) -> Result<Attribute> {
    let value = Any::encode_from(token)
        .map_err(|e| Error::Internal(format!("esc timestamp token encode: {e}")))?;
    attribute_with_value(OidId::AaEtsEscTimeStamp, value)
}

/// Create id-aa-ets-certCRLTimestamp unsigned attribute (CAdES-X Type 2 / X-L Type 2).
pub fn cert_crl_timestamp_token_attribute(
    token: &crate::pki::cms::types::ContentInfo,
) -> Result<Attribute> {
    let value = Any::encode_from(token)
        .map_err(|e| Error::Internal(format!("cert/crl timestamp token encode: {e}")))?;
    attribute_with_value(OidId::AaEtsCertCrlTimestamp, value)
}

/// `sinfo_verify_signing_cert_v2`.
pub fn verify_signing_cert_v2(
    sinfo: &SignerInfo,
    ess_da: &DigestAdapter,
    cert: &Cert,
) -> Result<()> {
    let signed_attrs = sinfo
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::Unsupported("signer info missing signed attributes".into()))?;

    let attr = signed_attr_by_oid(signed_attrs, OidId::AaSigningCertificateV2)?
        .ok_or_else(|| Error::Unsupported("signing certificate v2 attribute missing".into()))?;

    let value = attr.values.get(0).ok_or_else(|| {
        Error::Unsupported("signing certificate v2 attribute has no value".into())
    })?;

    let signing_cert_v2 = value
        .decode_as::<SigningCertificateV2>()
        .map_err(|e| Error::Internal(format!("signing certificate v2 decode: {e}")))?;

    let cert_serial = cert
        .inner_certificate()
        .tbs_certificate
        .serial_number
        .clone();
    let ess_cert = signing_cert_v2
        .certs
        .iter()
        .find(|ess| ess.issuer_serial.serial_number == cert_serial)
        .ok_or(Error::VerifyFailed)?;

    let ess_aid = AlgorithmIdentifier::<Any>::from_der(ess_da.algorithm_der())
        .map_err(|e| Error::Internal(format!("ess digest aid decode: {e}")))?;
    if ess_cert.hash_algorithm != ess_aid {
        return Err(Error::InvalidParam(
            "signing certificate v2 digest algorithm mismatch".into(),
        ));
    }

    let cert_der = cert.encode()?;
    let mut hasher = ess_da.clone_state()?;
    hasher.update(&cert_der)?;
    let digest = hasher.finalize()?;
    if digest != ess_cert.cert_hash.as_bytes() {
        return Err(Error::VerifyFailed);
    }

    Ok(())
}
