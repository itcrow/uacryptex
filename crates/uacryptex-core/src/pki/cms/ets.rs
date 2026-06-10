//! ETSI CAdES-C reference types (CompleteCertificateRefs, CompleteRevocationRefs).

use std::time::Duration;

use der::asn1::{Int, OctetString, UtcTime};
use der::{Any, Decode, Encode, Sequence, ValueOrd};
use x509_cert::certificate::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::name::Name;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::time::Time;
use x509_ocsp::BasicOcspResponse;

use crate::pki::cert::Cert;
use crate::pki::crl::Crl;
use crate::pki::crypto::DigestAdapter;
use crate::pki::ocsp::OcspResp;
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// `OtherHashAlgAndValue ::= SEQUENCE { hashAlgorithm, hashValue }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct OtherHashAlgAndValue {
    pub hash_algorithm: AlgorithmIdentifier<Any>,
    pub hash_value: OctetString,
}

/// `OtherCertID ::= SEQUENCE { otherCertHash OtherHash, issuerSerial OPTIONAL }`
///
/// Cryptonite uses the `otherHash` CHOICE alternative (SEQUENCE), encoded directly.
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct OtherCertId {
    pub other_cert_hash: OtherHashAlgAndValue,
}

/// `CompleteCertificateRefs ::= SEQUENCE OF OtherCertID`
pub type CompleteCertificateRefs = Vec<OtherCertId>;

/// `CrlIdentifier ::= SEQUENCE { crlissuer Name, crlIssuedTime UTCTime, crlNumber OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CrlIdentifier {
    pub crlissuer: Name,
    pub crl_issued_time: UtcTime,
    pub crl_number: Option<Int>,
}

/// `CrlValidatedID ::= SEQUENCE { crlHash OtherHash, crlIdentifier OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CrlValidatedId {
    pub crl_hash: OtherHashAlgAndValue,
    pub crl_identifier: Option<CrlIdentifier>,
}

/// `CRLListID ::= SEQUENCE { crls SEQUENCE OF CrlValidatedID }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CrlListId {
    pub crls: Vec<CrlValidatedId>,
}

/// `CrlOcspRef ::= SEQUENCE { crlids OPTIONAL, ocspids OPTIONAL, otherRev OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct CrlOcspRef {
    pub crlids: Option<CrlListId>,
    pub ocspids: Option<Any>,
    pub other_rev: Option<Any>,
}

/// `CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef`
pub type CompleteRevocationRefs = Vec<CrlOcspRef>;

/// `CertValues` attribute payload — `Certificates ::= SEQUENCE OF Certificate`.
pub type CertValues = Vec<Certificate>;

/// `RevocationValues ::= SEQUENCE { crlVals, ocspVals, otherRevVals }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevocationValues {
    #[asn1(context_specific = "0", optional = "true", constructed = "true")]
    pub crl_vals: Option<Vec<CertificateList>>,
    #[asn1(context_specific = "1", optional = "true", constructed = "true")]
    pub ocsp_vals: Option<Vec<BasicOcspResponse>>,
    #[asn1(context_specific = "2", optional = "true")]
    pub other_rev_vals: Option<Any>,
}

fn hash_alg_and_value(da: &DigestAdapter, data: &[u8]) -> Result<OtherHashAlgAndValue> {
    let hash_algorithm = {
        let aid = da.algorithm_der();
        AlgorithmIdentifier::<Any>::from_der(aid)
            .map_err(|e| Error::Internal(format!("ets digest aid decode: {e}")))?
    };
    let mut hasher = da.clone_state()?;
    hasher.update(data)?;
    let digest = hasher.finalize()?;
    let hash_value = OctetString::new(digest)
        .map_err(|e| Error::Internal(format!("ets hash octet string: {e}")))?;
    Ok(OtherHashAlgAndValue {
        hash_algorithm,
        hash_value,
    })
}

/// Build `OtherCertID` for a certificate (hash of full cert DER).
pub fn other_cert_id(cert: &Cert, da: &DigestAdapter) -> Result<OtherCertId> {
    let cert_der = cert.encode()?;
    Ok(OtherCertId {
        other_cert_hash: hash_alg_and_value(da, &cert_der)?,
    })
}

fn crl_issued_time(crl: &Crl) -> Result<UtcTime> {
    match &crl.tbs().this_update {
        Time::UtcTime(ut) => Ok(*ut),
        Time::GeneralTime(gt) => {
            let secs = gt.to_unix_duration().as_secs();
            UtcTime::from_unix_duration(Duration::from_secs(secs))
                .map_err(|e| Error::Internal(format!("crl thisUpdate utc: {e}")))
        }
    }
}

/// Build `CrlValidatedID` for a CRL (hash of full CRL DER + optional identifier).
pub fn crl_validated_id(crl: &Crl, da: &DigestAdapter) -> Result<CrlValidatedId> {
    let crl_der = crl.encode()?;
    let crl_hash = hash_alg_and_value(da, &crl_der)?;

    let crl_number = crl
        .crl_number()
        .ok()
        .and_then(|bytes| Int::new(&bytes).ok());
    let crl_identifier = Some(CrlIdentifier {
        crlissuer: crl.tbs().issuer.clone(),
        crl_issued_time: crl_issued_time(crl)?,
        crl_number,
    });

    Ok(CrlValidatedId {
        crl_hash,
        crl_identifier,
    })
}

/// Build `CompleteCertificateRefs` for one certificate.
pub fn complete_certificate_refs(
    cert: &Cert,
    da: &DigestAdapter,
) -> Result<CompleteCertificateRefs> {
    Ok(vec![other_cert_id(cert, da)?])
}

/// Build `CompleteRevocationRefs` for one CRL.
pub fn complete_revocation_refs(crl: &Crl, da: &DigestAdapter) -> Result<CompleteRevocationRefs> {
    let validated = crl_validated_id(crl, da)?;
    Ok(vec![CrlOcspRef {
        crlids: Some(CrlListId {
            crls: vec![validated],
        }),
        ocspids: None,
        other_rev: None,
    }])
}

/// Build `CertValues` for one certificate (full DER embedded).
pub fn cert_values(cert: &Cert) -> Result<CertValues> {
    Ok(vec![cert.inner_certificate().clone()])
}

/// Build `RevocationValues` with one OCSP response (`BasicOCSPResponse` inside).
pub fn revocation_values_from_ocsp(ocsp_der: &[u8]) -> Result<RevocationValues> {
    let resp = OcspResp::decode(ocsp_der)?;
    let basic = resp.basic_ocsp_response()?;
    Ok(RevocationValues {
        crl_vals: None,
        ocsp_vals: Some(vec![basic]),
        other_rev_vals: None,
    })
}

/// Build `RevocationValues` with CRLs only (reserved for CAdES-X-L).
#[allow(dead_code)]
pub fn revocation_values_from_crls(crls: &[Crl]) -> Result<RevocationValues> {
    let crl_vals = crls
        .iter()
        .map(|crl| {
            CertificateList::from_der(&crl.encode()?)
                .map_err(|e| Error::Internal(format!("crl list decode: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(RevocationValues {
        crl_vals: Some(crl_vals),
        ocsp_vals: None,
        other_rev_vals: None,
    })
}

/// Message imprint for id-aa-ets-escTimeStamp (CAdES-X Type 1 / X-L Type 1), RFC 5126 §6.3.5.
pub fn cades_c_timestamp_imprint(
    container: &crate::pki::cms::signed_data::SignedDataContainer,
    signer_index: usize,
) -> Result<Vec<u8>> {
    use crate::pki::cms::signer_info::{signature_octets, unsigned_attr_imprint};

    let inner = container.inner();
    let sinfo = inner
        .signer_info(signer_index)
        .ok_or_else(|| Error::InvalidParam("signer info index out of bounds".into()))?;

    let sig_alg = sinfo
        .signature_algorithm
        .to_der()
        .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?;
    let mut imprint = signature_octets(&sinfo.signature, &sig_alg)?;

    let unsigned = sinfo.unsigned_attrs.as_ref().ok_or_else(|| {
        Error::InvalidParam("CAdES-C refs required for escTimeStamp imprint".into())
    })?;

    if let Some(bytes) = unsigned_attr_imprint(unsigned, OidId::AaSignatureTimeStampToken)? {
        imprint.extend_from_slice(&bytes);
    }
    let cert_refs = unsigned_attr_imprint(unsigned, OidId::AaEtsCertificateRefs)?
        .ok_or_else(|| Error::InvalidParam("missing complete-certificate-references".into()))?;
    imprint.extend_from_slice(&cert_refs);
    let rev_refs = unsigned_attr_imprint(unsigned, OidId::AaEtsRevocationRefs)?
        .ok_or_else(|| Error::InvalidParam("missing complete-revocation-references".into()))?;
    imprint.extend_from_slice(&rev_refs);

    Ok(imprint)
}

/// Message imprint for id-aa-ets-certCRLTimestamp (CAdES-X Type 2 / X-L Type 2), RFC 5126 §6.3.6.
pub fn cades_refs_timestamp_imprint(
    container: &crate::pki::cms::signed_data::SignedDataContainer,
    signer_index: usize,
) -> Result<Vec<u8>> {
    use crate::pki::cms::signer_info::unsigned_attr_imprint;

    let inner = container.inner();
    let sinfo = inner
        .signer_info(signer_index)
        .ok_or_else(|| Error::InvalidParam("signer info index out of bounds".into()))?;

    let unsigned = sinfo.unsigned_attrs.as_ref().ok_or_else(|| {
        Error::InvalidParam("CAdES-C refs required for certCRLTimestamp imprint".into())
    })?;

    let cert_refs = unsigned_attr_imprint(unsigned, OidId::AaEtsCertificateRefs)?
        .ok_or_else(|| Error::InvalidParam("missing complete-certificate-references".into()))?;
    let rev_refs = unsigned_attr_imprint(unsigned, OidId::AaEtsRevocationRefs)?
        .ok_or_else(|| Error::InvalidParam("missing complete-revocation-references".into()))?;

    let mut imprint = cert_refs;
    imprint.extend_from_slice(&rev_refs);
    Ok(imprint)
}

/// Build archive timestamp message imprint (ETSI CAdES-A order for present attributes).
pub fn archive_timestamp_imprint(
    container: &crate::pki::cms::signed_data::SignedDataContainer,
    signer_index: usize,
) -> Result<Vec<u8>> {
    use crate::pki::cms::signer_info::{
        signature_octets, signed_attributes_der, unsigned_attr_value_bytes,
    };

    let inner = container.inner();
    let sinfo = inner
        .signer_info(signer_index)
        .ok_or_else(|| Error::InvalidParam("signer info index out of bounds".into()))?;

    let mut imprint = inner.encap_content_info.content_bytes()?;

    if let Some(attrs) = &sinfo.signed_attrs {
        imprint.extend_from_slice(&signed_attributes_der(attrs)?);
    }

    let sig_alg = sinfo
        .signature_algorithm
        .to_der()
        .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?;
    imprint.extend_from_slice(&signature_octets(&sinfo.signature, &sig_alg)?);

    if let Some(unsigned) = &sinfo.unsigned_attrs {
        for oid in [
            OidId::AaSignatureTimeStampToken,
            OidId::AaEtsCertificateRefs,
            OidId::AaEtsRevocationRefs,
            OidId::AaEtsCertValues,
            OidId::AaEtsRevocationValues,
            OidId::AaEtsEscTimeStamp,
            OidId::AaEtsCertCrlTimestamp,
        ] {
            if let Some(bytes) = unsigned_attr_value_bytes(unsigned, oid)? {
                imprint.extend_from_slice(&bytes);
            }
        }
    }

    Ok(imprint)
}
