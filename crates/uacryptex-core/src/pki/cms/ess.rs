//! ESS types for SigningCertificateV2 (RFC 5035).

use der::asn1::OctetString;
use der::{Any, Decode, Sequence, ValueOrd};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cert::Cert;
use crate::pki::crypto::DigestAdapter;
use crate::{Error, Result};

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber, ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct IssuerSerial {
    pub issuer: GeneralNames,
    pub serial_number: SerialNumber,
}

/// `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm, certHash, issuerSerial }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct EssCertIdV2 {
    pub hash_algorithm: AlgorithmIdentifier<Any>,
    pub cert_hash: OctetString,
    pub issuer_serial: IssuerSerial,
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct SigningCertificateV2 {
    pub certs: Vec<EssCertIdV2>,
}

/// Build ESSCertIDv2 for `SigningCertificateV2` attribute (`create_ess_cert_id`).
pub fn ess_cert_id_v2(cert: &Cert, ess_da: &DigestAdapter) -> Result<EssCertIdV2> {
    let hash_algorithm = {
        let aid = ess_da.algorithm_der();
        AlgorithmIdentifier::<Any>::from_der(aid)
            .map_err(|e| Error::Internal(format!("ess digest aid decode: {e}")))?
    };

    let cert_der = cert.encode()?;
    let mut hasher = ess_da.clone_state()?;
    hasher.update(&cert_der)?;
    let digest = hasher.finalize()?;
    let cert_hash = OctetString::new(digest).map_err(|e| {
        Error::Internal(format!("ess cert hash octet string: {e}"))
    })?;

    let issuer = vec![GeneralName::DirectoryName(
        cert.inner_certificate().tbs_certificate.issuer.clone(),
    )];
    let serial_number = cert.inner_certificate().tbs_certificate.serial_number.clone();

    Ok(EssCertIdV2 {
        hash_algorithm,
        cert_hash,
        issuer_serial: IssuerSerial {
            issuer,
            serial_number,
        },
    })
}

pub fn signing_certificate_v2(cert: &Cert, ess_da: &DigestAdapter) -> Result<SigningCertificateV2> {
    let ess = ess_cert_id_v2(cert, ess_da)?;
    Ok(SigningCertificateV2 {
        certs: vec![ess],
    })
}
