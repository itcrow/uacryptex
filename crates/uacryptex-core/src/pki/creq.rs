//! PKCS#10 certification request (`certification_request.c`).

use der::{Decode, Encode};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::request::{CertReq, CertReqInfo, ExtensionReq};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::pki::crypto::SignAdapter;
use crate::pki::crypto::VerifyAdapter;
use crate::pki::crypto::{sign_bitstring_to_raw, sign_raw_to_bitstring};
use crate::{Error, Result};

/// `creq_init_by_adapter`.
pub fn creq_init_by_adapter(info: CertReqInfo, adapter: &SignAdapter) -> Result<CertReq> {
    let info_der = info
        .to_der()
        .map_err(|e| Error::Internal(format!("CertReqInfo encode: {e}")))?;
    let signature_raw = adapter.sign_data(&info_der)?;
    let algorithm = signature_algorithm_without_params(adapter.signature_algorithm_der())?;
    let signature = sign_raw_to_bitstring(adapter.signature_algorithm_der(), &signature_raw)?;
    Ok(CertReq {
        info,
        algorithm,
        signature,
    })
}

/// `creq_verify`.
pub fn creq_verify(request: &CertReq, adapter: &VerifyAdapter) -> Result<()> {
    let info_der = request
        .info
        .to_der()
        .map_err(|e| Error::Internal(format!("CertReqInfo encode: {e}")))?;
    let sign_aid = request
        .algorithm
        .to_der()
        .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?;
    let signature_raw = sign_bitstring_to_raw(&sign_aid, &request.signature)?;
    adapter.verify_data(&info_der, &signature_raw)
}

fn signature_algorithm_without_params(sign_aid_der: &[u8]) -> Result<AlgorithmIdentifierOwned> {
    use der::asn1::Any;
    use x509_cert::spki::AlgorithmIdentifier;
    let mut aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(sign_aid_der)
        .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;
    aid.parameters = None;
    AlgorithmIdentifierOwned::from_der(
        &aid.to_der()
            .map_err(|e| Error::Internal(format!("signature aid encode: {e}")))?,
    )
    .map_err(|e| Error::Internal(format!("signature aid owned decode: {e}")))
}

/// Build PKCS#10 attributes with extensionRequest wrapping the given extensions.
pub fn cert_req_attributes_from_extensions(
    extensions: Vec<x509_cert::ext::Extension>,
) -> Result<Attributes> {
    let attr: Attribute = ExtensionReq(extensions)
        .try_into()
        .map_err(|e| Error::Internal(format!("extensionRequest attribute: {e}")))?;
    Attributes::try_from(vec![attr])
        .map_err(|e| Error::Internal(format!("cert request attributes: {e}")))
}

/// Decode SPKI from DER into the owned PKCS#10 type.
pub fn cert_req_public_key_from_spki(spki_der: &[u8]) -> Result<SubjectPublicKeyInfoOwned> {
    SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| Error::Internal(format!("spki decode: {e}")))
}

/// Re-export x509-cert request types used by callers.
pub use x509_cert::request::{
    CertReq as CertificationRequest, CertReqInfo as CertificationRequestInfo,
};
