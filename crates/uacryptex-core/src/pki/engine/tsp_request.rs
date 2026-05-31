//! TSP request engine (`tsp_request_engine.c`).

use der::asn1::{Int, ObjectIdentifier};
use der::Decode;
use x509_cert::spki::AlgorithmIdentifier;
use x509_tsp::{MessageImprint, TspVersion};

use crate::pki::crypto::gost3411_algorithm_der;
use crate::pki::crypto::DigestAdapter;
use crate::pki::tsp::TspReq;
use crate::{Error, Result};

/// `etspreq_generate_from_hash`.
pub fn etspreq_generate_from_hash(
    digest_aid: &AlgorithmIdentifier<der::Any>,
    hash: &[u8],
    rnd: Option<&[u8]>,
    policy: &ObjectIdentifier,
    cert_req: bool,
) -> Result<TspReq> {
    let hashed_message = der::asn1::OctetString::new(hash)
        .map_err(|e| Error::Internal(format!("message hash: {e}")))?;
    let mut req = TspReq::from_v1(x509_tsp::TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: digest_aid.clone(),
            hashed_message,
        },
        req_policy: Some(*policy),
        nonce: None,
        cert_req,
        extensions: None,
    })?;

    if let Some(rnd_bytes) = rnd {
        let nonce = Int::new(rnd_bytes).map_err(|e| Error::Internal(format!("nonce: {e}")))?;
        req.set_nonce(&nonce)?;
    } else {
        req.generate_nonce()?;
    }

    Ok(req)
}

/// `etspreq_generate`.
pub fn etspreq_generate(
    da: &DigestAdapter,
    msg: &[u8],
    rnd: Option<&[u8]>,
    policy: &ObjectIdentifier,
    cert_req: bool,
) -> Result<TspReq> {
    let digest_aid: AlgorithmIdentifier<der::Any> =
        AlgorithmIdentifier::from_der(da.algorithm_der())
            .map_err(|e| Error::Internal(format!("digest aid decode: {e}")))?;
    let mut adapter = da.clone_state()?;
    adapter.update(msg)?;
    let hash = adapter.finalize()?;
    etspreq_generate_from_hash(&digest_aid, &hash, rnd, policy, cert_req)
}

/// `etspreq_generate_from_gost34311`.
pub fn etspreq_generate_from_gost34311(
    hash: &[u8],
    policy: &str,
    cert_req: bool,
) -> Result<TspReq> {
    let digest_aid: AlgorithmIdentifier<der::Any> =
        AlgorithmIdentifier::from_der(gost3411_algorithm_der())
            .map_err(|e| Error::Internal(format!("gost3411 aid decode: {e}")))?;
    let policy_oid =
        ObjectIdentifier::new(policy).map_err(|e| Error::Internal(format!("policy oid: {e}")))?;
    etspreq_generate_from_hash(&digest_aid, hash, None, &policy_oid, cert_req)
}
