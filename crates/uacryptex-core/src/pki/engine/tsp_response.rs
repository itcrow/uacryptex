//! TSP response engine (`tsp_response_engine.c`).

use std::time::Duration;

use der::asn1::{GeneralizedTime, Int, ObjectIdentifier};
use der::{Any, Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifier;
use x509_tsp::{TspVersion, TstInfo};

use crate::pki::cms::{ContentInfo, SignedDataEngine, SignerInfoEngine};
use crate::pki::crypto::{gost3411_algorithm_der, oid_str_under, DigestAdapter, SignAdapter};
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::pki::tsp::{DigestAlgorithmIdentifiers, PkiStatus, PkiStatusInfo, TspReq, TspResp};
use crate::{Error, Result};

/// Adapter pair for TSP signing (`AdaptersMap` entry).
pub struct TspAdapterEntry {
    pub digest: DigestAdapter,
    pub sign: SignAdapter,
}

/// TSP adapter map (`AdaptersMap`).
pub struct TspAdapterMap {
    entries: Vec<TspAdapterEntry>,
}

impl TspAdapterMap {
    /// `adapters_map_alloc`.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// `adapters_map_add`.
    pub fn add(&mut self, digest: DigestAdapter, sign: SignAdapter) {
        self.entries.push(TspAdapterEntry { digest, sign });
    }

    fn find_by_sign_parent(&self, parent: OidId) -> Option<&TspAdapterEntry> {
        self.entries.iter().find(|entry| {
            let sign_oid = entry.sign.signature_algorithm_der();
            let Ok(aid) = AlgorithmIdentifier::<Any>::from_der(sign_oid) else {
                return false;
            };
            oid_str_under(parent, &aid.oid.to_string())
        })
    }
}

impl Default for TspAdapterMap {
    fn default() -> Self {
        Self::new()
    }
}

/// `etspresp_generate`.
pub fn etspresp_generate(
    tsp_map: &TspAdapterMap,
    tsp_req: &[u8],
    serial_number: &Int,
    tsp_digest_aids: &DigestAlgorithmIdentifiers,
    current_time: i64,
) -> Result<TspResp> {
    let req = TspReq::decode(tsp_req)?;
    validate_digest_aid(req.message_imprint(), tsp_digest_aids)?;

    let (entry, granted_with_mods) = prepare_signer(&req, tsp_map)?;
    let tst_info = build_tst_info(&req, serial_number, current_time, entry)?;
    let tst_der = tst_info
        .to_der()
        .map_err(|e| Error::Internal(format!("TSTInfo encode: {e}")))?;

    let signer = SignerInfoEngine::new(&entry.sign, entry.digest.clone_state()?, None)?;
    let mut sd_engine = SignedDataEngine::new(signer);
    sd_engine.set_data(OidId::CtTstInfo, &tst_der, true)?;

    if req.cert_req() && entry.sign.has_cert() {
        sd_engine.add_cert(entry.sign.cert()?.clone())?;
    }

    let signed_data = sd_engine.generate()?;
    let token_der = signed_data.encode_content_info()?;
    let token = ContentInfo::from_der(&token_der).map_err(|e| {
        Error::Internal(format!("timestamp token decode: {e}"))
    })?;

    let status = PkiStatusInfo {
        status: if granted_with_mods {
            PkiStatus::GrantedWithMods
        } else {
            PkiStatus::Accepted
        },
    };

    let mut resp = TspResp::new();
    resp.set_status(status);
    resp.set_time_stamp_token(token);
    Ok(resp)
}

fn validate_digest_aid(
    imprint: &x509_tsp::MessageImprint,
    tsp_digest_aids: &DigestAlgorithmIdentifiers,
) -> Result<()> {
    let imprint_der = imprint
        .hash_algorithm
        .to_der()
        .map_err(|e| Error::Internal(format!("imprint aid encode: {e}")))?;
    for aid in tsp_digest_aids {
        let aid_der = aid
            .to_der()
            .map_err(|e| Error::Internal(format!("digest aid encode: {e}")))?;
        if aid_der == imprint_der {
            return Ok(());
        }
    }
    Err(Error::DifferentDigestAlg)
}

fn prepare_signer<'a>(
    req: &TspReq,
    tsp_map: &'a TspAdapterMap,
) -> Result<(&'a TspAdapterEntry, bool)> {
    let policy_any = req.policy().ok();
    let parent = if policy_any.is_none() {
        OidId::PkiDstu4145PbLe
    } else {
        let policy_oid = policy_any
            .as_ref()
            .and_then(|any| any.decode_as::<ObjectIdentifier>().ok());
        match policy_oid {
            Some(oid) if oid_matches(OidId::PkiTspPolicyDstuPb, &oid) => OidId::PkiDstu4145PbLe,
            Some(oid) if oid_matches(OidId::PkiTspPolicyDstuOnb, &oid) => OidId::PkiDstu4145OnbLe,
            _ => return Err(Error::UnsupportedSignAlg),
        }
    };

    let granted_with_mods = policy_any.is_none();
    let entry = tsp_map
        .find_by_sign_parent(parent)
        .ok_or(Error::UnsupportedSignAlg)?;
    Ok((entry, granted_with_mods))
}

fn oid_matches(id: OidId, oid: &ObjectIdentifier) -> bool {
    object_identifier(id)
        .map(|expected| &expected == oid)
        .unwrap_or(false)
}

fn build_tst_info(
    req: &TspReq,
    serial_number: &Int,
    current_time: i64,
    entry: &TspAdapterEntry,
) -> Result<TstInfo> {
    let policy = req
        .policy()?
        .decode_as::<ObjectIdentifier>()
        .map_err(|e| Error::Internal(format!("policy decode: {e}")))?;
    let nonce = req.nonce()?;
    let gen_time = unix_to_generalized_time(current_time)?;

    let mut tst = TstInfo {
        version: TspVersion::V1,
        policy,
        message_imprint: req.message_imprint().clone(),
        serial_number: serial_number.clone(),
        gen_time,
        accuracy: None,
        ordering: false,
        nonce: Some(nonce),
        tsa: None,
        extensions: None,
    };

    if entry.sign.has_cert() {
        let cert = entry.sign.cert()?;
        let subject = cert.inner_certificate().tbs_certificate.subject.clone();
        tst.tsa = Some(GeneralName::DirectoryName(subject));
    }

    Ok(tst)
}

fn unix_to_generalized_time(secs: i64) -> Result<GeneralizedTime> {
    GeneralizedTime::from_unix_duration(Duration::from_secs(secs.max(0) as u64))
        .map_err(|e| Error::Internal(format!("generalized time: {e}")))
}

/// Convenience for engine tests: default supported digest list (GOST 34.311).
pub fn default_tsp_digest_aids() -> Result<DigestAlgorithmIdentifiers> {
    Ok(vec![AlgorithmIdentifier::from_der(gost3411_algorithm_der()).map_err(
        |e| Error::Internal(format!("gost3411 aid decode: {e}")),
    )?])
}
