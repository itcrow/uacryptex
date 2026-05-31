//! OCSP response engine (`ocsp_response_engine.c`).

use der::asn1::OctetString;
use der::{Decode, Encode};
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspGeneralizedTime, OcspResponse, OcspResponseStatus, Request,
    ResponderId, ResponseData, RevokedInfo, SingleResponse,
};

use crate::pki::crl::Crl;
use crate::pki::crypto::{sign_raw_to_bitstring, DigestAdapter, SignAdapter, VerifyAdapter};
use crate::pki::ext::object_identifier;
use crate::pki::ocsp::{digest_bytes, issuer_id_hashes, OcspReq, OcspResp};
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// Responder ID type (`ResponderIdType` in `ocsp_response_engine.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponderIdType {
    ByHashKey = 0,
    ByName = 1,
}

/// OCSP response generator (`OcspResponseEngine`).
pub struct OcspResponseEngine {
    root_va: VerifyAdapter,
    ocsp_sa: SignAdapter,
    responder_id: ResponderId,
    is_sign_required: bool,
    is_nextup_required: bool,
    is_crlreason_required: bool,
    crls: Vec<Crl>,
    name_hash: Vec<u8>,
    key_hash: Vec<u8>,
}

impl OcspResponseEngine {
    /// `eocspresp_alloc`.
    pub fn alloc(
        root_va: &VerifyAdapter,
        ocsp_sign: &SignAdapter,
        crls: &[Crl],
        da: &DigestAdapter,
        next_up_req: bool,
        crl_reason_req: bool,
        id_type: ResponderIdType,
    ) -> Result<Self> {
        if !root_va.has_cert() {
            return Err(Error::InvalidParam(
                "root adapter has no certificate".into(),
            ));
        }
        if !ocsp_sign.has_cert() {
            return Err(Error::InvalidParam(
                "sign adapter has no certificate".into(),
            ));
        }
        let ocsp_cert = ocsp_sign.cert()?;
        if !ocsp_cert.is_ocsp_responder()? {
            return Err(Error::InvalidParam(
                "sign adapter is not OCSP certificate".into(),
            ));
        }
        ocsp_cert.verify(root_va)?;
        for crl in crls {
            crl.verify(root_va)?;
        }

        let root_cert = root_va.cert()?;
        let digest_aid = da.algorithm_der();
        let (name_hash, key_hash) = issuer_id_hashes(root_cert, digest_aid)?;
        let responder_id = match id_type {
            ResponderIdType::ByHashKey => {
                let key_bytes = ocsp_cert
                    .inner_certificate()
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes();
                let key_hash = digest_bytes(digest_aid, key_bytes)?;
                ResponderId::ByKey(
                    OctetString::new(key_hash)
                        .map_err(|e| Error::Internal(format!("responder key hash: {e}")))?,
                )
            }
            ResponderIdType::ByName => ResponderId::ByName(
                ocsp_cert
                    .inner_certificate()
                    .tbs_certificate
                    .subject
                    .clone(),
            ),
        };

        Ok(Self {
            root_va: root_va.clone_state()?,
            ocsp_sa: ocsp_sign.clone_state()?,
            responder_id,
            is_sign_required: false,
            is_nextup_required: next_up_req,
            is_crlreason_required: crl_reason_req,
            crls: crls.to_vec(),
            name_hash,
            key_hash,
        })
    }

    /// `eocspresp_set_sign_required`.
    pub fn set_sign_required(&mut self, sign_required: bool) {
        self.is_sign_required = sign_required;
    }

    /// `eocspresp_set_crls`.
    pub fn set_crls(&mut self, crls: &[Crl]) -> Result<()> {
        if crls.is_empty() {
            return Err(Error::VerifyFailed);
        }
        for crl in crls {
            crl.verify(&self.root_va)?;
        }
        self.crls = crls.to_vec();
        Ok(())
    }

    /// `eocspresp_generate`.
    pub fn generate(
        &self,
        request: &OcspReq,
        req_va: &VerifyAdapter,
        current_time: i64,
    ) -> Result<OcspResp> {
        match self.try_generate_success(request, req_va, current_time) {
            Ok(resp) => Ok(resp),
            Err(Error::OcspReqNoSign) | Err(Error::InvalidParam(_)) | Err(Error::VerifyFailed) => {
                Ok(OcspResp::from_status(OcspResponseStatus::MalformedRequest))
            }
            Err(e) => Err(e),
        }
    }

    fn try_generate_success(
        &self,
        request: &OcspReq,
        req_va: &VerifyAdapter,
        current_time: i64,
    ) -> Result<OcspResp> {
        self.validate_request(request, req_va)?;
        let mut responses = Vec::with_capacity(request.tbs_request().request_list.len());
        for req in &request.tbs_request().request_list {
            responses.push(self.single_response(req, current_time)?);
        }

        let mut response_extensions = Vec::new();
        if let Some(exts) = &request.tbs_request().request_extensions {
            let nonce_oid = object_identifier(OidId::NonceExtension)?;
            for ext in exts {
                if ext.extn_id == nonce_oid {
                    response_extensions.push(ext.clone());
                }
            }
        }

        let response_data = ResponseData {
            version: Default::default(),
            responder_id: self.responder_id.clone(),
            produced_at: unix_to_ocsp_time(current_time)?,
            responses,
            response_extensions: if response_extensions.is_empty() {
                None
            } else {
                Some(response_extensions)
            },
        };

        let tbs_der = response_data
            .to_der()
            .map_err(|e| Error::Internal(format!("response data encode: {e}")))?;
        let sign_raw = self.ocsp_sa.sign_data(&tbs_der)?;
        let sign_aid = self.ocsp_sa.signature_algorithm_der();
        let signature = sign_raw_to_bitstring(sign_aid, &sign_raw)?;
        let signature_algorithm = x509_cert::spki::AlgorithmIdentifierOwned::from_der(sign_aid)
            .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;

        let mut certs = vec![self.ocsp_sa.cert()?.inner_certificate().clone()];
        certs.push(self.root_va.cert()?.inner_certificate().clone());

        let basic = BasicOcspResponse {
            tbs_response_data: response_data,
            signature_algorithm,
            signature,
            certs: Some(certs),
        };

        let ocsp_response = OcspResponse::successful(basic)
            .map_err(|e| Error::Internal(format!("ocsp successful response: {e}")))?;
        Ok(OcspResp::from_inner(ocsp_response))
    }

    fn validate_request(&self, request: &OcspReq, req_va: &VerifyAdapter) -> Result<()> {
        if !self.is_sign_required {
            return Ok(());
        }
        if !request.has_signature() {
            return Err(Error::OcspReqNoSign);
        }
        if request.tbs_request().requestor_name.is_none() {
            return Err(Error::InvalidParam("requestor name missing".into()));
        }
        request.verify(req_va).map_err(|e| match e {
            Error::VerifyFailed => Error::VerifyFailed,
            other => other,
        })
    }

    fn single_response(&self, req: &Request, current_time: i64) -> Result<SingleResponse> {
        if req.single_request_extensions.is_some() {
            return Err(Error::Unsupported(
                "single request extensions not supported".into(),
            ));
        }
        self.validate_cert_id(&req.req_cert)?;
        let serial = req.req_cert.serial_number.as_bytes();
        let revoked = self.find_revocation(serial);

        let cert_status;
        let single_extensions;
        if let Some(revoked) = revoked {
            let reason = crl_reason_from_revoked(&revoked);
            if self.is_crlreason_required && reason.is_none() {
                return Err(Error::InvalidParam("crl reason missing".into()));
            }
            cert_status = CertStatus::revoked(RevokedInfo {
                revocation_time: revoked.revocation_date.into(),
                revocation_reason: reason,
            });
            single_extensions = revoked.crl_entry_extensions.clone();
        } else {
            cert_status = CertStatus::good();
            single_extensions = None;
        }

        let this_update = self
            .last_update()
            .ok_or_else(|| Error::InvalidParam("no crl thisUpdate".into()))?;
        let next_update = self.nearest_update(current_time);
        if self.is_nextup_required && next_update.is_none() {
            return Err(Error::InvalidParam("no crl nextUpdate".into()));
        }

        Ok(SingleResponse {
            cert_id: req.req_cert.clone(),
            cert_status,
            this_update,
            next_update,
            single_extensions,
        })
    }

    fn validate_cert_id(&self, id: &x509_ocsp::CertId) -> Result<()> {
        if id.issuer_name_hash.as_bytes() != self.name_hash.as_slice() {
            return Err(Error::InvalidParam("invalid issuer name hash".into()));
        }
        if id.issuer_key_hash.as_bytes() != self.key_hash.as_slice() {
            return Err(Error::InvalidParam("invalid issuer key hash".into()));
        }
        Ok(())
    }

    fn find_revocation(&self, serial: &[u8]) -> Option<x509_cert::crl::RevokedCert> {
        let mut best: Option<(i64, x509_cert::crl::RevokedCert)> = None;
        for crl in &self.crls {
            if let Ok(revoked) = crl.revoked_cert_by_serial(serial) {
                let this_update = crl.this_update_unix();
                if best.as_ref().is_none_or(|(t, _)| this_update > *t) {
                    best = Some((this_update, revoked));
                }
            }
        }
        best.map(|(_, r)| r)
    }

    fn nearest_update(&self, current_time: i64) -> Option<OcspGeneralizedTime> {
        let mut best: Option<i64> = None;
        for crl in &self.crls {
            let Some(next) = crl.tbs().next_update else {
                continue;
            };
            let next_unix = next.to_unix_duration().as_secs() as i64;
            if next_unix > current_time {
                best = Some(match best {
                    None => next_unix,
                    Some(prev) => next_unix.min(prev),
                });
            }
        }
        best.and_then(|secs| unix_to_ocsp_time(secs).ok())
    }

    fn last_update(&self) -> Option<OcspGeneralizedTime> {
        let mut best: Option<i64> = None;
        for crl in &self.crls {
            let this = crl.this_update_unix();
            best = Some(best.map_or(this, |prev| prev.max(this)));
        }
        best.and_then(|secs| unix_to_ocsp_time(secs).ok())
    }
}

/// `eocspresp_form_malformed_req`.
pub fn eocspresp_form_malformed_req() -> OcspResp {
    OcspResp::from_status(OcspResponseStatus::MalformedRequest)
}

/// `eocspresp_form_internal_error`.
pub fn eocspresp_form_internal_error() -> OcspResp {
    OcspResp::from_status(OcspResponseStatus::InternalError)
}

/// `eocspresp_form_try_later`.
pub fn eocspresp_form_try_later() -> OcspResp {
    OcspResp::from_status(OcspResponseStatus::TryLater)
}

/// `eocspresp_form_unauthorized`.
pub fn eocspresp_form_unauthorized() -> OcspResp {
    OcspResp::from_status(OcspResponseStatus::Unauthorized)
}

fn crl_reason_from_revoked(revoked: &x509_cert::crl::RevokedCert) -> Option<CrlReason> {
    let exts = revoked.crl_entry_extensions.as_ref()?;
    let target = object_identifier(OidId::CrlReasonExtension).ok()?;
    for ext in exts {
        if ext.extn_id == target {
            return CrlReason::from_der(ext.extn_value.as_bytes()).ok();
        }
    }
    None
}

fn unix_to_ocsp_time(secs: i64) -> Result<OcspGeneralizedTime> {
    use std::time::{Duration, UNIX_EPOCH};
    OcspGeneralizedTime::try_from(UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
        .map_err(|e| Error::Internal(format!("ocsp generalized time: {e}")))
}
