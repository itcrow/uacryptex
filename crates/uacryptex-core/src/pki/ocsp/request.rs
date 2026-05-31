//! OCSP request API (`ocsp_request.c`).

use der::{Decode, Encode};
use x509_ocsp::{OcspRequest, Signature, TbsRequest};

use crate::pki::crypto::{sign_bitstring_to_raw, VerifyAdapter};
use crate::{Error, Result};

/// OCSP request wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspReq {
    inner: OcspRequest,
}

impl OcspReq {
    /// `ocspreq_alloc`.
    pub fn new() -> Self {
        Self {
            inner: OcspRequest {
                tbs_request: TbsRequest::default(),
                optional_signature: None,
            },
        }
    }

    /// `ocspreq_decode`.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let inner = OcspRequest::from_der(der)
            .map_err(|e| Error::Internal(format!("ocsp request decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `ocspreq_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("ocsp request encode: {e}")))
    }

    /// `ocspreq_get_tbsreq`.
    pub fn tbs_request(&self) -> &TbsRequest {
        &self.inner.tbs_request
    }

    /// `ocspreq_set_tbsreq`.
    pub fn set_tbs_request(&mut self, tbs: TbsRequest) {
        self.inner.tbs_request = tbs;
    }

    /// `ocspreq_get_sign`.
    pub fn optional_signature(&self) -> Option<&Signature> {
        self.inner.optional_signature.as_ref()
    }

    /// `ocspreq_set_sign`.
    pub fn set_optional_signature(&mut self, signature: Signature) {
        self.inner.optional_signature = Some(signature);
    }

    /// `ocspreq_has_sign`.
    pub fn has_signature(&self) -> bool {
        self.inner.optional_signature.is_some()
    }

    /// `ocspreq_verify`.
    pub fn verify(&self, adapter: &VerifyAdapter) -> Result<()> {
        if !self.has_signature() {
            return Err(Error::OcspReqNoSign);
        }
        let signature = self
            .inner
            .optional_signature
            .as_ref()
            .expect("checked above");
        let tbs_der = self
            .inner
            .tbs_request
            .to_der()
            .map_err(|e| Error::Internal(format!("tbs request encode: {e}")))?;
        let sign_aid = signature
            .signature_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?;
        let signature_raw = sign_bitstring_to_raw(&sign_aid, &signature.signature)?;
        adapter.verify_data(&tbs_der, &signature_raw)
    }

    pub(crate) fn from_inner(inner: OcspRequest) -> Self {
        Self { inner }
    }

    /// Underlying request.
    pub fn inner_request(&self) -> &OcspRequest {
        &self.inner
    }
}

impl Default for OcspReq {
    fn default() -> Self {
        Self::new()
    }
}
