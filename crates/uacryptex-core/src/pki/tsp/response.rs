//! TSP response API (`tsp_response.c`).

use der::{Decode, Encode};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cms::ContentInfo;
use crate::pki::cms::SignedDataContainer;
use crate::pki::crypto::{DigestAdapter, VerifyAdapter};
use crate::pki::tsp::status::PkiStatusInfo;
use crate::{Error, Result};

/// `TimeStampResp` wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TspResp {
    status: PkiStatusInfo,
    time_stamp_token: Option<ContentInfo>,
}

impl TspResp {
    /// `tsresp_alloc`.
    pub fn new() -> Self {
        Self {
            status: PkiStatusInfo {
                status: crate::pki::tsp::status::PkiStatus::Accepted,
            },
            time_stamp_token: None,
        }
    }

    /// `tsresp_decode`.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let inner = TimeStampRespInner::from_der(der)
            .map_err(|e| Error::Internal(format!("tsp response decode: {e}")))?;
        Ok(Self {
            status: inner.status,
            time_stamp_token: inner.time_stamp_token,
        })
    }

    /// `tsresp_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        TimeStampRespInner {
            status: self.status.clone(),
            time_stamp_token: self.time_stamp_token.clone(),
        }
        .to_der()
        .map_err(|e| Error::Internal(format!("tsp response encode: {e}")))
    }

    /// `tsresp_get_status`.
    pub fn status(&self) -> &PkiStatusInfo {
        &self.status
    }

    /// `tsresp_set_status`.
    pub fn set_status(&mut self, status: PkiStatusInfo) {
        self.status = status;
    }

    /// `tsresp_get_ts_token`.
    pub fn time_stamp_token(&self) -> Result<ContentInfo> {
        self.time_stamp_token
            .clone()
            .ok_or(Error::TspRespNoToken)
    }

    /// `tsresp_set_ts_token`.
    pub fn set_time_stamp_token(&mut self, token: ContentInfo) {
        self.time_stamp_token = Some(token);
    }

    /// `tsresp_verify`.
    pub fn verify(&self, da: &DigestAdapter, va: &VerifyAdapter) -> Result<()> {
        let token_der = self.time_stamp_token()?.to_der().map_err(|e| {
            Error::Internal(format!("timestamp token encode: {e}"))
        })?;
        let sdata = SignedDataContainer::decode(&token_der)?;
        sdata.verify_internal_data(da, va, 0)
    }
}

impl Default for TspResp {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, der::Sequence)]
struct TimeStampRespInner {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<ContentInfo>,
}

/// Supported digest algorithms for TSP response generation (`DigestAlgorithmIdentifiers`).
pub type DigestAlgorithmIdentifiers = Vec<AlgorithmIdentifier<der::Any>>;
