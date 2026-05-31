//! TSP request API (`tsp_request.c`).

use std::time::{SystemTime, UNIX_EPOCH};

use der::asn1::{Int, ObjectIdentifier};
use der::{Any, Decode, Encode, Sequence};
use x509_tsp::MessageImprint;

use crate::{Error, Result};

/// `TimeStampReq` wrapper (accepts legacy version 0 fixtures).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TspReq {
    inner: TimeStampReqInner,
}

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct TimeStampReqInner {
    version: Int,
    message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    req_policy: Option<Any>,
    #[asn1(optional = "true")]
    nonce: Option<Int>,
    #[asn1(default = "Default::default")]
    cert_req: bool,
}

impl TspReq {
    /// `tsreq_alloc`.
    pub fn new() -> Self {
        Self {
            inner: TimeStampReqInner {
                version: Int::new(&[1]).expect("version 1"),
                message_imprint: MessageImprint {
                    hash_algorithm: x509_cert::spki::AlgorithmIdentifier {
                        oid: der::asn1::ObjectIdentifier::new("1.2.804.2.1.1.1.1.2.1")
                            .expect("gost3411 oid"),
                        parameters: None,
                    },
                    hashed_message: der::asn1::OctetString::new([]).expect("empty hash"),
                },
                req_policy: None,
                nonce: None,
                cert_req: false,
            },
        }
    }

    /// `tsreq_decode`.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let inner = TimeStampReqInner::from_der(der)
            .map_err(|e| Error::Internal(format!("tsp request decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `tsreq_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("tsp request encode: {e}")))
    }

    /// `tsreq_get_message`.
    pub fn message_imprint(&self) -> &MessageImprint {
        &self.inner.message_imprint
    }

    /// `tsreq_set_message`.
    pub fn set_message_imprint(&mut self, imprint: MessageImprint) {
        self.inner.message_imprint = imprint;
    }

    /// `tsreq_get_policy`.
    pub fn policy(&self) -> Result<Any> {
        self.inner.req_policy.clone().ok_or(Error::TspReqNoPolicy)
    }

    /// `tsreq_set_policy`.
    pub fn set_policy(&mut self, policy: &ObjectIdentifier) -> Result<()> {
        let policy_der = policy
            .to_der()
            .map_err(|e| Error::Internal(format!("policy encode: {e}")))?;
        self.inner.req_policy = Some(
            Any::from_der(&policy_der).map_err(|e| Error::Internal(format!("policy any: {e}")))?,
        );
        Ok(())
    }

    /// `tsreq_set_policy` from raw TSAPolicyId bytes.
    pub fn set_policy_any(&mut self, policy: Any) {
        self.inner.req_policy = Some(policy);
    }

    /// `tsreq_get_nonce`.
    pub fn nonce(&self) -> Result<Int> {
        self.inner.nonce.clone().ok_or(Error::TspReqNoNonce)
    }

    /// `tsreq_set_nonce`.
    pub fn set_nonce(&mut self, nonce: &Int) -> Result<()> {
        if nonce.as_bytes().is_empty() {
            return Err(Error::InvalidParam("nonce is empty".into()));
        }
        self.inner.nonce = Some(nonce.clone());
        Ok(())
    }

    /// `tsreq_generate_nonce`.
    pub fn generate_nonce(&mut self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Internal(format!("system time: {e}")))?;
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&now.as_secs().to_le_bytes());
        bytes.extend_from_slice(&(now.subsec_nanos() as u64).to_le_bytes());
        self.inner.nonce =
            Some(Int::new(&bytes).map_err(|e| Error::Internal(format!("nonce integer: {e}")))?);
        Ok(())
    }

    /// `tsreq_get_cert_req`.
    pub fn cert_req(&self) -> bool {
        self.inner.cert_req
    }

    /// `tsreq_set_cert_req`.
    pub fn set_cert_req(&mut self, cert_req: bool) {
        self.inner.cert_req = cert_req;
    }

    /// `tsreq_get_version`.
    pub fn version(&self) -> Int {
        self.inner.version.clone()
    }

    pub(crate) fn from_v1(req: x509_tsp::TimeStampReq) -> Result<Self> {
        Ok(Self {
            inner: TimeStampReqInner {
                version: Int::new(&[1]).map_err(|e| Error::Internal(format!("version: {e}")))?,
                message_imprint: req.message_imprint,
                req_policy: req.req_policy.map(|oid| {
                    Any::from_der(&oid.to_der().expect("policy oid encode")).expect("policy any")
                }),
                nonce: req.nonce,
                cert_req: req.cert_req,
            },
        })
    }
}

impl Default for TspReq {
    fn default() -> Self {
        Self::new()
    }
}
