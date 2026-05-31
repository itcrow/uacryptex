//! OCSP request engine (`ocsp_request_engine.c`).

use der::asn1::OctetString;
use der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;
use x509_ocsp::{CertId, OcspRequest, Request, Signature, TbsRequest};

use crate::pki::cert::Cert;
use crate::pki::crypto::{sign_raw_to_bitstring, DigestAdapter, SignAdapter, VerifyAdapter};
use crate::pki::ext::ext_create_nonce;
use crate::pki::ocsp::{
    issuer_id_hashes, BasicOcspResponse, OcspReq, OcspResp, OcspResponseStatus,
};
use crate::{Error, Result};

/// OCSP request generator context (`OcspRequestEngine`).
pub struct OcspRequestEngine {
    root_va: VerifyAdapter,
    ocsp_va: Option<VerifyAdapter>,
    requestor_sa: Option<SignAdapter>,
    digest_aid: Vec<u8>,
    is_nonce_present: bool,
    name_hash: Vec<u8>,
    key_hash: Vec<u8>,
    requests: Vec<Request>,
}

impl OcspRequestEngine {
    /// `eocspreq_alloc`.
    pub fn alloc(
        is_nonce_present: bool,
        root_va: &VerifyAdapter,
        ocsp_va: Option<&VerifyAdapter>,
        subject_sa: Option<&SignAdapter>,
        da: &DigestAdapter,
    ) -> Result<Self> {
        if !root_va.has_cert() {
            return Err(Error::InvalidParam(
                "root verify adapter has no certificate".into(),
            ));
        }

        if let Some(ocsp) = ocsp_va {
            let ocsp_cert = ocsp.cert()?;
            if !ocsp_cert.is_ocsp_responder()? {
                return Err(Error::InvalidParam(
                    "adapter is not OCSP certificate".into(),
                ));
            }
            ocsp_cert.verify(root_va)?;
        }

        if let Some(sa) = subject_sa {
            sa.cert()?.verify(root_va)?;
        }

        let root_cert = root_va.cert()?;
        let digest_aid = da.algorithm_der().to_vec();
        let (name_hash, key_hash) = issuer_id_hashes(root_cert, &digest_aid)?;

        Ok(Self {
            root_va: root_va.clone_state()?,
            ocsp_va: ocsp_va.map(|v| v.clone_state()).transpose()?,
            requestor_sa: subject_sa.map(|s| s.clone_state()).transpose()?,
            digest_aid,
            is_nonce_present,
            name_hash,
            key_hash,
            requests: Vec::new(),
        })
    }

    /// `eocspreq_add_sn`.
    pub fn add_serial(&mut self, serial: &[u8]) -> Result<()> {
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned::from_der(&self.digest_aid)
            .map_err(|e| Error::Internal(format!("digest aid decode: {e}")))?;
        let req_cert = CertId {
            hash_algorithm: algorithm,
            issuer_name_hash: OctetString::new(self.name_hash.as_slice())
                .map_err(|e| Error::Internal(format!("name hash: {e}")))?,
            issuer_key_hash: OctetString::new(self.key_hash.as_slice())
                .map_err(|e| Error::Internal(format!("key hash: {e}")))?,
            serial_number: SerialNumber::new(serial)
                .map_err(|e| Error::Internal(format!("serial number: {e}")))?,
        };
        self.requests.push(Request {
            req_cert,
            single_request_extensions: None,
        });
        Ok(())
    }

    /// `eocspreq_add_cert`.
    pub fn add_cert(&mut self, cert: &Cert) -> Result<()> {
        cert.verify(&self.root_va)?;
        self.add_serial(&cert.serial_number())
    }

    /// `eocspreq_generate`.
    pub fn generate(&self, nonce: Option<&[u8]>) -> Result<OcspReq> {
        let mut tbs = TbsRequest {
            version: Default::default(),
            requestor_name: None,
            request_list: self.requests.clone(),
            request_extensions: None,
        };

        if self.is_nonce_present {
            let rnd = nonce.ok_or_else(|| Error::InvalidParam("nonce is required".into()))?;
            let ext = ext_create_nonce(false, rnd)?;
            tbs.request_extensions = Some(vec![ext]);
        }

        let signed = self.requestor_sa.as_ref().is_some_and(|sa| sa.has_cert());

        if !signed {
            return Ok(OcspReq::from_inner(OcspRequest {
                tbs_request: tbs,
                optional_signature: None,
            }));
        }

        let sa = self.requestor_sa.as_ref().expect("checked above");
        let requestor_cert = sa.cert()?;
        tbs.requestor_name = Some(GeneralName::DirectoryName(
            requestor_cert
                .inner_certificate()
                .tbs_certificate
                .subject
                .clone(),
        ));

        let tbs_der = tbs
            .to_der()
            .map_err(|e| Error::Internal(format!("tbs request encode: {e}")))?;
        let sign_raw = sa.sign_data(&tbs_der)?;
        let sign_aid = sa.signature_algorithm_der();
        let signature = sign_raw_to_bitstring(sign_aid, &sign_raw)?;
        let signature_algorithm = x509_cert::spki::AlgorithmIdentifierOwned::from_der(sign_aid)
            .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;

        let mut certs = vec![requestor_cert.inner_certificate().clone()];
        if let Some(ocsp_va) = &self.ocsp_va {
            certs.push(ocsp_va.cert()?.inner_certificate().clone());
        }
        certs.push(self.root_va.cert()?.inner_certificate().clone());

        Ok(OcspReq::from_inner(OcspRequest {
            tbs_request: tbs,
            optional_signature: Some(Signature {
                signature_algorithm,
                signature,
                certs: Some(certs),
            }),
        }))
    }

    /// `eocspreq_validate_resp`.
    pub fn validate_response(
        &self,
        response: &OcspResp,
        current_time: i64,
        timeout_minutes: i32,
    ) -> Result<()> {
        if response.response_status() != OcspResponseStatus::Successful {
            return Err(Error::InvalidParam("ocsp response not successful".into()));
        }
        let bytes = response.response_bytes()?;
        if !bytes
            .response_type
            .to_string()
            .contains("1.3.6.1.5.5.7.48.1.1")
        {
            return Err(Error::Unsupported("unsupported OCSP response type".into()));
        }
        let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())
            .map_err(|e| Error::Internal(format!("basic ocsp response decode: {e}")))?;
        if timeout_minutes >= 0 {
            let produced = basic
                .tbs_response_data
                .produced_at
                .0
                .to_unix_duration()
                .as_secs() as i64;
            if current_time > produced + i64::from(timeout_minutes) * 60 {
                return Err(Error::InvalidParam("ocsp response timeout".into()));
            }
        }
        for single in &basic.tbs_response_data.responses {
            if let Some(next) = &single.next_update {
                let next_up = next.0.to_unix_duration().as_secs() as i64;
                if next_up < current_time {
                    return Err(Error::InvalidParam("ocsp next update expired".into()));
                }
            }
        }
        Ok(())
    }
}

/// `eocspreq_generate_from_cert`.
pub fn eocspreq_generate_from_cert(root_cert: &Cert, user_cert: &Cert) -> Result<OcspReq> {
    let da = DigestAdapter::init_default()?;
    let root_va = VerifyAdapter::init_by_cert(root_cert)?;
    let mut engine = OcspRequestEngine::alloc(true, &root_va, None, None, &da)?;
    engine.add_cert(user_cert)?;
    let nonce = vec![0u8; 20];
    engine.generate(Some(&nonce))
}
