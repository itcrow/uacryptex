//! OCSP response API (`ocsp_response.c`).

use der::{Decode, Encode};
use x509_cert::ext::pkix::CrlReason;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId, ResponseBytes};

use crate::pki::cert::Cert;
use crate::pki::crypto::{sign_bitstring_to_raw, VerifyAdapter};
use crate::{Error, Result};

/// Parsed OCSP certificate status (`OcspCertStatus` in `ocsp_response.h`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspCertStatus {
    pub serial_number: Vec<u8>,
    pub status: &'static str,
    pub revocation_time: i64,
    pub revocation_reason: Option<String>,
}

/// OCSP response wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspResp {
    inner: OcspResponse,
}

impl OcspResp {
    /// `ocspresp_alloc`.
    pub fn new() -> Self {
        Self {
            inner: OcspResponse {
                response_status: OcspResponseStatus::Successful,
                response_bytes: None,
            },
        }
    }

    /// `ocspresp_decode`.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let inner = OcspResponse::from_der(der)
            .map_err(|e| Error::Internal(format!("ocsp response decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `ocspresp_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("ocsp response encode: {e}")))
    }

    /// `ocspresp_get_status`.
    pub fn response_status(&self) -> OcspResponseStatus {
        self.inner.response_status
    }

    /// `ocspresp_set_status`.
    pub fn set_response_status(&mut self, status: OcspResponseStatus) {
        self.inner.response_status = status;
    }

    /// `ocspresp_get_response_bytes`.
    pub fn response_bytes(&self) -> Result<ResponseBytes> {
        self.inner
            .response_bytes
            .clone()
            .ok_or(Error::OcspRespNoBytes)
    }

    /// `ocspresp_set_response_bytes`.
    pub fn set_response_bytes(&mut self, bytes: ResponseBytes) {
        self.inner.response_bytes = Some(bytes);
    }

    /// `ocspresp_get_certs`.
    pub fn embedded_certs(&self) -> Result<Vec<Cert>> {
        let basic = self.basic_ocsp_response()?;
        let Some(certs) = &basic.certs else {
            return Err(Error::NoCertificate);
        };
        if certs.is_empty() {
            return Err(Error::NoCertificate);
        }
        certs
            .iter()
            .map(|c| {
                let der = c
                    .to_der()
                    .map_err(|e| Error::Internal(format!("embedded cert encode: {e}")))?;
                Cert::decode(&der)
            })
            .collect()
    }

    /// `ocspresp_get_responder_id`.
    pub fn responder_id(&self) -> Result<ResponderId> {
        Ok(self.basic_ocsp_response()?.tbs_response_data.responder_id.clone())
    }

    /// ResponderID DER encoding.
    pub fn responder_id_der(&self) -> Result<Vec<u8>> {
        self.responder_id()?
            .to_der()
            .map_err(|e| Error::Internal(format!("responder id encode: {e}")))
    }

    /// `ocspresp_get_certs_status`.
    pub fn cert_statuses(&self) -> Result<Vec<OcspCertStatus>> {
        let basic = self.basic_ocsp_response()?;
        Ok(basic
            .tbs_response_data
            .responses
            .iter()
            .map(single_response_status)
            .collect())
    }

    /// `ocspresp_verify`.
    pub fn verify(&self, adapter: &VerifyAdapter) -> Result<()> {
        let basic = self.basic_ocsp_response()?;
        let tbs_der = basic
            .tbs_response_data
            .to_der()
            .map_err(|e| Error::Internal(format!("response data encode: {e}")))?;
        let sign_aid = basic
            .signature_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))?;
        let signature_raw = sign_bitstring_to_raw(&sign_aid, &basic.signature)?;
        adapter.verify_data(&tbs_der, &signature_raw)
    }

    /// Build error/status-only responses (`eocspresp_form_*`).
    pub fn from_status(status: OcspResponseStatus) -> Self {
        Self {
            inner: OcspResponse {
                response_status: status,
                response_bytes: None,
            },
        }
    }

    pub(crate) fn from_inner(inner: OcspResponse) -> Self {
        Self { inner }
    }

    /// Extract embedded `BasicOCSPResponse` from a successful OCSP response.
    pub fn basic_ocsp_response(&self) -> Result<BasicOcspResponse> {
        let bytes = self.response_bytes()?;
        let inner = bytes.response.as_bytes();
        match BasicOcspResponse::from_der(inner) {
            Ok(basic) => Ok(basic),
            Err(_) => BasicOcspResponse::from_der(&normalize_fractional_generalized_times(inner))
                .map_err(|e| Error::Internal(format!("basic ocsp response decode: {e}"))),
        }
    }
}

fn normalize_fractional_generalized_times(der: &[u8]) -> Vec<u8> {
    fn read_len(bytes: &[u8]) -> Option<(usize, usize)> {
        if bytes.is_empty() {
            return None;
        }
        if bytes[0] & 0x80 == 0 {
            return Some((bytes[0] as usize, 1));
        }
        let count = (bytes[0] & 0x7f) as usize;
        if count == 0 || bytes.len() < 1 + count {
            return None;
        }
        let mut len = 0usize;
        for b in &bytes[1..=count] {
            len = (len << 8) | *b as usize;
        }
        Some((len, 1 + count))
    }

    fn write_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.push(0x81);
            out.push(len as u8);
        } else if len <= 0xffff {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        } else {
            out.push(0x83);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }

    fn normalize(bytes: &[u8], out: &mut Vec<u8>) -> bool {
        let mut i = 0usize;
        while i < bytes.len() {
            let tag = bytes[i];
            i += 1;
            let Some((len, len_bytes)) = read_len(&bytes[i..]) else {
                return false;
            };
            i += len_bytes;
            if i + len > bytes.len() {
                return false;
            }
            let content = &bytes[i..i + len];
            i += len;

            out.push(tag);
            if tag == 0x18 {
                if let Ok(s) = std::str::from_utf8(content) {
                    let normalized = if let Some(dot) = s.find('.') {
                        if let Some(z_off) = s[dot..].find('Z') {
                            format!("{}{}", &s[..dot], &s[dot + z_off..])
                        } else {
                            s.to_string()
                        }
                    } else {
                        s.to_string()
                    };
                    let normalized = normalized.into_bytes();
                    write_len(out, normalized.len());
                    out.extend_from_slice(&normalized);
                    continue;
                }
            }

            if tag & 0x20 != 0 {
                let mut nested = Vec::new();
                if !normalize(content, &mut nested) {
                    return false;
                }
                write_len(out, nested.len());
                out.extend_from_slice(&nested);
            } else {
                write_len(out, len);
                out.extend_from_slice(content);
            }
        }
        true
    }

    let mut out = Vec::with_capacity(der.len());
    if normalize(der, &mut out) {
        out
    } else {
        der.to_vec()
    }
}

fn single_response_status(single: &x509_ocsp::SingleResponse) -> OcspCertStatus {
    let serial_number = single.cert_id.serial_number.as_bytes().to_vec();
    match &single.cert_status {
        CertStatus::Good(_) => OcspCertStatus {
            serial_number,
            status: "good",
            revocation_time: 0,
            revocation_reason: None,
        },
        CertStatus::Revoked(info) => OcspCertStatus {
            serial_number,
            status: "revoked",
            revocation_time: info.revocation_time.0.to_unix_duration().as_secs() as i64,
            revocation_reason: info
                .revocation_reason
                .map(crl_reason_name)
                .map(str::to_string),
        },
        CertStatus::Unknown(_) => OcspCertStatus {
            serial_number,
            status: "unknown",
            revocation_time: 0,
            revocation_reason: None,
        },
    }
}

fn crl_reason_name(reason: CrlReason) -> &'static str {
    match reason {
        CrlReason::Unspecified => "unspecified",
        CrlReason::KeyCompromise => "keyCompromise",
        CrlReason::CaCompromise => "cACompromise",
        CrlReason::AffiliationChanged => "affiliationChanged",
        CrlReason::Superseded => "superseded",
        CrlReason::CessationOfOperation => "cessationOfOperation",
        CrlReason::CertificateHold => "certificateHold",
        CrlReason::RemoveFromCRL => "removeFromCRL",
        CrlReason::PrivilegeWithdrawn => "privilegeWithdrawn",
        CrlReason::AaCompromise => "aACompromise",
    }
}
