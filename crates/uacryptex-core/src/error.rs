//! Error types aligned with Cryptonite `RET_*` codes where applicable.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Success (Cryptonite `RET_OK`).
pub const RET_OK: i32 = 0;
pub const RET_MEMORY_ALLOC_ERROR: i32 = 1;
pub const RET_INVALID_PARAM: i32 = 2;
pub const RET_VERIFY_FAILED: i32 = 3;
pub const RET_DSTU_PRNG_LOOPED: i32 = 8;
/// Cryptonite `RET_PKIX_OBJ_NOT_FOUND` (`0x0105`).
pub const RET_PKIX_OBJ_NOT_FOUND: i32 = 0x0105;
/// Cryptonite `RET_PKIX_OCSP_REQ_NO_SIGN` (`0x0102`).
pub const RET_PKIX_OCSP_REQ_NO_SIGN: i32 = 0x0102;
/// Cryptonite `RET_PKIX_OCSP_RESP_NO_BYTES` (`0x011f`).
pub const RET_PKIX_OCSP_RESP_NO_BYTES: i32 = 0x011f;
/// Cryptonite `RET_PKIX_NO_CERTIFICATE` (`0x0110`).
pub const RET_PKIX_NO_CERTIFICATE: i32 = 0x0110;
/// Cryptonite `RET_PKIX_TSP_REQ_NO_REQ_POLICY` (`0x014f`).
pub const RET_PKIX_TSP_REQ_NO_REQ_POLICY: i32 = 0x014f;
/// Cryptonite `RET_PKIX_TSP_REQ_NO_NONCE` (`0x0150`).
pub const RET_PKIX_TSP_REQ_NO_NONCE: i32 = 0x0150;
/// Cryptonite `RET_PKIX_TSP_RESP_NO_TS_TOKEN` (`0x0150`, same code as no-nonce in Cryptonite).
pub const RET_PKIX_TSP_RESP_NO_TS_TOKEN: i32 = 0x0150;
/// Cryptonite `RET_PKIX_UNSUPPORTED_SIGN_ALG` (`0x0145`).
pub const RET_PKIX_UNSUPPORTED_SIGN_ALG: i32 = 0x0145;
/// Cryptonite `RET_PKIX_DIFFERENT_DIGEST_ALG` (`0x014c`).
pub const RET_PKIX_DIFFERENT_DIGEST_ALG: i32 = 0x014c;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("memory allocation failed")]
    MemoryAlloc,

    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    #[error("verification failed")]
    VerifyFailed,

    #[error("DSTU PRNG looped")]
    DstuPrngLooped,

    #[error("PKIX object not found")]
    NotFound,

    #[error("OCSP request has no signature")]
    OcspReqNoSign,

    #[error("OCSP response has no response bytes")]
    OcspRespNoBytes,

    #[error("no certificate")]
    NoCertificate,

    #[error("TSP request has no policy")]
    TspReqNoPolicy,

    #[error("TSP request has no nonce")]
    TspReqNoNonce,

    #[error("TSP response has no timestamp token")]
    TspRespNoToken,

    #[error("unsupported signature algorithm")]
    UnsupportedSignAlg,

    #[error("different digest algorithm")]
    DifferentDigestAlg,

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("storage key not selected")]
    StorageKeyNotSelected,

    #[error("storage no key")]
    StorageNoKey,

    #[error("storage invalid key password")]
    StorageInvalidKeyPassword,
}

impl Error {
    pub fn code(&self) -> i32 {
        match self {
            Self::MemoryAlloc => RET_MEMORY_ALLOC_ERROR,
            Self::InvalidParam(_) => RET_INVALID_PARAM,
            Self::VerifyFailed => RET_VERIFY_FAILED,
            Self::DstuPrngLooped => RET_DSTU_PRNG_LOOPED,
            Self::NotFound => RET_PKIX_OBJ_NOT_FOUND,
            Self::OcspReqNoSign => RET_PKIX_OCSP_REQ_NO_SIGN,
            Self::OcspRespNoBytes => RET_PKIX_OCSP_RESP_NO_BYTES,
            Self::NoCertificate => RET_PKIX_NO_CERTIFICATE,
            Self::TspReqNoPolicy => RET_PKIX_TSP_REQ_NO_REQ_POLICY,
            Self::TspReqNoNonce => RET_PKIX_TSP_REQ_NO_NONCE,
            Self::TspRespNoToken => RET_PKIX_TSP_RESP_NO_TS_TOKEN,
            Self::UnsupportedSignAlg => RET_PKIX_UNSUPPORTED_SIGN_ALG,
            Self::DifferentDigestAlg => RET_PKIX_DIFFERENT_DIGEST_ALG,
            Self::Unsupported(_) | Self::Internal(_) => RET_INVALID_PARAM,
            Self::StorageKeyNotSelected | Self::StorageNoKey | Self::StorageInvalidKeyPassword => {
                RET_INVALID_PARAM
            }
        }
    }

    pub fn write_message(&self, buf: &mut [u8]) -> usize {
        let msg = self.to_string();
        let len = msg.len().min(buf.len().saturating_sub(1));
        buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
        if !buf.is_empty() {
            buf[len.min(buf.len() - 1)] = 0;
        }
        len
    }
}
