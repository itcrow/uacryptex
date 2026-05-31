//! Digest adapter (`digest_adapter_init_*`, `cryptonite_manager.c`).

use der::Decode;
use crate::pki::cert::Cert;
use crate::pki::crypto::aid::{gost3411_algorithm_der, sbox_from_algorithm_der, spki_algorithm_der};
use crate::pki::oid::OidId;
use crate::primitives::gost34_311::Gost34311;
use crate::primitives::intl::{
    sha1_digest_chunks, sha224_digest_chunks, sha256_digest_chunks, sha384_digest_chunks,
    sha512_digest_chunks,
};
use crate::{Error, Result};

/// Cryptonite `DigestAdapter`.
#[derive(Clone)]
pub struct DigestAdapter {
    algorithm_der: Vec<u8>,
    buffer: Vec<u8>,
}

impl DigestAdapter {
    /// `digest_adapter_init_default` (GOST 34.311, default S-box, zero sync).
    pub fn init_default() -> Result<Self> {
        Self::init_by_aid(gost3411_algorithm_der())
    }

    /// `digest_adapter_init_by_aid`.
    pub fn init_by_aid(algorithm_der: &[u8]) -> Result<Self> {
        // Validate algorithm up front.
        let _ = digest_kind(algorithm_der)?;
        Ok(Self {
            algorithm_der: algorithm_der.to_vec(),
            buffer: Vec::new(),
        })
    }

    /// `digest_adapter_init_by_cert`.
    pub fn init_by_cert(cert: &Cert) -> Result<Self> {
        let sign_aid = cert.signature_algorithm_der()?;
        let spki_aid = cert_spki_algorithm_der(cert)?;
        let algorithm_der =
            crate::pki::crypto::aid::digest_algorithm_from_certificate(&sign_aid, &spki_aid)?;
        Self::init_by_aid(&algorithm_der)
    }

    /// `digest_adapter_copy_with_alloc`.
    pub fn clone_state(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// `da->update`.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    /// `da->final`.
    pub fn finalize(self) -> Result<Vec<u8>> {
        hash_bytes(&self.algorithm_der, &self.buffer)
    }

    /// One-shot digest (Cryptonite `digest_adapter` update+final).
    pub fn digest_data(
        data: &[u8],
        algorithm_aid: Option<&[u8]>,
        cert: Option<&Cert>,
    ) -> Result<Vec<u8>> {
        let mut da = match (cert, algorithm_aid) {
            (Some(c), _) => Self::init_by_cert(c)?,
            (None, Some(aid)) if !aid.is_empty() => Self::init_by_aid(aid)?,
            _ => Self::init_default()?,
        };
        da.update(data)?;
        da.finalize()
    }

    /// `da->get_alg`.
    pub fn algorithm_der(&self) -> &[u8] {
        &self.algorithm_der
    }
}

fn cert_spki_algorithm_der(cert: &Cert) -> Result<Vec<u8>> {
    let spki = cert.spki_der()?;
    spki_algorithm_der(&spki)
}

enum DigestKind {
    Gost,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

fn digest_kind(algorithm_der: &[u8]) -> Result<DigestKind> {
    use x509_cert::spki::AlgorithmIdentifier;
    let aid: AlgorithmIdentifier<der::Any> =
        AlgorithmIdentifier::from_der(algorithm_der)
            .map_err(|e| Error::Internal(format!("algorithm decode: {e}")))?;
    let oid = aid.oid.to_string();
    if crate::pki::crypto::aid::oid_str_under(OidId::PkiDstu4145WithGost3411, &oid)
        || crate::pki::crypto::aid::oid_str_under(OidId::PkiGost3411, &oid)
    {
        return Ok(DigestKind::Gost);
    }
    let id = crate::pki::crypto::aid::oid_id_from_str(&oid)
        .ok_or_else(|| Error::Unsupported(format!("unsupported digest OID: {oid}")))?;
    Ok(match id {
        OidId::PkiSha1 => DigestKind::Sha1,
        OidId::PkiSha224 => DigestKind::Sha224,
        OidId::PkiSha256 => DigestKind::Sha256,
        OidId::PkiSha384 => DigestKind::Sha384,
        OidId::PkiSha512 => DigestKind::Sha512,
        _ => return Err(Error::Unsupported(format!("unsupported digest OID: {oid}"))),
    })
}

fn hash_bytes(algorithm_der: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match digest_kind(algorithm_der)? {
        DigestKind::Gost => {
            let sbox = sbox_from_algorithm_der(algorithm_der)?;
            let mut ctx = Gost34311::with_user_sbox(&[0u8; 32], &sbox)?;
            ctx.update(data)?;
            Ok(ctx.final_hash()?.to_vec())
        }
        DigestKind::Sha1 => Ok(sha1_digest_chunks(&[data]).to_vec()),
        DigestKind::Sha224 => Ok(sha224_digest_chunks(&[data]).to_vec()),
        DigestKind::Sha256 => Ok(sha256_digest_chunks(&[data]).to_vec()),
        DigestKind::Sha384 => Ok(sha384_digest_chunks(&[data]).to_vec()),
        DigestKind::Sha512 => Ok(sha512_digest_chunks(&[data]).to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn init_default_empty_hash_matches_utest() {
        let mut da = DigestAdapter::init_default().unwrap();
        da.update(&[]).unwrap();
        let hash = da.finalize().unwrap();
        assert_eq!(
            hash,
            hex("5DF74E647FED52C1E941B26D546B8C689112F207EB8542965FDD9CD3083E5282")
        );
    }
}
