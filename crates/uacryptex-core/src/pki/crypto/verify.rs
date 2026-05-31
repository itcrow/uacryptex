//! Verify adapter (`verify_adapter_init_*`, `cryptonite_manager.c`).

use der::{Any, Decode};
use x509_cert::spki::SubjectPublicKeyInfo;

use crate::pki::cert::Cert;
#[cfg(feature = "legacy-gost3410")]
use crate::pki::crypto::aid::is_gost3410_signature_oid;
use crate::pki::crypto::aid::{
    curve_params_from_spki_algorithm, digest_aid_from_signature_oid,
    ecdsa_signature_oid_for_digest_oid, is_dstu4145_signature_oid, is_ecdsa_signature_oid,
    spki_algorithm_der,
};
use crate::pki::crypto::digest::DigestAdapter;
use crate::primitives::dstu4145::{
    compressed_key_from_spki_bitstring, decompress_public_key, verify, Signature,
};
use crate::primitives::intl::{ecdsa_public_key_from_spki, ecdsa_verify, EcdsaCurve};
use crate::{Error, Result};

enum VerifyKind {
    Dstu4145 {
        params: crate::primitives::dstu4145::CurveParams,
        public_key: crate::primitives::dstu4145::PublicKey,
    },
    Ecdsa {
        curve: EcdsaCurve,
        qx: Vec<u8>,
        qy: Vec<u8>,
    },
    #[cfg(feature = "legacy-gost3410")]
    Gost3410 {
        params: crate::primitives::gost3410::CurveParams,
        qx: Vec<u8>,
        qy: Vec<u8>,
    },
}

/// Cryptonite `VerifyAdapter`.
pub struct VerifyAdapter {
    kind: VerifyKind,
    digest_aid: Vec<u8>,
    sign_aid: Vec<u8>,
    spki_aid: Vec<u8>,
    cert: Option<Cert>,
    opt_level: u32,
}

impl VerifyAdapter {
    /// `verify_adapter_init_by_cert`.
    pub fn init_by_cert(cert: &Cert) -> Result<Self> {
        let spki = cert.spki_der()?;
        let sign_aid = cert.signature_algorithm_der()?;
        let spki_aid = spki_algorithm_der(&spki)?;
        Self::init_by_spki(&sign_aid, &spki, &spki_aid).map(|mut va| {
            va.cert = Some(cert.clone());
            va
        })
    }

    /// `verify_adapter_init_by_spki`.
    pub fn init_by_spki(
        signature_aid_der: &[u8],
        spki_der: &[u8],
        spki_aid_der: &[u8],
    ) -> Result<Self> {
        let sign_oid = algorithm_oid_string(signature_aid_der)?;
        let spki = SubjectPublicKeyInfo::<Any, der::asn1::BitString>::from_der(spki_der)
            .map_err(|e| Error::Internal(format!("spki decode: {e}")))?;

        let (kind, digest_aid) = if is_dstu4145_signature_oid(&sign_oid) {
            let params = curve_params_from_spki_algorithm(spki_aid_der)?;
            let compressed =
                compressed_key_from_spki_bitstring(spki.subject_public_key.raw_bytes())?;
            let public_key = decompress_public_key(&params, &compressed)?;
            (
                VerifyKind::Dstu4145 { params, public_key },
                crate::pki::crypto::aid::gost3411_algorithm_der().to_vec(),
            )
        } else if is_ecdsa_signature_oid(&sign_oid) {
            let (curve, qx, qy) = ecdsa_public_key_from_spki(spki.subject_public_key.raw_bytes())?;
            (
                VerifyKind::Ecdsa { curve, qx, qy },
                digest_aid_from_signature_oid(&sign_oid)?,
            )
        } else if {
            #[cfg(feature = "legacy-gost3410")]
            {
                is_gost3410_signature_oid(&sign_oid)
            }
            #[cfg(not(feature = "legacy-gost3410"))]
            {
                false
            }
        } {
            #[cfg(feature = "legacy-gost3410")]
            {
                use crate::primitives::gost3410::{pubkey_be_from_spki_bitstring, ParamsId};
                let params = ParamsId::Id1
                    .curve_params()
                    .ok_or_else(|| Error::Internal("GOST3410 params ID 1 unavailable".into()))?;
                let (qx, qy) = pubkey_be_from_spki_bitstring(spki.subject_public_key.raw_bytes())?;
                (
                    VerifyKind::Gost3410 { params, qx, qy },
                    crate::pki::crypto::aid::gost3411_algorithm_der().to_vec(),
                )
            }
            #[cfg(not(feature = "legacy-gost3410"))]
            {
                return Err(Error::Unsupported(
                    "legacy-gost3410 feature disabled".into(),
                ));
            }
        } else {
            return Err(Error::Unsupported(format!(
                "unsupported signature algorithm: {sign_oid}"
            )));
        };

        Ok(Self {
            kind,
            digest_aid,
            sign_aid: signature_aid_der.to_vec(),
            spki_aid: spki_aid_der.to_vec(),
            cert: None,
            opt_level: 0,
        })
    }

    /// `verify_adapter_copy_with_alloc`.
    pub fn clone_state(&self) -> Result<Self> {
        Ok(Self {
            kind: match &self.kind {
                VerifyKind::Dstu4145 { params, public_key } => VerifyKind::Dstu4145 {
                    params: params.clone(),
                    public_key: public_key.clone(),
                },
                VerifyKind::Ecdsa { curve, qx, qy } => VerifyKind::Ecdsa {
                    curve: *curve,
                    qx: qx.clone(),
                    qy: qy.clone(),
                },
                #[cfg(feature = "legacy-gost3410")]
                VerifyKind::Gost3410 { params, qx, qy } => VerifyKind::Gost3410 {
                    params: params.clone(),
                    qx: qx.clone(),
                    qy: qy.clone(),
                },
            },
            digest_aid: self.digest_aid.clone(),
            sign_aid: self.sign_aid.clone(),
            spki_aid: self.spki_aid.clone(),
            cert: self.cert.clone(),
            opt_level: self.opt_level,
        })
    }

    /// `verify_adapter_set_opt_level`.
    pub fn set_opt_level(&mut self, opt_level: u32) -> Result<()> {
        self.opt_level = opt_level;
        Ok(())
    }

    /// `va->set_digest_alg`.
    pub fn set_digest_algorithm(&mut self, digest_aid_der: &[u8]) -> Result<()> {
        use crate::pki::crypto::algorithm_identifier_der;
        use crate::pki::oid::{oid_matches_str, OidId};

        let digest_oid = algorithm_oid_string(digest_aid_der)?;
        self.digest_aid = digest_aid_der.to_vec();
        match &self.kind {
            VerifyKind::Ecdsa { .. } => {
                let sign_id = ecdsa_signature_oid_for_digest_oid(&digest_oid)?;
                self.sign_aid = algorithm_identifier_der(sign_id, None)?;
            }
            VerifyKind::Dstu4145 { .. } => {
                if !oid_matches_str(OidId::PkiGost3411, &digest_oid) {
                    return Err(Error::Unsupported(
                        "DSTU4145 verify adapter requires GOST3411 digest".into(),
                    ));
                }
            }
            #[cfg(feature = "legacy-gost3410")]
            VerifyKind::Gost3410 { .. } => {
                if !oid_matches_str(OidId::PkiGost3411, &digest_oid) {
                    return Err(Error::Unsupported(
                        "GOST3410 verify adapter requires GOST3411 digest".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn has_cert(&self) -> bool {
        self.cert.is_some()
    }

    pub fn cert(&self) -> Result<&Cert> {
        self.cert
            .as_ref()
            .ok_or_else(|| Error::Unsupported("verify adapter has no certificate".into()))
    }

    pub fn set_cert(&mut self, cert: &Cert) -> Result<()> {
        *self = Self::init_by_cert(cert)?;
        Ok(())
    }

    pub fn digest_algorithm_der(&self) -> &[u8] {
        &self.digest_aid
    }

    pub fn signature_algorithm_der(&self) -> &[u8] {
        &self.sign_aid
    }

    pub fn spki_der(&self) -> Result<Vec<u8>> {
        self.cert
            .as_ref()
            .ok_or_else(|| Error::Unsupported("verify adapter has no certificate".into()))?
            .spki_der()
    }

    /// `va->verify_data`.
    pub fn verify_data(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let mut da = match &self.kind {
            VerifyKind::Dstu4145 { .. } => DigestAdapter::init_by_aid(&self.spki_aid)?,
            #[cfg(feature = "legacy-gost3410")]
            VerifyKind::Gost3410 { .. } => DigestAdapter::init_by_aid(&self.spki_aid)?,
            _ => DigestAdapter::init_by_aid(&self.digest_aid)?,
        };
        da.update(data)?;
        let hash = da.finalize()?;
        self.verify_hash(&hash, signature)
    }

    /// `va->verify_hash`.
    pub fn verify_hash(&self, hash: &[u8], signature: &[u8]) -> Result<()> {
        match &self.kind {
            VerifyKind::Dstu4145 { params, public_key } => {
                let sig = split_dstu_signature(signature)?;
                verify(params, public_key, hash, &sig)
            }
            VerifyKind::Ecdsa { curve, qx, qy } => ecdsa_verify(*curve, qx, qy, hash, signature),
            #[cfg(feature = "legacy-gost3410")]
            VerifyKind::Gost3410 { params, qx, qy } => {
                use crate::primitives::gost3410::{split_signature_be, verify as gost3410_verify};
                let sig = split_signature_be(signature)?;
                gost3410_verify(params, qx, qy, hash, &sig.r, &sig.s)
            }
        }
    }
}

fn algorithm_oid_string(algorithm_der: &[u8]) -> Result<String> {
    use x509_cert::spki::AlgorithmIdentifier;
    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(algorithm_der)
        .map_err(|e| Error::Internal(format!("algorithm decode: {e}")))?;
    Ok(aid.oid.to_string())
}

fn split_dstu_signature(signature: &[u8]) -> Result<Signature> {
    if signature.len() % 2 != 0 || signature.is_empty() {
        return Err(Error::InvalidParam(
            "invalid DSTU4145 signature length".into(),
        ));
    }
    let mid = signature.len() / 2;
    Ok(Signature::from_le(
        signature[..mid].to_vec(),
        signature[mid..].to_vec(),
    ))
}
