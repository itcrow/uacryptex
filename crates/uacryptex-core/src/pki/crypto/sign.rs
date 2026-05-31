//! Sign adapter (`sign_adapter_init_*`, `cryptonite_manager.c`).

use der::{Any, Decode, Encode};
use x509_cert::spki::SubjectPublicKeyInfo;

use crate::pki::cert::Cert;
use crate::pki::crypto::aid::{
    curve_params_from_spki_algorithm, digest_aid_from_signature_oid,
    ecdsa_curve_from_spki_algorithm, ecdsa_signature_oid_for_digest_oid,
    is_dstu4145_signature_oid, is_ecdsa_signature_oid, spki_algorithm_der,
};
use crate::pki::crypto::dh::DhAdapter;
#[cfg(feature = "legacy-gost3410")]
use crate::pki::crypto::aid::is_gost3410_signature_oid;
use crate::pki::crypto::digest::DigestAdapter;
use crate::pki::crypto::prng::MasterPrng;
use crate::primitives::dstu4145::{
    compress_public_key, compressed_key_from_spki_bitstring, public_key_from_private_key, sign,
    Signature,
};
use crate::primitives::intl::{
    build_ecdsa_spki_der, ecdsa_public_key_from_private, ecdsa_public_key_from_spki, ecdsa_sign,
    ecdsa_validate_private_key, EcdsaCurve,
};
use crate::{Error, Result};

enum SignKind {
    Dstu4145 {
        params: crate::primitives::dstu4145::CurveParams,
        private_key: Vec<u8>,
    },
    Ecdsa {
        curve: EcdsaCurve,
        private_key: Vec<u8>,
        qx: Vec<u8>,
        qy: Vec<u8>,
    },
    #[cfg(feature = "legacy-gost3410")]
    Gost3410 {
        params: crate::primitives::gost3410::CurveParams,
        private_key: Vec<u8>,
    },
}

/// Cryptonite `SignAdapter`.
pub struct SignAdapter {
    kind: SignKind,
    digest_aid: Vec<u8>,
    sign_aid: Vec<u8>,
    spki_aid: Vec<u8>,
    cert: Option<Cert>,
    master_prng: MasterPrng,
    opt_level: u32,
}

impl SignAdapter {
    /// `sign_adapter_init_by_aid`.
    pub fn init_by_aid(
        private_key: &[u8],
        signature_aid_der: &[u8],
        spki_aid_der: &[u8],
    ) -> Result<Self> {
        let sign_oid = algorithm_oid_string(signature_aid_der)?;
        let (kind, digest_aid) = if is_dstu4145_signature_oid(&sign_oid) {
            let params = curve_params_from_spki_algorithm(spki_aid_der)?;
            validate_dstu_private_key(&params, private_key, None)?;
            (
                SignKind::Dstu4145 {
                    params,
                    private_key: private_key.to_vec(),
                },
                crate::pki::crypto::aid::gost3411_algorithm_der().to_vec(),
            )
        } else if is_ecdsa_signature_oid(&sign_oid) {
            let curve = ecdsa_curve_from_spki_algorithm(spki_aid_der)?;
            ecdsa_validate_private_key(curve, private_key)?;
            let (qx, qy) = ecdsa_public_key_from_private(curve, private_key)?;
            (
                SignKind::Ecdsa {
                    curve,
                    private_key: normalize_private_key(curve, private_key),
                    qx,
                    qy,
                },
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
                use crate::primitives::gost3410::{ParamsId, MODULE_BYTES};
                let params = ParamsId::Id1.curve_params().ok_or_else(|| {
                    Error::Internal("GOST3410 params ID 1 unavailable".into())
                })?;
                if private_key.is_empty() || private_key.len() > MODULE_BYTES {
                    return Err(Error::InvalidParam("invalid GOST3410 private key".into()));
                }
                (
                    SignKind::Gost3410 {
                        params,
                        private_key: private_key.to_vec(),
                    },
                    crate::pki::crypto::aid::gost3411_algorithm_der().to_vec(),
                )
            }
            #[cfg(not(feature = "legacy-gost3410"))]
            {
                return Err(Error::Unsupported("legacy-gost3410 feature disabled".into()));
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
            master_prng: MasterPrng::new()?,
            opt_level: 0,
        })
    }

    /// `sign_adapter_init_by_cert`.
    pub fn init_by_cert(private_key: &[u8], cert: &Cert) -> Result<Self> {
        let spki = cert.spki_der()?;
        let spki_aid = spki_algorithm_der(&spki)?;
        let sign_aid = cert.signature_algorithm_der()?;
        let sign_oid = algorithm_oid_string(&sign_aid)?;
        let mut adapter = Self::init_by_aid(private_key, &sign_aid, &spki_aid)?;

        if is_dstu4145_signature_oid(&sign_oid) {
            let compressed = compressed_key_from_spki(
                &SubjectPublicKeyInfo::<Any, der::asn1::BitString>::from_der(&spki)
                    .map_err(|e| Error::Internal(format!("spki decode: {e}")))?,
            )?;
            if let SignKind::Dstu4145 { params, private_key } = &adapter.kind {
                validate_dstu_private_key(params, private_key, Some(&compressed))?;
            }
        } else if is_ecdsa_signature_oid(&sign_oid) {
            let spki = SubjectPublicKeyInfo::<Any, der::asn1::BitString>::from_der(&spki)
                .map_err(|e| Error::Internal(format!("spki decode: {e}")))?;
            let (_, cert_qx, cert_qy) =
                ecdsa_public_key_from_spki(spki.subject_public_key.raw_bytes())?;
            if let SignKind::Ecdsa { qx, qy, .. } = &adapter.kind {
                if qx != &cert_qx || qy != &cert_qy {
                    return Err(Error::InvalidParam(
                        "public key does not correspond to private key".into(),
                    ));
                }
            }
        }

        adapter.cert = Some(cert.clone());
        Ok(adapter)
    }

    /// Build a DH adapter sharing this signing key (DSTU4145 / ECDSA).
    pub fn dh_adapter(&self) -> Result<DhAdapter> {
        match &self.kind {
            SignKind::Dstu4145 { private_key, .. } | SignKind::Ecdsa { private_key, .. } => {
                DhAdapter::init(private_key, &self.spki_aid)
            }
            #[cfg(feature = "legacy-gost3410")]
            SignKind::Gost3410 { .. } => Err(Error::Unsupported(
                "GOST3410 keys cannot be used for CMS EnvelopedData DH".into(),
            )),
        }
    }

    /// `sign_adapter_copy_with_alloc`.
    pub fn clone_state(&self) -> Result<Self> {
        Ok(Self {
            kind: match &self.kind {
                SignKind::Dstu4145 { params, private_key } => SignKind::Dstu4145 {
                    params: params.clone(),
                    private_key: private_key.clone(),
                },
                SignKind::Ecdsa {
                    curve,
                    private_key,
                    qx,
                    qy,
                } => SignKind::Ecdsa {
                    curve: *curve,
                    private_key: private_key.clone(),
                    qx: qx.clone(),
                    qy: qy.clone(),
                },
                #[cfg(feature = "legacy-gost3410")]
                SignKind::Gost3410 { params, private_key } => SignKind::Gost3410 {
                    params: params.clone(),
                    private_key: private_key.clone(),
                },
            },
            digest_aid: self.digest_aid.clone(),
            sign_aid: self.sign_aid.clone(),
            spki_aid: self.spki_aid.clone(),
            cert: self.cert.clone(),
            master_prng: self.master_prng.clone(),
            opt_level: self.opt_level,
        })
    }

    /// `sign_adapter_set_opt_level`.
    pub fn set_opt_level(&mut self, opt_level: u32) -> Result<()> {
        self.opt_level = opt_level;
        Ok(())
    }

    /// `sa->set_digest_alg`.
    pub fn set_digest_algorithm(&mut self, digest_aid_der: &[u8]) -> Result<()> {
        use crate::pki::crypto::algorithm_identifier_der;
        use crate::pki::oid::{oid_matches_str, OidId};

        let digest_oid = algorithm_oid_string(digest_aid_der)?;
        self.digest_aid = digest_aid_der.to_vec();
        match &self.kind {
            SignKind::Ecdsa { .. } => {
                let sign_id = ecdsa_signature_oid_for_digest_oid(&digest_oid)?;
                self.sign_aid = algorithm_identifier_der(sign_id, None)?;
            }
            SignKind::Dstu4145 { .. } => {
                if !oid_matches_str(OidId::PkiGost3411, &digest_oid) {
                    return Err(Error::Unsupported(
                        "DSTU4145 sign adapter requires GOST3411 digest".into(),
                    ));
                }
            }
            #[cfg(feature = "legacy-gost3410")]
            SignKind::Gost3410 { .. } => {
                if !oid_matches_str(OidId::PkiGost3411, &digest_oid) {
                    return Err(Error::Unsupported(
                        "GOST3410 sign adapter requires GOST3411 digest".into(),
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
            .ok_or_else(|| Error::Unsupported("sign adapter has no certificate".into()))
    }

    pub fn digest_algorithm_der(&self) -> &[u8] {
        &self.digest_aid
    }

    pub fn signature_algorithm_der(&self) -> &[u8] {
        &self.sign_aid
    }

    pub fn spki_der(&self) -> Result<Vec<u8>> {
        match &self.cert {
            Some(cert) => cert.spki_der(),
            None => match &self.kind {
                SignKind::Dstu4145 { params, private_key } => {
                    let pk = public_key_from_private_key(params, private_key)?;
                    let compressed = compress_public_key(params, &pk)?;
                    build_dstu_spki_der(&self.spki_aid, &compressed)
                }
                SignKind::Ecdsa { qx, qy, .. } => build_ecdsa_spki_der(&self.spki_aid, qx, qy),
                #[cfg(feature = "legacy-gost3410")]
                SignKind::Gost3410 { params, private_key } => {
                    use crate::primitives::gost3410::get_pubkey;
                    let (qx, qy) = get_pubkey(params, private_key)?;
                    build_gost3410_spki_der(&self.spki_aid, &qx, &qy)
                }
            },
        }
    }

    /// `sa->sign_data`.
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let hash = self.hash_data(data)?;
        self.sign_hash(&hash)
    }

    /// `sa->sign_hash`.
    pub fn sign_hash(&self, hash: &[u8]) -> Result<Vec<u8>> {
        match &self.kind {
            SignKind::Dstu4145 { params, private_key } => {
                if hash.len() != 32 {
                    return Err(Error::InvalidParam(format!(
                        "DSTU4145 hash must be 32 bytes, got {}",
                        hash.len()
                    )));
                }
                let mut rng = self.master_prng.dstu_sign_prng()?;
                let sig = sign(params, private_key, hash, &mut rng)?;
                Ok(join_signature(&sig))
            }
            SignKind::Ecdsa { curve, private_key, .. } => ecdsa_sign(*curve, private_key, hash),
            #[cfg(feature = "legacy-gost3410")]
            SignKind::Gost3410 { params, private_key } => {
                use crate::primitives::gost3410::sign;
                if hash.len() != 32 {
                    return Err(Error::InvalidParam(format!(
                        "GOST3410 hash must be 32 bytes, got {}",
                        hash.len()
                    )));
                }
                let mut rng = self.master_prng.dstu_sign_prng()?;
                let sig = sign(params, private_key, hash, &mut rng)?;
                Ok(sig.join_be())
            }
        }
    }

    fn hash_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut da = match &self.kind {
            SignKind::Dstu4145 { .. } => DigestAdapter::init_by_aid(&self.spki_aid)?,
            #[cfg(feature = "legacy-gost3410")]
            SignKind::Gost3410 { .. } => DigestAdapter::init_by_aid(&self.spki_aid)?,
            SignKind::Ecdsa { .. } => DigestAdapter::init_by_aid(&self.digest_aid)?,
        };
        da.update(data)?;
        da.finalize()
    }
}

fn normalize_private_key(curve: EcdsaCurve, private_key: &[u8]) -> Vec<u8> {
    let field_len = curve.field_len();
    let mut out = private_key.to_vec();
    if out.len() > field_len {
        out.truncate(field_len);
    } else {
        out.resize(field_len, 0);
    }
    out
}

fn validate_dstu_private_key(
    params: &crate::primitives::dstu4145::CurveParams,
    private_key: &[u8],
    expected_compressed: Option<&[u8]>,
) -> Result<()> {
    let derived = public_key_from_private_key(params, private_key)?;
    if let Some(expected) = expected_compressed {
        let compressed = compress_public_key(params, &derived)?;
        if compressed != expected {
            return Err(Error::InvalidParam(
                "public key does not correspond to private key".into(),
            ));
        }
    }
    Ok(())
}

fn join_signature(sig: &Signature) -> Vec<u8> {
    let mut out = sig.r.clone();
    out.extend_from_slice(&sig.s);
    out
}

fn algorithm_oid_string(algorithm_der: &[u8]) -> Result<String> {
    use x509_cert::spki::AlgorithmIdentifier;
    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(algorithm_der)
        .map_err(|e| Error::Internal(format!("algorithm decode: {e}")))?;
    Ok(aid.oid.to_string())
}

fn compressed_key_from_spki(spki: &SubjectPublicKeyInfo<Any, der::asn1::BitString>) -> Result<Vec<u8>> {
    compressed_key_from_spki_bitstring(spki.subject_public_key.raw_bytes())
}

pub(crate) fn build_dstu_spki_der(spki_aid: &[u8], compressed: &[u8]) -> Result<Vec<u8>> {
    use der::asn1::{BitString, OctetString};
    use x509_cert::spki::AlgorithmIdentifier;
    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_aid)
        .map_err(|e| Error::Internal(format!("spki aid decode: {e}")))?;
    let wrapped = OctetString::new(compressed)
        .map_err(|e| Error::Internal(format!("octet string: {e}")))?;
    let wrapped_der = wrapped
        .to_der()
        .map_err(|e| Error::Internal(format!("octet string encode: {e}")))?;
    let bit_string = BitString::new(0, wrapped_der.as_slice())
        .map_err(|e| Error::Internal(format!("bit string: {e}")))?;

    let spki = SubjectPublicKeyInfo {
        algorithm: aid,
        subject_public_key: bit_string,
    };
    spki.to_der()
        .map_err(|e| Error::Internal(format!("spki encode: {e}")))
}

#[cfg(feature = "legacy-gost3410")]
pub(crate) fn build_gost3410_spki_der(spki_aid: &[u8], qx: &[u8], qy: &[u8]) -> Result<Vec<u8>> {
    use der::asn1::{BitString, OctetString};
    use x509_cert::spki::AlgorithmIdentifier;
    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_aid)
        .map_err(|e| Error::Internal(format!("spki aid decode: {e}")))?;
    let mut pubkey = qx.to_vec();
    pubkey.extend_from_slice(qy);
    let wrapped = OctetString::new(pubkey).map_err(|e| Error::Internal(format!("octet string: {e}")))?;
    let wrapped_der = wrapped
        .to_der()
        .map_err(|e| Error::Internal(format!("octet string encode: {e}")))?;
    let bit_string = BitString::new(0, wrapped_der.as_slice())
        .map_err(|e| Error::Internal(format!("bit string: {e}")))?;
    SubjectPublicKeyInfo {
        algorithm: aid,
        subject_public_key: bit_string,
    }
    .to_der()
    .map_err(|e| Error::Internal(format!("spki encode: {e}")))
}
