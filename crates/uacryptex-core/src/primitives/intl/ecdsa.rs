//! ECDSA verify/sign (NIST P-192 … P-521) via RustCrypto `p*` crates.

use elliptic_curve::Curve;
use elliptic_curve::FieldBytes;
use num_bigint_dig::BigUint;
use num_traits::Zero;

use crate::error::{Error, Result};
use crate::pki::oid::OidId;

/// NIST / SECG curve selected from SPKI or signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    P192,
    P224,
    P256,
    P384,
    P521,
    P256K1,
}

impl EcdsaCurve {
    pub fn field_len(&self) -> usize {
        match self {
            Self::P192 => 24,
            Self::P224 => 28,
            Self::P256 | Self::P256K1 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            Self::P192 | Self::P224 | Self::P256 | Self::P256K1 => 32,
            Self::P384 => 48,
            Self::P521 => 64,
        }
    }
}

pub fn ecdsa_curve_from_oid_str(oid: &str) -> Option<EcdsaCurve> {
    use crate::pki::oid::oid_from_str;
    let id = oid_from_str(oid)?;
    Some(match id {
        OidId::EcdsaSecp192R1 => EcdsaCurve::P192,
        OidId::EcdsaSecp224R1 => EcdsaCurve::P224,
        OidId::EcdsaSecp256R1 => EcdsaCurve::P256,
        OidId::EcdsaSecp384R1 => EcdsaCurve::P384,
        OidId::EcdsaSecp521R1 => EcdsaCurve::P521,
        OidId::EcdsaSecp256K1 => EcdsaCurve::P256K1,
        _ => return None,
    })
}

pub fn is_ecdsa_signature_oid(oid: &str) -> bool {
    use crate::pki::oid::oid_from_str;
    matches!(
        oid_from_str(oid),
        Some(
            OidId::EcdsaWithSha1
                | OidId::EcdsaWithSha224
                | OidId::EcdsaWithSha256
                | OidId::EcdsaWithSha384
                | OidId::EcdsaWithSha512
        )
    )
}

/// Parse uncompressed SPKI BIT STRING (`0x04 || X || Y`, coordinates in BE).
pub fn ecdsa_public_key_from_spki(raw: &[u8]) -> Result<(EcdsaCurve, Vec<u8>, Vec<u8>)> {
    if raw.is_empty() {
        return Err(Error::InvalidParam("empty ECDSA SPKI".into()));
    }
    if raw[0] != 0x04 {
        return Err(Error::Unsupported(
            "compressed ECDSA SPKI keys are not supported".into(),
        ));
    }
    let body = &raw[1..];
    if body.len() % 2 != 0 {
        return Err(Error::InvalidParam("invalid ECDSA SPKI length".into()));
    }
    let half = body.len() / 2;
    let curve = match half {
        24 => EcdsaCurve::P192,
        28 => EcdsaCurve::P224,
        32 => EcdsaCurve::P256,
        48 => EcdsaCurve::P384,
        66 => EcdsaCurve::P521,
        n => {
            return Err(Error::InvalidParam(format!(
                "unsupported ECDSA field size: {n}"
            )))
        }
    };
    let qx = be_coord_to_cryptonite_le(&body[..half]);
    let qy = be_coord_to_cryptonite_le(&body[half..]);
    Ok((curve, qx, qy))
}

pub fn ecdsa_public_key_from_private(curve: EcdsaCurve, private_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    validate_private_key(curve, private_key)?;
    match curve {
        EcdsaCurve::P192 | EcdsaCurve::P224 | EcdsaCurve::P521 => Err(Error::Unsupported(
            "ECDSA public key derivation is not supported for this curve".into(),
        )),
        EcdsaCurve::P256 => public_key_p256(private_key),
        EcdsaCurve::P384 => public_key_p384(private_key),
        EcdsaCurve::P256K1 => public_key_p256k1(private_key),
    }
}

pub fn validate_private_key(curve: EcdsaCurve, private_key: &[u8]) -> Result<()> {
    if private_key.is_empty() {
        return Err(Error::InvalidParam("empty private key".into()));
    }
    let field_len = curve.field_len();
    if private_key.len() > field_len + 9 {
        return Err(Error::InvalidParam(
            "private key does not correspond to parameters".into(),
        ));
    }
    let mut le = private_key.to_vec();
    if le.len() > field_len {
        le.truncate(field_len);
    } else {
        le.resize(field_len, 0);
    }
    let n = BigUint::from_bytes_le(&le);
    if n.is_zero() {
        return Err(Error::InvalidParam("invalid private key".into()));
    }
    Ok(())
}

pub fn ecdsa_verify(
    curve: EcdsaCurve,
    qx_le: &[u8],
    qy_le: &[u8],
    hash: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() % 2 != 0 || signature.is_empty() {
        return Err(Error::InvalidParam("invalid ECDSA signature length".into()));
    }
    let mid = signature.len() / 2;
    match curve {
        EcdsaCurve::P192 => {
            ecdsa_verify_p192(qx_le, qy_le, hash, &signature[..mid], &signature[mid..])
        }
        EcdsaCurve::P224 => {
            ecdsa_verify_p224(qx_le, qy_le, hash, &signature[..mid], &signature[mid..])
        }
        EcdsaCurve::P256 | EcdsaCurve::P256K1 => {
            ecdsa_verify_p256(qx_le, qy_le, hash, &signature[..mid], &signature[mid..])
        }
        EcdsaCurve::P384 => {
            ecdsa_verify_p384(qx_le, qy_le, hash, &signature[..mid], &signature[mid..])
        }
        EcdsaCurve::P521 => {
            ecdsa_verify_p521(qx_le, qy_le, hash, &signature[..mid], &signature[mid..])
        }
    }
}

pub fn ecdsa_sign(curve: EcdsaCurve, private_key: &[u8], hash: &[u8]) -> Result<Vec<u8>> {
    validate_private_key(curve, private_key)?;
    match curve {
        EcdsaCurve::P192 | EcdsaCurve::P224 | EcdsaCurve::P521 => Err(Error::Unsupported(
            "ECDSA signing is not supported for this curve".into(),
        )),
        EcdsaCurve::P256 => sign_p256(private_key, hash),
        EcdsaCurve::P384 => sign_p384(private_key, hash),
        EcdsaCurve::P256K1 => sign_p256k1(private_key, hash),
    }
}

pub fn build_ecdsa_spki_der(spki_aid: &[u8], qx_le: &[u8], qy_le: &[u8]) -> Result<Vec<u8>> {
    use der::asn1::BitString;
    use der::{Any, Decode, Encode};
    use x509_cert::spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

    let field_len = qx_le.len().max(qy_le.len());
    let mut qx_be = cryptonite_le_to_be_fixed(qx_le, field_len);
    let qy_be = cryptonite_le_to_be_fixed(qy_le, field_len);
    let mut point = Vec::with_capacity(1 + qx_be.len() + qy_be.len());
    point.push(0x04);
    point.append(&mut qx_be);
    point.extend_from_slice(&qy_be);

    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_aid)
        .map_err(|e| Error::Internal(format!("spki aid decode: {e}")))?;
    let bit_string = BitString::new(0, point.as_slice())
        .map_err(|e| Error::Internal(format!("ecdsa bit string: {e}")))?;
    SubjectPublicKeyInfo {
        algorithm: aid,
        subject_public_key: bit_string,
    }
    .to_der()
    .map_err(|e| Error::Internal(format!("ecdsa spki encode: {e}")))
}

macro_rules! impl_ecdsa_sign {
    ($fn_name:ident, $pkg:ident, $curve:ty, $field_len:expr) => {
        fn $fn_name(private_key: &[u8], hash: &[u8]) -> Result<Vec<u8>> {
            use $pkg::ecdsa::signature::hazmat::PrehashSigner;
            use $pkg::ecdsa::Signature;
            use $pkg::ecdsa::SigningKey;

            let be = cryptonite_le_to_be_fixed(private_key, $field_len);
            let signing = SigningKey::from_slice(&be)
                .map_err(|e| Error::InvalidParam(format!("ecdsa private key: {e}")))?;
            let hash_padded = pad_hash_for_prehash::<$curve>(hash);
            let sig: Signature = signing
                .sign_prehash(&hash_padded)
                .map_err(|e| Error::Internal(format!("ecdsa sign: {e}")))?;
            let (r, s) = sig.split_bytes();
            let mut out = be_component_to_cryptonite_le(r.as_slice(), $field_len);
            out.extend(be_component_to_cryptonite_le(s.as_slice(), $field_len));
            Ok(out)
        }
    };
}

macro_rules! impl_ecdsa_public_key {
    ($fn_name:ident, $pkg:ident, $curve:ty, $field_len:expr) => {
        fn $fn_name(private_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            use $pkg::ecdsa::SigningKey;

            let be = cryptonite_le_to_be_fixed(private_key, $field_len);
            let signing = SigningKey::from_slice(&be)
                .map_err(|e| Error::InvalidParam(format!("ecdsa private key: {e}")))?;
            let encoded = signing.verifying_key().to_encoded_point(false);
            let x = encoded
                .x()
                .ok_or_else(|| Error::Internal("missing x coordinate".into()))?;
            let y = encoded
                .y()
                .ok_or_else(|| Error::Internal("missing y coordinate".into()))?;
            Ok((
                be_component_to_cryptonite_le(x, $field_len),
                be_component_to_cryptonite_le(y, $field_len),
            ))
        }
    };
}

impl_ecdsa_sign!(sign_p256, p256, p256::NistP256, 32);
impl_ecdsa_sign!(sign_p384, p384, p384::NistP384, 48);
impl_ecdsa_sign!(sign_p256k1, k256, k256::Secp256k1, 32);

impl_ecdsa_public_key!(public_key_p256, p256, p256::NistP256, 32);
impl_ecdsa_public_key!(public_key_p384, p384, p384::NistP384, 48);
impl_ecdsa_public_key!(public_key_p256k1, k256, k256::Secp256k1, 32);


fn be_coord_to_cryptonite_le(coord: &[u8]) -> Vec<u8> {
    let mut le = coord.to_vec();
    le.reverse();
    le
}

fn cryptonite_le_to_be_fixed(le: &[u8], field_len: usize) -> Vec<u8> {
    let mut padded = le.to_vec();
    if padded.len() > field_len {
        padded.truncate(field_len);
    } else {
        padded.resize(field_len, 0);
    }
    padded.reverse();
    padded
}

fn be_component_to_cryptonite_le(be: &[u8], field_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; field_len];
    let start = field_len.saturating_sub(be.len());
    out[start..].copy_from_slice(be);
    out.reverse();
    out
}

fn pad_hash_for_prehash<C: Curve>(hash: &[u8]) -> Vec<u8> {
    let min_len = FieldBytes::<C>::default().as_slice().len() / 2;
    if hash.len() >= min_len {
        return hash.to_vec();
    }
    let mut out = vec![0u8; min_len - hash.len()];
    out.extend_from_slice(hash);
    out
}

fn cryptonite_le_to_field<C: Curve>(le_bytes: &[u8]) -> FieldBytes<C> {
    let field_len = FieldBytes::<C>::default().as_slice().len();
    let mut padded = le_bytes.to_vec();
    if padded.len() > field_len {
        padded.truncate(field_len);
    } else {
        padded.resize(field_len, 0);
    }
    let n = BigUint::from_bytes_le(&padded);
    let be = n.to_bytes_be();
    let mut out = FieldBytes::<C>::default();
    let start = field_len.saturating_sub(be.len());
    out.as_mut()[start..].copy_from_slice(&be);
    out
}

macro_rules! impl_verify {
    ($fn_name:ident, $pkg:ident, $curve:ty) => {
        pub fn $fn_name(
            qx_le: &[u8],
            qy_le: &[u8],
            hash: &[u8],
            r_le: &[u8],
            s_le: &[u8],
        ) -> Result<()> {
            use $pkg::ecdsa::signature::hazmat::PrehashVerifier;
            use $pkg::ecdsa::{Signature, VerifyingKey};
            use $pkg::EncodedPoint;

            let qx = cryptonite_le_to_field::<$curve>(qx_le);
            let qy = cryptonite_le_to_field::<$curve>(qy_le);

            let mut enc = vec![0x04u8];
            enc.extend_from_slice(qx.as_slice());
            enc.extend_from_slice(qy.as_slice());

            let point = EncodedPoint::from_bytes(&enc)
                .map_err(|e| Error::InvalidParam(format!("EC point: {e}")))?;
            let vk = VerifyingKey::from_encoded_point(&point)
                .map_err(|e| Error::InvalidParam(format!("verifying key: {e}")))?;

            let r_fb = cryptonite_le_to_field::<$curve>(r_le);
            let s_fb = cryptonite_le_to_field::<$curve>(s_le);
            let field_len = r_fb.as_slice().len();
            let mut sig_raw = vec![0u8; field_len * 2];
            sig_raw[..field_len].copy_from_slice(r_fb.as_slice());
            sig_raw[field_len..].copy_from_slice(s_fb.as_slice());
            let sig = Signature::try_from(sig_raw.as_slice())
                .map_err(|e| Error::InvalidParam(format!("signature: {e}")))?;

            let hash_padded = pad_hash_for_prehash::<$curve>(hash);
            vk.verify_prehash(&hash_padded, &sig)
                .map_err(|_| Error::VerifyFailed)
        }
    };
}

impl_verify!(ecdsa_verify_p192, p192, p192::NistP192);
impl_verify!(ecdsa_verify_p224, p224, p224::NistP224);
impl_verify!(ecdsa_verify_p256, p256, p256::NistP256);
impl_verify!(ecdsa_verify_p384, p384, p384::NistP384);
impl_verify!(ecdsa_verify_p521, p521, p521::NistP521);
