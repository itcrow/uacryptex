//! Algorithm identifier helpers (`cryptonite_manager.c`, `aid.c`).

use der::{Any, Decode, Encode, Sequence};
use x509_cert::spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::pki::oid::{oid_from_str, oid_matches_str, oid_to_str, OidId};
use crate::primitives::gost28147::{expand_dke, GOST28147_SBOX_LEN};
use crate::{Error, Result};

const GOST3411_AID_DER: &[u8] = &hex_literal::hex!("300c060a2a862402010101010201");

/// Compare OID string to registry entry or its descendants.
pub fn oid_str_under(id: OidId, oid: &str) -> bool {
    if oid_matches_str(id, oid) {
        return true;
    }
    let Some(prefix) = oid_to_str(id) else {
        return false;
    };
    oid == prefix.as_str() || oid.starts_with(&format!("{prefix}."))
}

pub fn gost3411_algorithm_der() -> &'static [u8] {
    GOST3411_AID_DER
}

pub fn sbox_from_algorithm_der(algorithm_der: &[u8]) -> Result<[u8; GOST28147_SBOX_LEN]> {
    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(algorithm_der)
        .map_err(|e| Error::Internal(format!("algorithm decode: {e}")))?;
    sbox_from_algorithm_identifier(&aid)
}

pub fn sbox_from_algorithm_identifier(
    aid: &AlgorithmIdentifier<Any>,
) -> Result<[u8; GOST28147_SBOX_LEN]> {
    let oid = aid.oid.to_string();
    if oid_str_under(OidId::PkiDstu4145WithGost3411, &oid) {
        if let Some(params) = &aid.parameters {
            if let Ok(dstu) = Dstu4145Params::from_der(params.value()) {
                if let Some(dke) = dstu.dke {
                    return expand_dke(dke.as_bytes());
                }
            }
        }
    }
    Ok(crate::primitives::gost28147::default_sbox())
}

pub fn digest_algorithm_from_signature_oid(sign_oid: &str) -> Result<OidId> {
    if oid_str_under(OidId::PkiDstu4145WithGost3411, sign_oid) {
        return Ok(OidId::PkiGost3411);
    }
    if oid_str_under(OidId::EcdsaWithSha1, sign_oid) || oid_matches_str(OidId::PkiSha1, sign_oid) {
        return Ok(OidId::PkiSha1);
    }
    if oid_str_under(OidId::EcdsaWithSha224, sign_oid)
        || oid_matches_str(OidId::PkiSha224, sign_oid)
    {
        return Ok(OidId::PkiSha224);
    }
    if oid_str_under(OidId::EcdsaWithSha256, sign_oid)
        || oid_matches_str(OidId::PkiSha256, sign_oid)
    {
        return Ok(OidId::PkiSha256);
    }
    if oid_str_under(OidId::EcdsaWithSha384, sign_oid)
        || oid_matches_str(OidId::PkiSha384, sign_oid)
    {
        return Ok(OidId::PkiSha384);
    }
    if oid_str_under(OidId::EcdsaWithSha512, sign_oid)
        || oid_matches_str(OidId::PkiSha512, sign_oid)
    {
        return Ok(OidId::PkiSha512);
    }
    Err(Error::Unsupported(format!(
        "unsupported signature OID: {sign_oid}"
    )))
}

pub fn digest_algorithm_from_certificate(
    signature_algorithm_der: &[u8],
    spki_algorithm_der: &[u8],
) -> Result<Vec<u8>> {
    let sign_aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(signature_algorithm_der)
        .map_err(|e| Error::Internal(format!("signature algorithm decode: {e}")))?;
    let sign_oid = sign_aid.oid.to_string();
    if oid_str_under(OidId::PkiDstu4145WithGost3411, &sign_oid) {
        let spki_aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_algorithm_der)
            .map_err(|e| Error::Internal(format!("spki algorithm decode: {e}")))?;
        return algorithm_identifier_der(OidId::PkiGost3411, spki_aid.parameters.as_ref());
    }
    algorithm_identifier_der(
        digest_algorithm_from_signature_oid(&sign_oid)?,
        sign_aid.parameters.as_ref(),
    )
}

pub fn algorithm_identifier_der(id: OidId, params: Option<&Any>) -> Result<Vec<u8>> {
    let dot = oid_to_str(id).ok_or_else(|| Error::InvalidParam(format!("unknown OID {id:?}")))?;
    let oid = der::asn1::ObjectIdentifier::new(&dot)
        .map_err(|e| Error::Internal(format!("object identifier: {e}")))?;
    let aid = AlgorithmIdentifier {
        oid,
        parameters: params.cloned(),
    };
    aid.to_der()
        .map_err(|e| Error::Internal(format!("algorithm identifier encode: {e}")))
}

pub fn spki_algorithm_der(spki_der: &[u8]) -> Result<Vec<u8>> {
    let spki: SubjectPublicKeyInfo<Any, der::asn1::BitString> =
        SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|e| Error::Internal(format!("spki decode: {e}")))?;
    spki.algorithm
        .to_der()
        .map_err(|e| Error::Internal(format!("spki algorithm encode: {e}")))
}

pub fn curve_params_from_spki_algorithm(
    spki_algorithm_der: &[u8],
) -> Result<crate::primitives::dstu4145::CurveParams> {
    use crate::primitives::dstu4145::ParamsId;

    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_algorithm_der)
        .map_err(|e| Error::Internal(format!("spki algorithm decode: {e}")))?;
    let oid = aid.oid.to_string();
    if !oid_str_under(OidId::PkiDstu4145WithGost3411, &oid) {
        return Err(Error::Unsupported(format!(
            "unsupported SPKI signature algorithm: {oid}"
        )));
    }

    if let Some(params) = &aid.parameters {
        if let Ok(dstu) = Dstu4145Params::from_der(params.value()) {
            if let Some(m) = dstu.field_degree {
                return params_id_from_field_degree(uint_to_u32(&m)).curve_params();
            }
        }
    }

    ParamsId::M257Pb.curve_params()
}

pub fn params_id_from_field_degree(m: u32) -> crate::primitives::dstu4145::ParamsId {
    use crate::primitives::dstu4145::ParamsId;
    match m {
        163 => ParamsId::M163Pb,
        167 => ParamsId::M167Pb,
        173 => ParamsId::M173Pb,
        179 => ParamsId::M179Pb,
        191 => ParamsId::M191Pb,
        233 => ParamsId::M233Pb,
        257 => ParamsId::M257Pb,
        307 => ParamsId::M307Pb,
        367 => ParamsId::M367Pb,
        431 => ParamsId::M431Pb,
        _ => ParamsId::M257Pb,
    }
}

pub fn is_ecdsa_signature_oid(oid: &str) -> bool {
    crate::primitives::intl::is_ecdsa_signature_oid(oid)
}

pub fn ecdsa_curve_from_spki_algorithm(
    spki_algorithm_der: &[u8],
) -> Result<crate::primitives::intl::EcdsaCurve> {
    use crate::primitives::intl::ecdsa_curve_from_oid_str;
    use der::asn1::ObjectIdentifier;

    let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_algorithm_der)
        .map_err(|e| Error::Internal(format!("spki algorithm decode: {e}")))?;
    if let Some(params) = &aid.parameters {
        if let Ok(curve_oid) = params.decode_as::<ObjectIdentifier>() {
            if let Some(curve) = ecdsa_curve_from_oid_str(&curve_oid.to_string()) {
                return Ok(curve);
            }
        }
        if let Ok(curve_oid) = ObjectIdentifier::from_der(params.value()) {
            if let Some(curve) = ecdsa_curve_from_oid_str(&curve_oid.to_string()) {
                return Ok(curve);
            }
        }
    }
    Err(Error::Unsupported(
        "unsupported ECDSA SPKI parameters".into(),
    ))
}

pub fn digest_aid_from_signature_oid(sign_oid: &str) -> Result<Vec<u8>> {
    algorithm_identifier_der(digest_algorithm_from_signature_oid(sign_oid)?, None)
}

/// Map a digest OID to the matching ECDSA signature OID (`sa_set_digest_alg`).
pub fn ecdsa_signature_oid_for_digest_oid(digest_oid: &str) -> Result<OidId> {
    use crate::pki::oid::{oid_matches_str, OidId};
    if oid_matches_str(OidId::PkiSha1, digest_oid) {
        Ok(OidId::EcdsaWithSha1)
    } else if oid_matches_str(OidId::PkiSha224, digest_oid) {
        Ok(OidId::EcdsaWithSha224)
    } else if oid_matches_str(OidId::PkiSha256, digest_oid) {
        Ok(OidId::EcdsaWithSha256)
    } else if oid_matches_str(OidId::PkiSha384, digest_oid) {
        Ok(OidId::EcdsaWithSha384)
    } else if oid_matches_str(OidId::PkiSha512, digest_oid) {
        Ok(OidId::EcdsaWithSha512)
    } else {
        Err(Error::Unsupported(format!(
            "unsupported digest OID for ECDSA signature mapping: {digest_oid}"
        )))
    }
}

pub fn is_dstu4145_signature_oid(oid: &str) -> bool {
    oid_str_under(OidId::PkiDstu4145WithGost3411, oid)
}

#[cfg(feature = "legacy-gost3410")]
pub fn is_gost3410_signature_oid(oid: &str) -> bool {
    oid_matches_str(OidId::Gost34310WithGost34311, oid)
        || oid_matches_str(OidId::PkiGost3410, oid)
        || oid_matches_str(OidId::Gost3410Kz, oid)
}

pub fn oid_id_from_str(s: &str) -> Option<OidId> {
    oid_from_str(s)
}

fn uint_to_u32(value: &der::asn1::Uint) -> u32 {
    let mut out = 0u32;
    for byte in value.as_bytes() {
        out = (out << 8) | u32::from(*byte);
    }
    out
}

#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
struct Dstu4145Params {
    #[asn1(context_specific = "0", optional = "true")]
    field_degree: Option<der::asn1::Uint>,
    #[asn1(context_specific = "1", optional = "true")]
    a: Option<der::asn1::Uint>,
    #[asn1(context_specific = "2", optional = "true")]
    b: Option<der::asn1::OctetString>,
    #[asn1(context_specific = "3", optional = "true")]
    n: Option<der::asn1::OctetString>,
    #[asn1(context_specific = "4", optional = "true")]
    p_x: Option<der::asn1::OctetString>,
    #[asn1(context_specific = "5", optional = "true")]
    p_y: Option<der::asn1::OctetString>,
    #[asn1(context_specific = "6", optional = "true")]
    dke: Option<der::asn1::OctetString>,
}

mod hex_literal {
    macro_rules! hex {
        ($s:expr) => {{
            const INPUT: &str = $s;
            const fn decode(input: &str) -> [u8; INPUT.len() / 2] {
                let bytes = input.as_bytes();
                let mut out = [0u8; INPUT.len() / 2];
                let mut i = 0;
                while i < out.len() {
                    out[i] = (hex_nib(bytes[2 * i]) << 4) | hex_nib(bytes[2 * i + 1]);
                    i += 1;
                }
                out
            }
            const fn hex_nib(b: u8) -> u8 {
                match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => 0,
                }
            }
            decode(INPUT)
        }};
    }
    pub(crate) use hex;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gost3411_aid_matches_utest() {
        assert_eq!(
            gost3411_algorithm_der(),
            hex_literal::hex!("300c060a2a862402010101010201")
        );
    }
}
