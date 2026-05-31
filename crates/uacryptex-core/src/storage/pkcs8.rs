//! PKCS#8 private key containers (`cryptonite/src/storage/c/file/pkcs8.c`).

use der::asn1::{Any, OctetString, Uint};
use der::{Decode, Encode, Sequence};
use x509_cert::attr::Attributes;
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cert::Cert;
use crate::pki::crypto::{
    algorithm_identifier_der, build_dstu_spki_der, curve_params_from_spki_algorithm,
    ecdsa_curve_from_spki_algorithm, oid_str_under, spki_algorithm_der, DhAdapter, SignAdapter,
    VerifyAdapter,
};
#[cfg(feature = "legacy-gost3410")]
use crate::pki::crypto::build_gost3410_spki_der;
use crate::pki::oid::{oid_matches_str, OidId};
use crate::primitives::dstu4145::{
    compress_public_key, generate_private_key, public_key_from_private_key, RandomBytes,
    SystemRandom,
};
use crate::{Error, Result};

const RSA_KEY_OID: &str = "1.2.840.113549.1.1.1";
const DSA_KEY_OID: &str = "1.2.840.113549.1.4.1";

/// RFC 5208 `PrivateKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
pub struct PrivateKeyInfo {
    pub version: Uint,
    pub private_key_algorithm: AlgorithmIdentifier<Any>,
    pub private_key: OctetString,
    #[asn1(optional = "true")]
    pub attributes: Option<Attributes>,
}

/// Cryptonite `Pkcs8PrivatekeyType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs8PrivateKeyType {
    Dstu,
    Rsa,
    Dsa,
    Ecdsa,
    Gost3410,
    Unknown,
}

/// `pkcs8_decode`.
pub fn pkcs8_decode(der: &[u8]) -> Result<PrivateKeyInfo> {
    PrivateKeyInfo::from_der(der).map_err(|e| Error::Internal(format!("PrivateKeyInfo decode: {e}")))
}

/// `pkcs8_encode`.
pub fn pkcs8_encode(key: &PrivateKeyInfo) -> Result<Vec<u8>> {
    key.to_der()
        .map_err(|e| Error::Internal(format!("PrivateKeyInfo encode: {e}")))
}

/// `pkcs8_type`.
pub fn pkcs8_type(key: &PrivateKeyInfo) -> Pkcs8PrivateKeyType {
    let oid = key.private_key_algorithm.oid.to_string();
    if oid == DSA_KEY_OID {
        Pkcs8PrivateKeyType::Dsa
    } else if oid == RSA_KEY_OID {
        Pkcs8PrivateKeyType::Rsa
    } else if oid_str_under(OidId::PkiDstu4145WithGost3411, &oid) {
        Pkcs8PrivateKeyType::Dstu
    } else if oid_matches_str(OidId::EcPublicKeyType, &oid) {
        Pkcs8PrivateKeyType::Ecdsa
    } else if oid_matches_str(OidId::Gost34310WithGost34311, &oid) {
        Pkcs8PrivateKeyType::Gost3410
    } else if oid_matches_str(OidId::PkiGost3410, &oid) {
        Pkcs8PrivateKeyType::Gost3410
    } else {
        Pkcs8PrivateKeyType::Unknown
    }
}

/// `pkcs8_get_privatekey` (DSTU + ECDSA).
pub fn pkcs8_get_privatekey(key: &PrivateKeyInfo) -> Result<Vec<u8>> {
    match pkcs8_type(key) {
        Pkcs8PrivateKeyType::Dstu => Ok(key.private_key.as_bytes().to_vec()),
        Pkcs8PrivateKeyType::Ecdsa => extract_ecdsa_private_key(key),
        #[cfg(feature = "legacy-gost3410")]
        Pkcs8PrivateKeyType::Gost3410 => Ok(key.private_key.as_bytes().to_vec()),
        _ => Err(Error::Unsupported(
            "unsupported PKCS#8 private key type".into(),
        )),
    }
}

fn extract_ecdsa_private_key(key: &PrivateKeyInfo) -> Result<Vec<u8>> {
    key.private_key_algorithm.parameters.as_ref().ok_or_else(|| {
        Error::InvalidParam("ECDSA PrivateKeyInfo parameters missing".into())
    })?;
    let spki_aid = key.private_key_algorithm.to_der().map_err(|e| {
        Error::Internal(format!("private key algorithm encode: {e}"))
    })?;
    let curve = ecdsa_curve_from_spki_algorithm(&spki_aid)?;
    let len = curve.field_len();
    let raw = key.private_key.as_bytes();
    let mut out = if let Ok(ec) = EcPrivateKey::from_der(raw) {
        ec.private_key.as_bytes().to_vec()
    } else if raw.len() >= len {
        raw[raw.len() - len..].to_vec()
    } else {
        return Err(Error::InvalidParam("ECDSA private key too short".into()));
    };
    if out.len() != len {
        return Err(Error::InvalidParam(format!(
            "ECDSA private key length mismatch: expected {len}, got {}",
            out.len()
        )));
    }
    out.reverse();
    Ok(out)
}

/// Build SPKI DER from a PKCS#8 container (`pkcs8_get_spki`).
pub fn pkcs8_get_spki_der(key: &PrivateKeyInfo) -> Result<Vec<u8>> {
    match pkcs8_type(key) {
        Pkcs8PrivateKeyType::Dstu => {
            let private_key = pkcs8_get_privatekey(key)?;
            let spki_aid = key.private_key_algorithm.to_der().map_err(|e| {
                Error::Internal(format!("private key algorithm encode: {e}"))
            })?;
            let params = curve_params_from_spki_algorithm(&spki_aid)?;
            let public_key = public_key_from_private_key(&params, &private_key)?;
            let compressed = compress_public_key(&params, &public_key)?;
            build_dstu_spki_der(&spki_aid, &compressed)
        }
        Pkcs8PrivateKeyType::Ecdsa => {
            let private_key = pkcs8_get_privatekey(key)?;
            let spki_aid = key.private_key_algorithm.to_der().map_err(|e| {
                Error::Internal(format!("private key algorithm encode: {e}"))
            })?;
            let curve = ecdsa_curve_from_spki_algorithm(&spki_aid)?;
            let (qx, qy) = crate::primitives::intl::ecdsa_public_key_from_private(curve, &private_key)?;
            crate::primitives::intl::build_ecdsa_spki_der(&spki_aid, &qx, &qy)
        }
        #[cfg(feature = "legacy-gost3410")]
        Pkcs8PrivateKeyType::Gost3410 => {
            use crate::primitives::gost3410::{get_pubkey, ParamsId};
            let private_key = pkcs8_get_privatekey(key)?;
            let spki_aid = key.private_key_algorithm.to_der().map_err(|e| {
                Error::Internal(format!("private key algorithm encode: {e}"))
            })?;
            let params = ParamsId::Id1.curve_params().ok_or_else(|| {
                Error::Internal("GOST3410 params ID 1 unavailable".into())
            })?;
            let (qx, qy) = get_pubkey(&params, &private_key)?;
            build_gost3410_spki_der(&spki_aid, &qx, &qy)
        }
        _ => Err(Error::Unsupported(
            "unsupported PKCS#8 private key type".into(),
        )),
    }
}

/// `pkcs8_get_sign_adapter`.
pub fn pkcs8_get_sign_adapter(
    key: &PrivateKeyInfo,
    cert: Option<&Cert>,
) -> Result<SignAdapter> {
    let private_key = pkcs8_get_privatekey(key)?;
    match pkcs8_type(key) {
        Pkcs8PrivateKeyType::Dstu => {
            if let Some(cert) = cert {
                SignAdapter::init_by_cert(&private_key, cert)
            } else {
                let sign_aid = key.private_key_algorithm.to_der().map_err(|e| {
                    Error::Internal(format!("private key algorithm encode: {e}"))
                })?;
                SignAdapter::init_by_aid(&private_key, &sign_aid, &sign_aid)
            }
        }
        Pkcs8PrivateKeyType::Ecdsa => {
            if let Some(cert) = cert {
                SignAdapter::init_by_cert(&private_key, cert)
            } else {
                let sign_aid = algorithm_identifier_der(
                    OidId::EcdsaWithSha256,
                    None,
                )?;
                let spki_aid = key.private_key_algorithm.to_der().map_err(|e| {
                    Error::Internal(format!("private key algorithm encode: {e}"))
                })?;
                SignAdapter::init_by_aid(&private_key, &sign_aid, &spki_aid)
            }
        }
        #[cfg(feature = "legacy-gost3410")]
        Pkcs8PrivateKeyType::Gost3410 => {
            let sign_aid = key.private_key_algorithm.to_der().map_err(|e| {
                Error::Internal(format!("private key algorithm encode: {e}"))
            })?;
            if let Some(cert) = cert {
                SignAdapter::init_by_cert(&private_key, cert)
            } else {
                SignAdapter::init_by_aid(&private_key, &sign_aid, &sign_aid)
            }
        }
        _ => Err(Error::Unsupported(
            "unsupported PKCS#8 private key type".into(),
        )),
    }
}

/// `pkcs8_get_verify_adapter`.
pub fn pkcs8_get_verify_adapter(key: &PrivateKeyInfo) -> Result<VerifyAdapter> {
    let spki = pkcs8_get_spki_der(key)?;
    match pkcs8_type(key) {
        Pkcs8PrivateKeyType::Dstu => {
            let sign_aid = key.private_key_algorithm.to_der().map_err(|e| {
                Error::Internal(format!("private key algorithm encode: {e}"))
            })?;
            let spki_aid = spki_algorithm_der(&spki)?;
            VerifyAdapter::init_by_spki(&sign_aid, &spki, &spki_aid)
        }
        Pkcs8PrivateKeyType::Ecdsa => {
            let sign_aid = algorithm_identifier_der(
                OidId::EcdsaWithSha256,
                None,
            )?;
            let spki_aid = spki_algorithm_der(&spki)?;
            VerifyAdapter::init_by_spki(&sign_aid, &spki, &spki_aid)
        }
        #[cfg(feature = "legacy-gost3410")]
        Pkcs8PrivateKeyType::Gost3410 => {
            let sign_aid = key.private_key_algorithm.to_der().map_err(|e| {
                Error::Internal(format!("private key algorithm encode: {e}"))
            })?;
            let spki_aid = spki_algorithm_der(&spki)?;
            VerifyAdapter::init_by_spki(&sign_aid, &spki, &spki_aid)
        }
        _ => Err(Error::Unsupported(
            "unsupported PKCS#8 private key type".into(),
        )),
    }
}

#[derive(Sequence)]
struct EcPrivateKey {
    version: Uint,
    private_key: OctetString,
}

fn default_dstu_algorithm() -> Result<AlgorithmIdentifier<Any>> {
    let cert = Cert::decode(include_bytes!("../../../../testdata/pki/certificate257.der"))
        .map_err(|e| Error::Internal(format!("default cert: {e}")))?;
    let spki = cert.spki_der()?;
    let der = spki_algorithm_der(&spki)?;
    AlgorithmIdentifier::from_der(&der)
        .map_err(|e| Error::Internal(format!("default dstu aid: {e}")))
}

fn generate_dstu_private_key(aid: &AlgorithmIdentifier<Any>) -> Result<PrivateKeyInfo> {
    let params = curve_params_from_spki_algorithm(
        &aid.to_der()
            .map_err(|e| Error::Internal(format!("aid encode: {e}")))?,
    )?;
    let mut rng = SystemRandom;
    let d = generate_private_key(&params, &mut rng)?;
    Ok(PrivateKeyInfo {
        version: Uint::new(&[0]).map_err(|e| Error::Internal(format!("version: {e}")))?,
        private_key_algorithm: aid.clone(),
        private_key: OctetString::new(d).map_err(|e| Error::Internal(format!("key: {e}")))?,
        attributes: None,
    })
}

fn generate_ecdsa_private_key(aid: &AlgorithmIdentifier<Any>) -> Result<PrivateKeyInfo> {
    let aid_der = aid
        .to_der()
        .map_err(|e| Error::Internal(format!("aid encode: {e}")))?;
    let curve = ecdsa_curve_from_spki_algorithm(&aid_der)?;
    let len = curve.field_len();
    let mut rng = SystemRandom;
    let mut scalar_le = vec![0u8; len];
    loop {
        rng.fill(&mut scalar_le)?;
        if scalar_le.iter().any(|&b| b != 0) {
            break;
        }
    }
    let ec = EcPrivateKey {
        version: Uint::new(&[1]).map_err(|e| Error::Internal(format!("version: {e}")))?,
        private_key: OctetString::new(scalar_le)
            .map_err(|e| Error::Internal(format!("ec key: {e}")))?,
    };
    let ec_der = ec
        .to_der()
        .map_err(|e| Error::Internal(format!("ECPrivateKey encode: {e}")))?;
    Ok(PrivateKeyInfo {
        version: Uint::new(&[0]).map_err(|e| Error::Internal(format!("version: {e}")))?,
        private_key_algorithm: aid.clone(),
        private_key: OctetString::new(ec_der).map_err(|e| Error::Internal(format!("key: {e}")))?,
        attributes: None,
    })
}

/// `pkcs8_generate`.
pub fn pkcs8_generate(aid: Option<&[u8]>) -> Result<PrivateKeyInfo> {
    let algorithm = if let Some(aid) = aid {
        AlgorithmIdentifier::from_der(aid)
            .map_err(|e| Error::Internal(format!("algorithm decode: {e}")))?
    } else {
        default_dstu_algorithm()?
    };
    let probe = PrivateKeyInfo {
        version: Uint::new(&[0]).map_err(|e| Error::Internal(format!("version: {e}")))?,
        private_key_algorithm: algorithm.clone(),
        private_key: OctetString::new(&[1u8]).map_err(|e| Error::Internal(format!("key: {e}")))?,
        attributes: None,
    };
    match pkcs8_type(&probe) {
        Pkcs8PrivateKeyType::Dstu => generate_dstu_private_key(&algorithm),
        Pkcs8PrivateKeyType::Ecdsa => generate_ecdsa_private_key(&algorithm),
        _ => Err(Error::Unsupported(
            "unsupported PKCS#8 private key type".into(),
        )),
    }
}

/// `pkcs8_get_dh_adapter`.
pub fn pkcs8_get_dh_adapter(key: &PrivateKeyInfo) -> Result<DhAdapter> {
    match pkcs8_type(key) {
        Pkcs8PrivateKeyType::Dstu | Pkcs8PrivateKeyType::Ecdsa => {
            DhAdapter::init_from_private_key_info(key)
        }
        _ => Err(Error::Unsupported(
            "unsupported PKCS#8 private key type".into(),
        )),
    }
}

pub fn is_private_key_info(der: &[u8]) -> bool {
    PrivateKeyInfo::from_der(der).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs8_type_detects_dstu_from_epki_decrypt_vector() {
        use crate::storage::pkcs5::{pkcs5_decrypt_dstu, EncryptedPrivateKeyInfo};
        let der = hex::decode("308201AA3081B006092A864886F70D01050D3081A2304306092A864886F70D01050C30360420A75E8C61FC464EFAB889E6649432B008EE4E19150A83AA6F100F78FA2D7E5BC302022710300E060A2A8624020101010101020500305B060B2A86240201010101010103304C0408C72C952E189D42BD0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040481F43BF7164B530944870E1886E7B849CB18C6552D827D069BF67C986AA6F8308CAD701008A8FE00FA99EB4A3E36F00130C0A8F035AC47BC6A0D8946F423ECE5AF209DE31191F96922C5905E8BA6C71DB6091BD98E797C8B622041E9E9C6DF0FA1418891742E6EB7C39029A4179D6F90E9A9FAFA2877728B981A60E2758742ECE5D56E5BFE12A445E30C1926171714B1EC07D28A02BC924B8FB617F08A41461AFAAAEE88EFFA8F1ACD14C7C090AD27BECD140E34E0615200E41449422E7BFB8243B6C8DDFDBCF7151FF062C9BAAF4BFA95A072CEDE2D83EB01D2D37BE0CC2D0BF9B801D4FDBE51452DF5F3356F163B27CCE527E0858C").unwrap();
        let epki = EncryptedPrivateKeyInfo::from_der(&der).unwrap();
        let pki = pkcs8_decode(&pkcs5_decrypt_dstu(&epki, "123456").unwrap()).unwrap();
        assert_eq!(pkcs8_type(&pki), Pkcs8PrivateKeyType::Dstu);
        assert_eq!(pkcs8_get_privatekey(&pki).unwrap().len(), 32);
    }
}
