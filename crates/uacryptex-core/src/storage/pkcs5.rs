//! PKCS#5 PBES2 / PBKDF2 for DSTU private keys (`cryptonite/src/storage/c/file/pkcs5.c`).

use der::asn1::{Any, ObjectIdentifier, OctetString, Uint};
use der::{Decode, Sequence};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::crypto::{algorithm_identifier_der, oid_str_under};
use crate::pki::oid::{oid_matches_str, oid_to_str, OidId};
use crate::primitives::dstu4145::{RandomBytes, SystemRandom};
use crate::primitives::gost28147::{expand_dke, Gost28147, GOST28147_SBOX_LEN};
use crate::primitives::gost34_311::hmac_gost3411;
use crate::primitives::intl::{aes_cbc_decrypt, aes_cbc_encrypt, hmac_sha1};
use crate::{Error, Result};

/// Cryptonite `Pkcs5Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs5Type {
    Unknown,
    Dstu,
}

/// Cryptonite `Pbkdf2HmacId` (subset used by DSTU storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2HmacId {
    GostHmac,
    Sha1Hmac,
}

/// RFC 5208 / PKCS#8 `EncryptedPrivateKeyInfo`.
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPrivateKeyInfo {
    pub encryption_algorithm: AlgorithmIdentifier<Any>,
    pub encrypted_data: OctetString,
}

#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
struct Pbes2Params {
    key_derivation_func: Pbes2Kdfs,
    encryption_scheme: AlgorithmIdentifier<Any>,
}

#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
struct Pbes2Kdfs {
    algorithm: ObjectIdentifier,
    parameters: Pbkdf2Params,
}

#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
struct Pbkdf2Params {
    salt: OctetString,
    iteration_count: Uint,
    #[asn1(optional = "true")]
    key_length: Option<Uint>,
    #[asn1(optional = "true")]
    prf: Option<AlgorithmIdentifier<Any>>,
}

#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
struct Gost28147ParamsOptionalDke {
    iv: OctetString,
    #[asn1(optional = "true")]
    dke: Option<OctetString>,
}

/// `pkcs5_get_type`.
pub fn pkcs5_get_type(container: &EncryptedPrivateKeyInfo) -> Pkcs5Type {
    let oid = container.encryption_algorithm.oid.to_string();
    if oid_matches_str(OidId::Pbes2, &oid) {
        Pkcs5Type::Dstu
    } else {
        Pkcs5Type::Unknown
    }
}

/// PBKDF2 (`pbkdf2_f`).
pub fn pbkdf2(
    password: &str,
    salt: &[u8],
    iterations: u32,
    key_len: usize,
    hmac_id: Pbkdf2HmacId,
) -> Result<Vec<u8>> {
    if iterations == 0 {
        return Err(Error::InvalidParam(
            "PBKDF2 iteration count must be > 0".into(),
        ));
    }
    if key_len == 0 {
        return Err(Error::InvalidParam("PBKDF2 key length must be > 0".into()));
    }

    let hash_len = match hmac_id {
        Pbkdf2HmacId::GostHmac => 32,
        Pbkdf2HmacId::Sha1Hmac => 20,
    };

    let pass = password.as_bytes();
    let mut dk = Vec::with_capacity(key_len);
    let mut block = 1u32;

    while dk.len() < key_len {
        let count_bytes = block.to_be_bytes();
        let mut u = prf(hmac_id, pass, salt, &count_bytes)?;
        let mut t = u.clone();

        for _ in 1..iterations {
            u = prf(hmac_id, pass, &u, &[])?;
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }

        let take = (key_len - dk.len()).min(hash_len);
        dk.extend_from_slice(&t[..take]);
        block += 1;
    }

    Ok(dk)
}

fn prf(hmac_id: Pbkdf2HmacId, pass: &[u8], a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    match hmac_id {
        Pbkdf2HmacId::GostHmac => {
            let sync = [0u8; 32];
            let chunks: [&[u8]; 2] = [a, b];
            let out = hmac_gost3411(&sync, pass, &chunks)?;
            Ok(out.to_vec())
        }
        Pbkdf2HmacId::Sha1Hmac => {
            let mut msg = Vec::with_capacity(a.len() + b.len());
            msg.extend_from_slice(a);
            msg.extend_from_slice(b);
            Ok(hmac_sha1(pass, &msg).to_vec())
        }
    }
}

fn pbkdf2_hmac_id(prf: Option<&AlgorithmIdentifier<Any>>) -> Result<Pbkdf2HmacId> {
    match prf {
        None => Ok(Pbkdf2HmacId::Sha1Hmac),
        Some(aid) => {
            let oid = aid.oid.to_string();
            if oid_matches_str(OidId::PkiHmacGost3411, &oid) {
                Ok(Pbkdf2HmacId::GostHmac)
            } else if oid_matches_str(OidId::PkiHmacSha1, &oid) {
                Ok(Pbkdf2HmacId::Sha1Hmac)
            } else {
                Err(Error::Unsupported(format!(
                    "unsupported PBKDF2 PRF OID: {oid}"
                )))
            }
        }
    }
}

fn uint_to_u32(value: &Uint) -> u32 {
    let mut out = 0u32;
    for byte in value.as_bytes() {
        out = (out << 8) | u32::from(*byte);
    }
    out
}

fn gost28147_sbox_from_cipher_aid(
    aid: &AlgorithmIdentifier<Any>,
) -> Result<[u8; GOST28147_SBOX_LEN]> {
    let Some(params) = &aid.parameters else {
        return Ok(crate::primitives::gost28147::default_sbox());
    };
    let parsed = params
        .decode_as::<Gost28147ParamsOptionalDke>()
        .map_err(|e| Error::Internal(format!("GOST28147 params decode: {e}")))?;
    if let Some(dke) = parsed.dke {
        expand_dke(dke.as_bytes())
    } else {
        Ok(crate::primitives::gost28147::default_sbox())
    }
}

fn gost28147_iv_from_cipher_aid(aid: &AlgorithmIdentifier<Any>) -> Result<[u8; 8]> {
    let params = aid
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("GOST28147 cipher params missing".into()))?;
    let parsed = params
        .decode_as::<Gost28147ParamsOptionalDke>()
        .map_err(|e| Error::Internal(format!("GOST28147 params decode: {e}")))?;
    let iv = parsed.iv.as_bytes();
    if iv.len() != 8 {
        return Err(Error::InvalidParam(format!(
            "GOST28147 IV must be 8 bytes, got {}",
            iv.len()
        )));
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(iv);
    Ok(out)
}

/// PBES2 decrypt with GOST 28147 CFB (`pbes2_decrypt` + cipher adapter).
pub fn pbes2_decrypt_gost_cfb(
    encryption_scheme: &AlgorithmIdentifier<Any>,
    dk: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let oid = encryption_scheme.oid.to_string();
    if !oid_str_under(OidId::Gost28147Dstu, &oid) {
        return Err(Error::Unsupported(format!(
            "unsupported PBES2 encryption scheme OID: {oid}"
        )));
    }
    if dk.len() != 32 {
        return Err(Error::InvalidParam(format!(
            "GOST28147 key must be 32 bytes, got {}",
            dk.len()
        )));
    }

    let sbox = gost28147_sbox_from_cipher_aid(encryption_scheme)?;
    let iv = gost28147_iv_from_cipher_aid(encryption_scheme)?;

    let mut ctx = Gost28147::from_raw_sbox(&sbox);
    ctx.init_cfb(dk, &iv)?;
    let mut plaintext = vec![0u8; ciphertext.len()];
    ctx.cfb_crypt(ciphertext, &mut plaintext, false)?;
    Ok(plaintext)
}

fn aes_iv_from_cipher_aid(aid: &AlgorithmIdentifier<Any>) -> Result<[u8; 16]> {
    let params = aid
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("AES cipher params missing".into()))?;
    let iv = params
        .decode_as::<OctetString>()
        .map_err(|e| Error::Internal(format!("AES IV decode: {e}")))?;
    if iv.as_bytes().len() != 16 {
        return Err(Error::InvalidParam(format!(
            "AES IV must be 16 bytes, got {}",
            iv.as_bytes().len()
        )));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(iv.as_bytes());
    Ok(out)
}

fn pkcs7_pad(data: &[u8], block_len: usize) -> Vec<u8> {
    let pad_len = block_len - (data.len() % block_len);
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    let pad_len = *data
        .last()
        .ok_or_else(|| Error::InvalidParam("PKCS#7 padding missing".into()))?
        as usize;
    if pad_len == 0 || pad_len > data.len() {
        return Err(Error::InvalidParam("invalid PKCS#7 padding".into()));
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

/// PBES2 decrypt with AES-256-CBC.
pub fn pbes2_decrypt_aes_cbc(
    encryption_scheme: &AlgorithmIdentifier<Any>,
    dk: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if !oid_matches_str(OidId::Aes256Cbc, &encryption_scheme.oid.to_string()) {
        return Err(Error::Unsupported(
            "encryption scheme is not AES-256-CBC".into(),
        ));
    }
    let iv = aes_iv_from_cipher_aid(encryption_scheme)?;
    let decrypted = aes_cbc_decrypt(dk, &iv, ciphertext)?;
    pkcs7_unpad(&decrypted)
}

/// PBES2 encrypt with GOST 28147 CFB.
pub fn pbes2_encrypt_gost_cfb(
    encryption_scheme: &AlgorithmIdentifier<Any>,
    dk: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let oid = encryption_scheme.oid.to_string();
    if !oid_str_under(OidId::Gost28147Dstu, &oid) {
        return Err(Error::Unsupported(format!(
            "unsupported PBES2 encryption scheme OID: {oid}"
        )));
    }
    if dk.len() != 32 {
        return Err(Error::InvalidParam(format!(
            "GOST28147 key must be 32 bytes, got {}",
            dk.len()
        )));
    }
    let sbox = gost28147_sbox_from_cipher_aid(encryption_scheme)?;
    let iv = gost28147_iv_from_cipher_aid(encryption_scheme)?;
    let mut ctx = Gost28147::from_raw_sbox(&sbox);
    ctx.init_cfb(dk, &iv)?;
    let mut ciphertext = vec![0u8; plaintext.len()];
    ctx.cfb_crypt(plaintext, &mut ciphertext, true)?;
    Ok(ciphertext)
}

/// PBES2 encrypt with AES-256-CBC (PKCS#7 padding).
pub fn pbes2_encrypt_aes_cbc(
    encryption_scheme: &AlgorithmIdentifier<Any>,
    dk: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if !oid_matches_str(OidId::Aes256Cbc, &encryption_scheme.oid.to_string()) {
        return Err(Error::Unsupported(
            "encryption scheme is not AES-256-CBC".into(),
        ));
    }
    let iv = aes_iv_from_cipher_aid(encryption_scheme)?;
    let padded = pkcs7_pad(plaintext, 16);
    aes_cbc_encrypt(dk, &iv, &padded)
}

fn pbes2_params_from_epki(container: &EncryptedPrivateKeyInfo) -> Result<Pbes2Params> {
    let enc_oid = container.encryption_algorithm.oid.to_string();
    if !oid_matches_str(OidId::Pbes2, &enc_oid) {
        return Err(Error::Unsupported(
            "unsupported EncryptedPrivateKeyInfo algorithm".into(),
        ));
    }
    let params_any = container
        .encryption_algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("PBES2 parameters missing".into()))?;
    params_any
        .decode_as::<Pbes2Params>()
        .map_err(|e| Error::Internal(format!("PBES2-params decode: {e}")))
}

fn derive_pbes2_key(container: &Pbes2Params, password: &str) -> Result<Vec<u8>> {
    let kdf_oid = container.key_derivation_func.algorithm.to_string();
    if !oid_matches_str(OidId::Kdf, &kdf_oid) {
        return Err(Error::Unsupported(
            "unsupported key derivation function algorithm".into(),
        ));
    }
    let kdf = &container.key_derivation_func.parameters;
    let salt = kdf.salt.as_bytes();
    let iterations = uint_to_u32(&kdf.iteration_count);
    let hmac_id = pbkdf2_hmac_id(kdf.prf.as_ref())?;
    pbkdf2(password, salt, iterations, 32, hmac_id)
}

fn encrypt_with_pbes2_params(
    params: &Pbes2Params,
    password: &str,
    plaintext: &[u8],
) -> Result<EncryptedPrivateKeyInfo> {
    let dk = derive_pbes2_key(params, password)?;
    let scheme_oid = params.encryption_scheme.oid.to_string();
    let ciphertext = if oid_str_under(OidId::Gost28147Dstu, &scheme_oid) {
        pbes2_encrypt_gost_cfb(&params.encryption_scheme, &dk, plaintext)?
    } else if oid_matches_str(OidId::Aes256Cbc, &scheme_oid) {
        pbes2_encrypt_aes_cbc(&params.encryption_scheme, &dk, plaintext)?
    } else {
        return Err(Error::Unsupported(
            "unsupported PBES2 encryption scheme algorithm".into(),
        ));
    };
    Ok(EncryptedPrivateKeyInfo {
        encryption_algorithm: {
            let params_any = Any::encode_from(params)
                .map_err(|e| Error::Internal(format!("PBES2-params any: {e}")))?;
            let der = algorithm_identifier_der(OidId::Pbes2, Some(&params_any))?;
            AlgorithmIdentifier::from_der(&der)
                .map_err(|e| Error::Internal(format!("PBES2 aid decode: {e}")))?
        },
        encrypted_data: OctetString::new(ciphertext)
            .map_err(|e| Error::Internal(format!("encrypted data: {e}")))?,
    })
}

/// Build a GOST 28147 CFB encryption `AlgorithmIdentifier` with IV.
pub fn gost28147_cfb_encryption_aid(iv: &[u8; 8]) -> Result<AlgorithmIdentifier<Any>> {
    let params = Gost28147ParamsOptionalDke {
        iv: OctetString::new(iv).map_err(|e| Error::Internal(format!("IV: {e}")))?,
        dke: None,
    };
    let params_any = Any::encode_from(&params)
        .map_err(|e| Error::Internal(format!("GOST28147 params any: {e}")))?;
    let der = algorithm_identifier_der(OidId::Gost28147Cfb, Some(&params_any))?;
    AlgorithmIdentifier::from_der(&der)
        .map_err(|e| Error::Internal(format!("GOST28147 aid decode: {e}")))
}

/// Build AES-256-CBC encryption `AlgorithmIdentifier` with IV.
pub fn aes256_cbc_encryption_aid(iv: &[u8; 16]) -> Result<AlgorithmIdentifier<Any>> {
    let params_any =
        Any::encode_from(&OctetString::new(iv).map_err(|e| Error::Internal(format!("IV: {e}")))?)
            .map_err(|e| Error::Internal(format!("AES IV any: {e}")))?;
    let der = algorithm_identifier_der(OidId::Aes256Cbc, Some(&params_any))?;
    AlgorithmIdentifier::from_der(&der).map_err(|e| Error::Internal(format!("AES aid decode: {e}")))
}

fn u32_to_uint(value: u32) -> Result<Uint> {
    if value == 0 {
        return Uint::new(&[0u8]).map_err(|e| Error::Internal(format!("uint: {e}")));
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(7);
    Uint::new(&be[start..]).map_err(|e| Error::Internal(format!("uint: {e}")))
}

fn build_pbes2_params(
    password_scheme: &AlgorithmIdentifier<Any>,
    salt: &[u8],
    iterations: u32,
    use_gost_prf: bool,
) -> Result<Pbes2Params> {
    let prf = if use_gost_prf {
        let der = algorithm_identifier_der(OidId::PkiHmacGost3411, None)?;
        Some(
            AlgorithmIdentifier::from_der(&der)
                .map_err(|e| Error::Internal(format!("PRF aid decode: {e}")))?,
        )
    } else {
        None
    };
    Ok(Pbes2Params {
        key_derivation_func: Pbes2Kdfs {
            algorithm: ObjectIdentifier::new(
                &oid_to_str(OidId::Kdf)
                    .ok_or_else(|| Error::Internal("PBKDF2 OID missing from registry".into()))?,
            )
            .map_err(|e| Error::Internal(format!("PBKDF2 OID: {e}")))?,
            parameters: Pbkdf2Params {
                salt: OctetString::new(salt).map_err(|e| Error::Internal(format!("salt: {e}")))?,
                iteration_count: u32_to_uint(iterations)?,
                key_length: None,
                prf,
            },
        },
        encryption_scheme: password_scheme.clone(),
    })
}

/// `pkcs5_encrypt_dstu` / PBES2 encrypt for storage.
pub fn pkcs5_encrypt_dstu(
    plaintext: &[u8],
    password: &str,
    salt: &[u8],
    iterations: u32,
    encrypt_aid: &AlgorithmIdentifier<Any>,
) -> Result<EncryptedPrivateKeyInfo> {
    let use_gost_prf = oid_str_under(OidId::Gost28147Dstu, &encrypt_aid.oid.to_string());
    let params = build_pbes2_params(encrypt_aid, salt, iterations, use_gost_prf)?;
    encrypt_with_pbes2_params(&params, password, plaintext)
}

/// Re-encrypt using PBES2 parameters from an existing container (preserves salt/IV/scheme).
pub fn pkcs5_reencrypt_pbes2(
    template: &EncryptedPrivateKeyInfo,
    password: &str,
    plaintext: &[u8],
) -> Result<EncryptedPrivateKeyInfo> {
    let params = pbes2_params_from_epki(template)?;
    encrypt_with_pbes2_params(&params, password, plaintext)
}

/// Random salt for PKCS#12 key/certificate bags.
pub fn pkcs12_random_salt(len: usize) -> Result<Vec<u8>> {
    let mut salt = vec![0u8; len];
    let mut rng = SystemRandom;
    rng.fill(&mut salt)
        .map_err(|e| Error::Internal(format!("random salt: {e}")))?;
    Ok(salt)
}

/// Random IV for GOST28147 CFB.
pub fn random_gost28147_iv() -> Result<[u8; 8]> {
    let mut iv = [0u8; 8];
    let mut rng = SystemRandom;
    rng.fill(&mut iv)
        .map_err(|e| Error::Internal(format!("random iv: {e}")))?;
    Ok(iv)
}

/// Random IV for AES-256-CBC.
pub fn random_aes_iv() -> Result<[u8; 16]> {
    let mut iv = [0u8; 16];
    let mut rng = SystemRandom;
    rng.fill(&mut iv)
        .map_err(|e| Error::Internal(format!("random iv: {e}")))?;
    Ok(iv)
}

/// `pkcs5_decrypt_dstu`.
pub fn pkcs5_decrypt_dstu(container: &EncryptedPrivateKeyInfo, password: &str) -> Result<Vec<u8>> {
    let params = pbes2_params_from_epki(container)?;

    let scheme_oid = params.encryption_scheme.oid.to_string();
    let gost_scheme = oid_str_under(OidId::Gost28147Dstu, &scheme_oid);
    let aes_scheme = oid_matches_str(OidId::Aes256Cbc, &scheme_oid);
    if !gost_scheme && !aes_scheme {
        return Err(Error::Unsupported(
            "unsupported PBES2 encryption scheme algorithm".into(),
        ));
    }

    let dk = derive_pbes2_key(&params, password)?;

    if gost_scheme {
        pbes2_decrypt_gost_cfb(
            &params.encryption_scheme,
            &dk,
            container.encrypted_data.as_bytes(),
        )
    } else {
        pbes2_decrypt_aes_cbc(
            &params.encryption_scheme,
            &dk,
            container.encrypted_data.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn pkcs5_get_type_matches_utest_vector() {
        let der = hex(
            "308201AA3081B006092A864886F70D01050D3081A2304306092A864886F70D01050C30360420A75E8C61FC464EFAB889E6649432B008EE4E19150A83AA6F100F78FA2D7E5BC302022710300E060A2A8624020101010101020500305B060B2A86240201010101010103304C0408C72C952E189D42BD0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040481F43BF7164B530944870E1886E7B849CB18C6552D827D069BF67C986AA6F8308CAD701008A8FE00FA99EB4A3E36F00130C0A8F035AC47BC6A0D8946F423ECE5AF209DE31191F96922C5905E8BA6C71DB6091BD98E797C8B622041E9E9C6DF0FA1418891742E6EB7C39029A4179D6F90E9A9FAFA2877728B981A60E2758742ECE5D56E5BFE12A445E30C1926171714B1EC07D28A02BC924B8FB617F08A41461AFAAAEE88EFFA8F1ACD14C7C090AD27BECD140E34E0615200E41449422E7BFB8243B6C8DDFDBCF7151FF062C9BAAF4BFA95A072CEDE2D83EB01D2D37BE0CC2D0BF9B801D4FDBE51452DF5F3356F163B27CCE527E0858C",
        );
        let epki = EncryptedPrivateKeyInfo::from_der(&der).unwrap();
        assert_eq!(pkcs5_get_type(&epki), Pkcs5Type::Dstu);
    }

    #[test]
    fn pkcs5_decrypt_dstu_utest_vector() {
        let der = hex(
            "308201AA3081B006092A864886F70D01050D3081A2304306092A864886F70D01050C30360420A75E8C61FC464EFAB889E6649432B008EE4E19150A83AA6F100F78FA2D7E5BC302022710300E060A2A8624020101010101020500305B060B2A86240201010101010103304C0408C72C952E189D42BD0440A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E9720DC615B43A28975F0BC1DEA36438B564EA2C179FD0123E6DB8FAC579040481F43BF7164B530944870E1886E7B849CB18C6552D827D069BF67C986AA6F8308CAD701008A8FE00FA99EB4A3E36F00130C0A8F035AC47BC6A0D8946F423ECE5AF209DE31191F96922C5905E8BA6C71DB6091BD98E797C8B622041E9E9C6DF0FA1418891742E6EB7C39029A4179D6F90E9A9FAFA2877728B981A60E2758742ECE5D56E5BFE12A445E30C1926171714B1EC07D28A02BC924B8FB617F08A41461AFAAAEE88EFFA8F1ACD14C7C090AD27BECD140E34E0615200E41449422E7BFB8243B6C8DDFDBCF7151FF062C9BAAF4BFA95A072CEDE2D83EB01D2D37BE0CC2D0BF9B801D4FDBE51452DF5F3356F163B27CCE527E0858C",
        );
        let epki = EncryptedPrivateKeyInfo::from_der(&der).unwrap();
        let key = pkcs5_decrypt_dstu(&epki, "123456").unwrap();
        assert_eq!(key[0], 0x30);
        assert!(key.len() > 16);
    }
}
