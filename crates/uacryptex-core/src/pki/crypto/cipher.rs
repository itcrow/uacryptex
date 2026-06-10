//! Cipher adapter (`cipher_adapter_init`, `cryptonite_manager.c`).

use der::{Any, Decode};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cert::Cert;
use crate::pki::crypto::aid::{oid_str_under, sbox_from_algorithm_der, spki_algorithm_der};
use crate::pki::oid::{oid_matches_str, OidId};
use crate::primitives::dstu7624::Dstu7624Gcm;
use crate::primitives::gost28147::{Gost28147, GOST28147_SBOX_LEN};
use crate::{Error, Result};

/// CMS content encryption variants supported by EnvelopedData.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCipherOid {
    Gost28147Cfb,
    Gost28147Ofb,
    Kalyna128Gcm,
    Kalyna256Gcm,
    Kalyna512Gcm,
}

impl ContentCipherOid {
    pub fn to_oid_id(self) -> OidId {
        match self {
            Self::Gost28147Cfb => OidId::Gost28147Cfb,
            Self::Gost28147Ofb => OidId::Gost28147Ofb,
            Self::Kalyna128Gcm => OidId::Dstu7624Gmac128,
            Self::Kalyna256Gcm => OidId::Dstu7624Gmac256,
            Self::Kalyna512Gcm => OidId::Dstu7624Gmac512,
        }
    }

    pub fn from_oid_id(id: OidId) -> Result<Self> {
        match id {
            OidId::Gost28147Cfb => Ok(Self::Gost28147Cfb),
            OidId::Gost28147Ofb => Ok(Self::Gost28147Ofb),
            OidId::Dstu7624Gmac128 => Ok(Self::Kalyna128Gcm),
            OidId::Dstu7624Gmac256 => Ok(Self::Kalyna256Gcm),
            OidId::Dstu7624Gmac512 => Ok(Self::Kalyna512Gcm),
            _ => Err(Error::Unsupported(format!(
                "unsupported CMS content cipher OID id: {id:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CipherMode {
    Gost28147,
    Dstu7624Gcm { key_len: usize, q: usize },
}

/// Cryptonite `CipherAdapter`.
pub struct CipherAdapter {
    cipher_aid: Vec<u8>,
    mode: CipherMode,
    sbox: [u8; GOST28147_SBOX_LEN],
    iv: Vec<u8>,
}

impl CipherAdapter {
    /// `cipher_adapter_init`.
    pub fn init(algorithm_der: &[u8]) -> Result<Self> {
        let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(algorithm_der)
            .map_err(|e| Error::Internal(format!("cipher aid decode: {e}")))?;
        let oid = aid.oid.to_string();

        if oid_str_under(OidId::Gost28147Dstu, &oid)
            || oid_matches_str(OidId::Gost28147Cfb, &oid)
            || oid_matches_str(OidId::Gost28147Ofb, &oid)
        {
            let (iv, sbox) = gost28147_params_from_aid(&aid)?;
            return Ok(Self {
                cipher_aid: algorithm_der.to_vec(),
                mode: CipherMode::Gost28147,
                sbox,
                iv,
            });
        }

        if oid_str_under(OidId::Dstu7624Gmac, &oid) {
            let cipher = content_cipher_from_oid_str(&oid)?;
            let (key_len, iv_len, q) = dstu7624_gcm_sizes(cipher.to_oid_id())?;
            let (iv, q_param) = dstu7624_gcm_params_from_aid(&aid, iv_len, q)?;
            return Ok(Self {
                cipher_aid: algorithm_der.to_vec(),
                mode: CipherMode::Dstu7624Gcm { key_len, q: q_param },
                sbox: crate::primitives::gost28147::default_sbox(),
                iv,
            });
        }

        Err(Error::Unsupported(format!(
            "unsupported cipher algorithm: {oid}"
        )))
    }

    /// `cipher_adapter_copy_with_alloc`.
    pub fn clone_state(&self) -> Self {
        Self {
            cipher_aid: self.cipher_aid.clone(),
            mode: self.mode,
            sbox: self.sbox,
            iv: self.iv.clone(),
        }
    }

    /// `ca->get_alg`.
    pub fn algorithm_der(&self) -> &[u8] {
        &self.cipher_aid
    }

    fn key_len(&self) -> usize {
        match self.mode {
            CipherMode::Gost28147 => 32,
            CipherMode::Dstu7624Gcm { key_len, .. } => key_len,
        }
    }

    fn normalize_key<'a>(&self, session_key: &'a [u8]) -> Result<&'a [u8]> {
        let len = self.key_len();
        if session_key.len() < len {
            return Err(Error::InvalidParam(format!(
                "session key must be at least {len} bytes for this cipher"
            )));
        }
        Ok(&session_key[..len])
    }

    /// `ca->encrypt`.
    pub fn encrypt(&self, session_key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
        let key = self.normalize_key(session_key)?;
        match self.mode {
            CipherMode::Gost28147 => self.encrypt_gost28147(key, src),
            CipherMode::Dstu7624Gcm { q, .. } => self.encrypt_dstu7624_gcm(key, src, q),
        }
    }

    /// `ca->decrypt`.
    pub fn decrypt(&self, session_key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
        let key = self.normalize_key(session_key)?;
        match self.mode {
            CipherMode::Gost28147 => self.decrypt_gost28147(key, src),
            CipherMode::Dstu7624Gcm { q, .. } => self.decrypt_dstu7624_gcm(key, src, q),
        }
    }

    fn encrypt_gost28147(&self, key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
        let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(&self.cipher_aid)
            .map_err(|e| Error::Internal(format!("cipher aid decode: {e}")))?;
        let oid = aid.oid.to_string();
        let mut ctx = Gost28147::from_raw_sbox(&self.sbox);

        if oid_str_under(OidId::Gost28147Ofb, &oid) {
            ctx.init_ctr(key, &self.iv)?;
            let mut out = vec![0u8; src.len()];
            ctx.ctr_crypt(src, &mut out)?;
            Ok(out)
        } else if oid_str_under(OidId::Gost28147Cfb, &oid)
            || oid_str_under(OidId::Gost28147Dstu, &oid)
        {
            ctx.init_cfb(key, &self.iv)?;
            let mut out = vec![0u8; src.len()];
            ctx.cfb_crypt(src, &mut out, true)?;
            Ok(out)
        } else {
            Err(Error::Unsupported(format!(
                "unsupported cipher mode: {oid}"
            )))
        }
    }

    fn decrypt_gost28147(&self, key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
        let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(&self.cipher_aid)
            .map_err(|e| Error::Internal(format!("cipher aid decode: {e}")))?;
        let oid = aid.oid.to_string();
        let mut ctx = Gost28147::from_raw_sbox(&self.sbox);

        if oid_str_under(OidId::Gost28147Ofb, &oid) {
            ctx.init_ctr(key, &self.iv)?;
            let mut out = vec![0u8; src.len()];
            ctx.ctr_crypt(src, &mut out)?;
            Ok(out)
        } else if oid_str_under(OidId::Gost28147Cfb, &oid)
            || oid_str_under(OidId::Gost28147Dstu, &oid)
        {
            ctx.init_cfb(key, &self.iv)?;
            let mut out = vec![0u8; src.len()];
            ctx.cfb_crypt(src, &mut out, false)?;
            Ok(out)
        } else {
            Err(Error::Unsupported(format!(
                "unsupported cipher mode: {oid}"
            )))
        }
    }

    fn encrypt_dstu7624_gcm(&self, key: &[u8], src: &[u8], q: usize) -> Result<Vec<u8>> {
        let ctx = Dstu7624Gcm::init(key, &self.iv, q)?;
        let (cipher, tag) = ctx.encrypt(src, &[])?;
        let mut out = cipher;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn decrypt_dstu7624_gcm(&self, key: &[u8], src: &[u8], q: usize) -> Result<Vec<u8>> {
        if src.len() < q {
            return Err(Error::InvalidParam(
                "Kalyna-GCM ciphertext shorter than authentication tag".into(),
            ));
        }
        let split = src.len() - q;
        let (cipher, tag) = src.split_at(split);
        let ctx = Dstu7624Gcm::init(key, &self.iv, q)?;
        ctx.decrypt(cipher, tag, &[])
    }
}

#[derive(der::Sequence)]
struct Gost28147Params {
    iv: der::asn1::OctetString,
    #[asn1(optional = "true")]
    dke: Option<der::asn1::OctetString>,
}

/// DSTU 7624 GCM/GMAC algorithm parameters (IV + tag length `q`).
#[derive(der::Sequence)]
struct Dstu7624GcmParams {
    iv: der::asn1::OctetString,
    #[asn1(optional = "true")]
    q: Option<der::asn1::Uint>,
}

fn gost28147_params_from_aid(
    aid: &AlgorithmIdentifier<Any>,
) -> Result<(Vec<u8>, [u8; GOST28147_SBOX_LEN])> {
    let params = aid
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("GOST28147 cipher aid missing parameters".into()))?;
    let parsed: Gost28147Params = params
        .decode_as()
        .map_err(|e| Error::Internal(format!("GOST28147 params decode: {e}")))?;
    let iv = parsed.iv.as_bytes();
    if iv.len() != 8 {
        return Err(Error::InvalidParam("GOST28147 IV must be 8 bytes".into()));
    }
    let sbox = if let Some(dke) = parsed.dke {
        crate::primitives::gost28147::expand_dke(dke.as_bytes())?
    } else {
        crate::primitives::gost28147::default_sbox()
    };
    Ok((iv.to_vec(), sbox))
}

fn dstu7624_gcm_params_from_aid(
    aid: &AlgorithmIdentifier<Any>,
    iv_len: usize,
    default_q: usize,
) -> Result<(Vec<u8>, usize)> {
    let params = aid
        .parameters
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("DSTU7624 GCM aid missing parameters".into()))?;
    let parsed: Dstu7624GcmParams = params
        .decode_as()
        .map_err(|e| Error::Internal(format!("DSTU7624 GCM params decode: {e}")))?;
    let iv = parsed.iv.as_bytes();
    if iv.len() != iv_len {
        return Err(Error::InvalidParam(format!(
            "DSTU7624 GCM IV must be {iv_len} bytes"
        )));
    }
    let q = parsed
        .q
        .as_ref()
        .map(uint_to_usize)
        .unwrap_or(default_q);
    if !(8..=iv_len).contains(&q) {
        return Err(Error::InvalidParam(format!(
            "DSTU7624 GCM tag length q must be in 8..={iv_len}"
        )));
    }
    Ok((iv.to_vec(), q))
}

fn content_cipher_from_oid_str(oid: &str) -> Result<ContentCipherOid> {
    if oid_matches_str(OidId::Dstu7624Gmac128, oid) {
        Ok(ContentCipherOid::Kalyna128Gcm)
    } else if oid_matches_str(OidId::Dstu7624Gmac256, oid) {
        Ok(ContentCipherOid::Kalyna256Gcm)
    } else if oid_matches_str(OidId::Dstu7624Gmac512, oid) {
        Ok(ContentCipherOid::Kalyna512Gcm)
    } else {
        Err(Error::Unsupported(format!(
            "unsupported DSTU7624 GCM OID: {oid}"
        )))
    }
}

fn uint_to_usize(value: &der::asn1::Uint) -> usize {
    let mut out = 0usize;
    for byte in value.as_bytes() {
        out = (out << 8) | usize::from(*byte);
    }
    out
}

fn uint_from_usize(value: usize) -> Result<der::asn1::Uint> {
    if value == 0 {
        return der::asn1::Uint::new(&[0u8])
            .map_err(|e| Error::Internal(format!("uint encode: {e}")));
    }
    let be = (value as u64).to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    der::asn1::Uint::new(&be[start..]).map_err(|e| Error::Internal(format!("uint encode: {e}")))
}

/// `(key_len, iv_len, default_q)` for a Kalyna-GCM content cipher OID.
pub fn dstu7624_gcm_sizes(cipher_oid: OidId) -> Result<(usize, usize, usize)> {
    match cipher_oid {
        OidId::Dstu7624Gmac128 => Ok((16, 16, 16)),
        OidId::Dstu7624Gmac256 => Ok((32, 32, 32)),
        OidId::Dstu7624Gmac512 => Ok((64, 64, 64)),
        _ => Err(Error::InvalidParam(format!(
            "not a DSTU7624 GCM content OID: {cipher_oid:?}"
        ))),
    }
}

/// CEK length stored/wrapped for EnvelopedData (GOST28147-Wrap supports 32-byte blocks;
/// Kalyna-128 uses a 32-byte wrapped CEK with the first 16 bytes as the cipher key).
pub fn session_key_wrap_len(cipher_oid: OidId) -> Result<usize> {
    match cipher_oid {
        OidId::Dstu7624Gmac512 => Ok(64),
        OidId::Dstu7624Gmac128
        | OidId::Dstu7624Gmac256
        | OidId::Gost28147Cfb
        | OidId::Gost28147Ofb => Ok(32),
        _ => Ok(32),
    }
}

/// Session/content-encryption key length for a CMS content cipher OID.
pub fn content_cipher_key_len(cipher_oid: OidId) -> Result<usize> {
    if matches!(
        cipher_oid,
        OidId::Dstu7624Gmac128 | OidId::Dstu7624Gmac256 | OidId::Dstu7624Gmac512
    ) {
        Ok(dstu7624_gcm_sizes(cipher_oid)?.0)
    } else {
        Ok(32)
    }
}

/// Build content cipher AID for EnvelopedData (GOST28147 or Kalyna-GCM).
pub fn get_content_cipher_aid(
    rng: &mut dyn crate::primitives::dstu4145::RandomBytes,
    cipher_oid: OidId,
    cert: &Cert,
) -> Result<Vec<u8>> {
    if matches!(
        cipher_oid,
        OidId::Dstu7624Gmac128 | OidId::Dstu7624Gmac256 | OidId::Dstu7624Gmac512
    ) {
        get_dstu7624_gcm_aid(rng, cipher_oid)
    } else {
        get_gost28147_aid(rng, cipher_oid, cert)
    }
}

/// Build GOST28147 cipher AID with random IV and DKE from certificate SPKI.
pub fn get_gost28147_aid(
    rng: &mut dyn crate::primitives::dstu4145::RandomBytes,
    cipher_oid: OidId,
    cert: &Cert,
) -> Result<Vec<u8>> {
    use crate::pki::crypto::aid::algorithm_identifier_der;
    use crate::primitives::gost28147::compress_sbox;

    let mut iv = [0u8; 8];
    rng.fill(&mut iv)?;
    let spki_aid = spki_algorithm_der(&cert.spki_der()?)?;
    let sbox = sbox_from_algorithm_der(&spki_aid)?;
    let dke = compress_sbox(&sbox);

    let iv_oct = der::asn1::OctetString::new(iv)
        .map_err(|e| Error::Internal(format!("iv octet string: {e}")))?;
    let dke_oct = der::asn1::OctetString::new(dke)
        .map_err(|e| Error::Internal(format!("dke octet string: {e}")))?;
    let params = Gost28147Params {
        iv: iv_oct,
        dke: Some(dke_oct),
    };
    let params_any = Any::encode_from(&params)
        .map_err(|e| Error::Internal(format!("GOST28147 params encode: {e}")))?;
    algorithm_identifier_der(cipher_oid, Some(&params_any))
}

/// Build Kalyna-GCM (DSTU7624 GMAC) cipher AID with random IV.
pub fn get_dstu7624_gcm_aid(
    rng: &mut dyn crate::primitives::dstu4145::RandomBytes,
    cipher_oid: OidId,
) -> Result<Vec<u8>> {
    use crate::pki::crypto::aid::algorithm_identifier_der;

    let (_key_len, iv_len, q) = dstu7624_gcm_sizes(cipher_oid)?;
    let mut iv = vec![0u8; iv_len];
    rng.fill(&mut iv)?;
    let iv_oct = der::asn1::OctetString::new(iv)
        .map_err(|e| Error::Internal(format!("iv octet string: {e}")))?;
    let q_uint = uint_from_usize(q)?;
    let params = Dstu7624GcmParams {
        iv: iv_oct,
        q: Some(q_uint),
    };
    let params_any = Any::encode_from(&params)
        .map_err(|e| Error::Internal(format!("DSTU7624 GCM params encode: {e}")))?;
    algorithm_identifier_der(cipher_oid, Some(&params_any))
}

/// `aid_create_gost28147_wrap`.
pub fn create_gost28147_wrap_aid() -> Result<Vec<u8>> {
    use der::asn1::Null;
    let null = Null;
    let params_any =
        Any::encode_from(&null).map_err(|e| Error::Internal(format!("NULL encode: {e}")))?;
    crate::pki::crypto::aid::algorithm_identifier_der(OidId::Gost28147Wrap, Some(&params_any))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::crypto::MasterPrng;
    use crate::primitives::dstu4145::RandomBytes;

    fn userfiz_cert() -> Cert {
        Cert::decode(include_bytes!(
            "../../../../../testdata/pki/pki_example/userfiz_certificate.cer"
        ))
        .unwrap()
    }

    #[test]
    fn dstu7624_gcm_cipher_adapter_roundtrip() {
        let mut prng = MasterPrng::new().unwrap().dstu_prng().unwrap();
        let aid = get_dstu7624_gcm_aid(&mut prng, OidId::Dstu7624Gmac256).unwrap();
        let ca = CipherAdapter::init(&aid).unwrap();
        let mut key = [0u8; 32];
        prng.fill(&mut key).unwrap();
        let data = b"Status message for enveloped data test";
        let enc = ca.encrypt(&key, data).unwrap();
        let dec = ca.decrypt(&key, &enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn gost28147_cipher_adapter_still_works() {
        let cert = userfiz_cert();
        let mut prng = MasterPrng::new().unwrap().dstu_prng().unwrap();
        let aid = get_gost28147_aid(&mut prng, OidId::Gost28147Cfb, &cert).unwrap();
        let ca = CipherAdapter::init(&aid).unwrap();
        let mut key = [0u8; 32];
        prng.fill(&mut key).unwrap();
        let data = [0u8];
        let enc = ca.encrypt(&key, &data).unwrap();
        let dec = ca.decrypt(&key, &enc).unwrap();
        assert_eq!(dec, data);
    }
}
