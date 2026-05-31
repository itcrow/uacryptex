//! Cipher adapter (`cipher_adapter_init`, `cryptonite_manager.c`).

use der::{Any, Decode, Encode};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::crypto::aid::{oid_str_under, sbox_from_algorithm_der, spki_algorithm_der};
use crate::pki::oid::{oid_matches_str, OidId};
use crate::primitives::gost28147::{Gost28147, GOST28147_SBOX_LEN};
use crate::{Error, Result};

/// Cryptonite `CipherAdapter`.
pub struct CipherAdapter {
    cipher_aid: Vec<u8>,
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
                sbox,
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
            sbox: self.sbox,
            iv: self.iv.clone(),
        }
    }

    /// `ca->get_alg`.
    pub fn algorithm_der(&self) -> &[u8] {
        &self.cipher_aid
    }

    /// `ca->encrypt`.
    pub fn encrypt(&self, key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::InvalidParam("cipher key must be 32 bytes".into()));
        }
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

    /// `ca->decrypt`.
    pub fn decrypt(&self, key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(Error::InvalidParam("cipher key must be 32 bytes".into()));
        }
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
}

#[derive(der::Sequence)]
struct Gost28147Params {
    iv: der::asn1::OctetString,
    #[asn1(optional = "true")]
    dke: Option<der::asn1::OctetString>,
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

/// Build GOST28147 cipher AID with random IV and DKE from certificate SPKI.
pub fn get_gost28147_aid(
    rng: &mut dyn crate::primitives::dstu4145::RandomBytes,
    cipher_oid: OidId,
    cert: &crate::pki::cert::Cert,
) -> Result<Vec<u8>> {
    use crate::pki::crypto::aid::algorithm_identifier_der;
    use crate::primitives::gost28147::compress_sbox;

    let mut iv = [0u8; 8];
    rng.fill(&mut iv)?;
    let spki_aid = spki_algorithm_der(&cert.spki_der()?)?;
    let sbox = sbox_from_algorithm_der(&spki_aid)?;
    let dke = compress_sbox(&sbox);

    let iv_oct = der::asn1::OctetString::new(&iv)
        .map_err(|e| Error::Internal(format!("iv octet string: {e}")))?;
    let dke_oct = der::asn1::OctetString::new(&dke)
        .map_err(|e| Error::Internal(format!("dke octet string: {e}")))?;
    let params = Gost28147Params {
        iv: iv_oct,
        dke: Some(dke_oct),
    };
    let params_any = Any::encode_from(&params)
        .map_err(|e| Error::Internal(format!("GOST28147 params encode: {e}")))?;
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
