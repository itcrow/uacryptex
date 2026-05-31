//! GOST 34.10-94 signature generation (Cryptonite `gost3410_sign`).

use crate::error::{Error, Result};
use crate::math::{
    ecp_mul, gfp_mod, int_add, int_bit_len, int_cmp, int_is_zero, int_mul, int_truncate, EcPoint,
    WordArray,
};
use crate::primitives::dstu4145::RandomBytes;

use super::params::{CurveParams, MODULE_BYTES};
use super::util::{load_be_scalar, wa_to_be_module};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl Signature {
    pub fn from_be(r: Vec<u8>, s: Vec<u8>) -> Self {
        Self { r, s }
    }

    pub fn join_be(&self) -> Vec<u8> {
        let mut out = self.r.clone();
        out.extend_from_slice(&self.s);
        out
    }
}

fn int_rand(q: &WordArray, rng: &mut dyn RandomBytes) -> Result<WordArray> {
    let len = q.buf.len();
    let q_bit_len = int_bit_len(q);
    let mut bytes = vec![0u8; len * 8];
    loop {
        rng.fill(&mut bytes)?;
        let mut out = WordArray::from_be_bytes(&bytes);
        out.change_len(len);
        int_truncate(&mut out, q_bit_len);
        if !int_is_zero(&out) && int_cmp(&out, q) < 0 {
            return Ok(out);
        }
    }
}

fn validate_private_key(params: &CurveParams, d: &WordArray) -> Result<()> {
    if int_is_zero(d) || int_cmp(d, &params.q) >= 0 {
        return Err(Error::InvalidParam("invalid GOST3410 private key".into()));
    }
    Ok(())
}

/// Generate a private key scalar in `[1, q)`.
pub fn generate_private_key(
    params: &CurveParams,
    rng: &mut dyn RandomBytes,
) -> Result<Vec<u8>> {
    let k = int_rand(&params.q, rng)?;
    Ok(k.to_le_bytes_len(MODULE_BYTES))
}

/// Sign a digest (Cryptonite `ByteArray` / LE octets for hash in utest, BE for verify KAT).
pub fn sign(
    params: &CurveParams,
    private_key: &[u8],
    hash: &[u8],
    rng: &mut dyn RandomBytes,
) -> Result<Signature> {
    let d = load_be_scalar(private_key, params.q.buf.len());
    validate_private_key(params, &d)?;

    let mut hash_wa = WordArray::from_be_bytes(hash);
    let mut e = WordArray::with_zero(params.gfq.p.buf.len());
    hash_wa.change_len(hash_wa.buf.len() << 1);
    gfp_mod(&params.gfq, &hash_wa, &mut e);
    if int_is_zero(&e) {
        e.set_one();
    }

    let mut r = WordArray::with_zero(params.q.buf.len());
    let mut s = WordArray::with_zero(params.q.buf.len());

    loop {
        loop {
            let k = int_rand(&params.q, rng)?;
            let mut c = EcPoint::with_len(params.ec.len);
            ecp_mul(&params.ec, &params.base, &k, &mut c);

            let mut cx = c.x.clone();
            cx.change_len(cx.buf.len() << 1);
            gfp_mod(&params.gfq, &cx, &mut r);
            if !int_is_zero(&r) {
                let mut rd = WordArray::with_zero(2 * d.buf.len());
                int_mul(&r, &d, &mut rd);
                let mut ek = WordArray::with_zero(2 * k.buf.len());
                int_mul(&e, &k, &mut ek);
                let mut sum = WordArray::with_zero(ek.buf.len());
                int_add(&rd, &ek, &mut sum);
                gfp_mod(&params.gfq, &sum, &mut s);
                break;
            }
        }
        if !int_is_zero(&s) {
            break;
        }
    }

    Ok(Signature::from_be(
        wa_to_be_module(&r),
        wa_to_be_module(&s),
    ))
}

pub fn split_signature_be(signature: &[u8]) -> Result<Signature> {
    if signature.len() != 2 * MODULE_BYTES {
        return Err(Error::InvalidParam(format!(
            "invalid GOST3410 signature length: {}",
            signature.len()
        )));
    }
    Ok(Signature::from_be(
        signature[..MODULE_BYTES].to_vec(),
        signature[MODULE_BYTES..].to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dstu4145::SliceRandom;
    use crate::primitives::gost3410::{get_pubkey, verify, ParamsId};

    fn hex_be(s: &str) -> Vec<u8> {
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        hex::decode(s).expect("hex")
    }

    fn le_to_be(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        out.reverse();
        out
    }

    /// Cryptonite `utest_gost3410.c::utest_sign_verify` (params ID 2, PRNG seed 0x09×40).
    #[test]
    fn sign_verify_roundtrip_params2_utest() {
        let params = ParamsId::Id2.curve_params().unwrap();
        let d = hex_be("066E675EB37AE3C5736CE765824D6A8B6CAA5A489F4EEA270767A54D62C971");
        let hash = hex_be("719BD04194B68A33CAE7F9500ADABA9268719266D9951D681CF84924AAAF975F");

        let mut rng = SliceRandom::new(vec![0x09; 40]);
        let sig = sign(&params, &d, &hash, &mut rng).unwrap();
        let (qx, qy) = get_pubkey(&params, &d).unwrap();
        verify(
            &params,
            &le_to_be(&qx),
            &le_to_be(&qy),
            &hash,
            &sig.r,
            &sig.s,
        )
        .unwrap();
    }

    #[test]
    fn sign_verify_roundtrip_params1() {
        let params = ParamsId::Id1.curve_params().unwrap();
        let d = hex_be("7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28");
        let hash = hex_be("2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5");
        let mut rng = SliceRandom::new(vec![0x11; 64]);
        let sig = sign(&params, &d, &hash, &mut rng).unwrap();
        let (qx, qy) = get_pubkey(&params, &d).unwrap();
        verify(
            &params,
            &le_to_be(&qx),
            &le_to_be(&qy),
            &hash,
            &sig.r,
            &sig.s,
        )
        .unwrap();
    }
}
