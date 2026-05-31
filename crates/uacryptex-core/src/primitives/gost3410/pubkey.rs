//! GOST 34.10-94 public-key derivation (Cryptonite `gost3410_get_pubkey`).

use der::Decode;

use crate::error::{Error, Result};
use crate::math::{
    ecp_is_on_curve, ecp_mul, gfp_mod_add, gfp_mod_mul, gfp_mod_sqr, gfp_mod_sqrt, gfp_mod_sub,
    int_bit_len, int_cmp, int_get_bit, int_is_zero, EcPoint, WordArray,
};

use super::params::{CurveParams, MODULE_BYTES};

fn load_le_coord(bytes: &[u8], word_len: usize) -> WordArray {
    let mut padded = bytes.to_vec();
    if padded.len() < MODULE_BYTES {
        padded.resize(MODULE_BYTES, 0);
    } else if padded.len() > MODULE_BYTES {
        padded = padded[padded.len() - MODULE_BYTES..].to_vec();
    }
    let mut wa = WordArray::from_le_bytes(&padded);
    wa.change_len(word_len);
    wa
}

fn validate_affine_pubkey(params: &CurveParams, qx: &WordArray, qy: &WordArray) -> Result<()> {
    if int_cmp(qx, &params.ec.gfp.p) >= 0 {
        return Err(Error::InvalidParam("invalid public key".into()));
    }
    if int_cmp(qy, &params.ec.gfp.p) >= 0 || int_is_zero(qy) {
        return Err(Error::InvalidParam("invalid public key".into()));
    }
    if !ecp_is_on_curve(&params.ec, qx, qy) {
        return Err(Error::InvalidParam("invalid public key".into()));
    }
    Ok(())
}

pub fn get_pubkey(params: &CurveParams, d: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use super::util::load_be_scalar;
    let d_wa = load_be_scalar(d, params.q.buf.len());

    if int_is_zero(&d_wa) || int_cmp(&d_wa, &params.q) >= 0 {
        return Err(Error::InvalidParam("invalid GOST3410 private key".into()));
    }

    let mut pubkey = EcPoint::with_len(params.ec.len);
    ecp_mul(&params.ec, &params.base, &d_wa, &mut pubkey);

    if !ecp_is_on_curve(&params.ec, &pubkey.x, &pubkey.y) {
        return Err(Error::InvalidParam("derived point not on curve".into()));
    }

    Ok((
        pubkey.x.to_le_bytes_len(MODULE_BYTES),
        pubkey.y.to_le_bytes_len(MODULE_BYTES),
    ))
}

/// `gost3410_compress_pubkey` — stores `qx` (LE) and the LSB of `qy`.
pub fn compress_pubkey(params: &CurveParams, qx: &[u8], qy: &[u8]) -> Result<(Vec<u8>, u8)> {
    let qx_wa = load_le_coord(qx, params.ec.len);
    let qy_wa = load_le_coord(qy, params.ec.len);
    validate_affine_pubkey(params, &qx_wa, &qy_wa)?;
    let last_qy_bit = int_get_bit(&qy_wa, 0) as u8;
    Ok((qx.to_vec(), last_qy_bit))
}

/// `gost3410_decompress_pubkey` — restores `(qx, qy)` LE octets from compressed `x` + `qy` LSB.
pub fn decompress_pubkey(
    params: &CurveParams,
    q: &[u8],
    last_qy_bit: u8,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if last_qy_bit != 0 && last_qy_bit != 1 {
        return Err(Error::InvalidParam("invalid compressed public key".into()));
    }

    let gfp = &params.ec.gfp;
    let x = load_le_coord(q, params.ec.len);
    if int_cmp(&x, &gfp.p) >= 0 || int_is_zero(&x) {
        return Err(Error::InvalidParam("invalid compressed public key".into()));
    }

    let mut t = WordArray::with_zero(params.ec.len);
    let mut y = WordArray::with_zero(params.ec.len);
    gfp_mod_sqr(gfp, &x, &mut t);
    gfp_mod_add(gfp, &t, &params.ec.a, &mut y);
    gfp_mod_mul(gfp, &x, &y, &mut t);
    gfp_mod_add(gfp, &t, &params.ec.b, &mut y);
    if !gfp_mod_sqrt(gfp, &y, &mut t) {
        return Err(Error::InvalidParam("invalid compressed public key".into()));
    }
    y.copy_from_slice(&t);
    if int_get_bit(&y, 0) != last_qy_bit as u32 {
        gfp_mod_sub(gfp, &gfp.p, &y, &mut t);
        y.copy_from_slice(&t);
    }

    validate_affine_pubkey(params, &x, &y)?;

    let byte_len = (int_bit_len(&gfp.p) + 7) / 8;
    Ok((x.to_le_bytes_len(byte_len), y.to_le_bytes_len(byte_len)))
}

/// Decode SPKI bit string (OctetString DER wrapping `qx||qy` LE octets).
pub fn pubkey_from_spki_bitstring(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use der::asn1::OctetString;
    let octets = OctetString::from_der(raw)
        .map_err(|e| Error::InvalidParam(format!("GOST3410 SPKI octet string: {e}")))?;
    let bytes = octets.as_bytes();
    if bytes.len() != 2 * MODULE_BYTES {
        return Err(Error::InvalidParam(format!(
            "GOST3410 public key length mismatch: expected {}, got {}",
            2 * MODULE_BYTES,
            bytes.len()
        )));
    }
    Ok((
        bytes[..MODULE_BYTES].to_vec(),
        bytes[MODULE_BYTES..].to_vec(),
    ))
}

fn le_to_be(mut v: Vec<u8>) -> Vec<u8> {
    v.reverse();
    v
}

/// SPKI LE octets → verify-ready BE coordinates.
pub fn pubkey_be_from_spki_bitstring(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (qx, qy) = pubkey_from_spki_bitstring(raw)?;
    Ok((le_to_be(qx), le_to_be(qy)))
}
