//! GOST 34.10-94 signature verification (Cryptonite `gost3410_verify`).

use crate::error::{Error, Result};
use crate::math::{
    ecp_dual_mul, ecp_is_on_curve, gfp_mod, gfp_mod_inv, gfp_mod_mul, gfp_mod_sub, int_ct_equals,
    int_cmp, int_is_zero, EcPoint, WordArray,
};

use super::params::CurveParams;

pub fn verify(
    params: &CurveParams,
    qx: &[u8],
    qy: &[u8],
    hash: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<()> {
    let mut r_wa = WordArray::from_be_bytes(r);
    let mut s_wa = WordArray::from_be_bytes(s);
    r_wa.change_len(params.ec.gfp.p.buf.len());
    s_wa.change_len(params.ec.gfp.p.buf.len());

    if int_cmp(&r_wa, &params.ec.gfp.p) >= 0
        || int_cmp(&s_wa, &params.ec.gfp.p) >= 0
        || int_is_zero(&r_wa)
        || int_is_zero(&s_wa)
    {
        return Err(Error::InvalidParam("invalid signature components".into()));
    }

    let mut qx_wa = WordArray::from_be_bytes(qx);
    let mut qy_wa = WordArray::from_be_bytes(qy);
    qx_wa.change_len(params.ec.len);
    qy_wa.change_len(params.ec.len);

    if int_is_zero(&qx_wa)
        || int_cmp(&qx_wa, &params.ec.gfp.p) >= 0
        || int_is_zero(&qy_wa)
        || int_cmp(&qy_wa, &params.ec.gfp.p) >= 0
        || !ecp_is_on_curve(&params.ec, &qx_wa, &qy_wa)
    {
        return Err(Error::InvalidParam("invalid public key".into()));
    }

    let q = EcPoint::from_affine(&qx_wa, &qy_wa);

    let mut hash_wa = WordArray::from_be_bytes(hash);
    let mut e = WordArray::with_zero(params.gfq.p.buf.len());
    hash_wa.change_len(hash_wa.buf.len() << 1);
    gfp_mod(&params.gfq, &hash_wa, &mut e);
    if int_is_zero(&e) {
        e.set_one();
    }

    let v = gfp_mod_inv(&params.gfq, &e).ok_or_else(|| Error::InvalidParam("hash not invertible mod q".into()))?;

    let mut z1 = WordArray::with_zero(v.buf.len());
    let mut z2 = WordArray::with_zero(v.buf.len());
    gfp_mod_mul(&params.gfq, &v, &s_wa, &mut z1);
    gfp_mod_mul(&params.gfq, &v, &r_wa, &mut z2);
    let neg_z2 = {
        let mut t = WordArray::with_zero(z2.buf.len());
        gfp_mod_sub(&params.gfq, &params.gfq.p, &z2, &mut t);
        t
    };
    z2.copy_from_slice(&neg_z2);

    let mut c = EcPoint::with_len(params.ec.len);
    ecp_dual_mul(&params.ec, &params.base, &z1, &q, &z2, &mut c);

    let mut r_check = WordArray::with_zero(v.buf.len());
    let mut cx = c.x.clone();
    cx.change_len(cx.buf.len() << 1);
    gfp_mod(&params.gfq, &cx, &mut r_check);

    if !int_ct_equals(&r_check, &r_wa) {
        return Err(Error::VerifyFailed);
    }

    Ok(())
}
