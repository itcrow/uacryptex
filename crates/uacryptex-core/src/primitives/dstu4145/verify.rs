//! DSTU 4145 signature verification.
//!
//! Algorithm reference: DSTU 4145-2002, Cryptonite `dstu4145_verify()`.

use super::OnbTables;
use super::{CurveParams, PublicKey, Signature};
use crate::math::{
    ec2m_dual_mul, gf2m_mod_mul, int_bit_len, int_cmp, int_equals, int_is_zero, int_truncate,
    EcGf2mCtx, EcPoint, WordArray,
};
use crate::{Error, Result};

fn verify_failed() -> Error {
    Error::VerifyFailed
}

pub(crate) fn build_ec2m(params: &CurveParams) -> Result<EcGf2mCtx> {
    let onb = onb_tables(params)?;
    build_ec2m_with_onb(params, onb.as_ref())
}

pub(crate) fn onb_tables(params: &CurveParams) -> Result<Option<OnbTables>> {
    if params.is_onb {
        Ok(Some(OnbTables::for_field_degree(params.field_degree())?))
    } else {
        Ok(None)
    }
}

pub(crate) fn build_ec2m_with_onb(
    params: &CurveParams,
    onb: Option<&OnbTables>,
) -> Result<EcGf2mCtx> {
    let f: Vec<i32> = params.field.f.iter().map(|&e| e as i32).collect();
    if f.len() != 3 && f.len() != 5 {
        return Err(Error::InvalidParam(
            "field polynomial f must have 3 or 5 terms".into(),
        ));
    }
    let mut b = WordArray::from_le_bytes(&params.b);
    if let Some(t) = onb {
        b.change_len((params.field_degree() as usize + 63) >> 6);
        t.onb_to_pb(&mut b);
    }
    Ok(EcGf2mCtx::new(&f, params.field.a, &b))
}

pub(crate) fn field_point_from_ba(
    x: &[u8],
    y: &[u8],
    len: usize,
    onb: Option<&OnbTables>,
) -> EcPoint {
    let mut px = WordArray::from_le_bytes(x);
    let mut py = WordArray::from_le_bytes(y);
    px.change_len(len);
    py.change_len(len);
    if let Some(t) = onb {
        t.onb_to_pb(&mut px);
        t.onb_to_pb(&mut py);
    }
    EcPoint::from_affine(&px, &py)
}

/// Verify a DSTU 4145 signature over a 32-byte digest.
///
/// KAT oracle: `cryptonite/src/cryptoniteAtest/c/atest_dstu4145.c`.
pub fn verify(
    params: &CurveParams,
    public_key: &PublicKey,
    hash: &[u8],
    signature: &Signature,
) -> Result<()> {
    params.validate()?;

    if hash.len() != 32 {
        return Err(Error::InvalidParam(format!(
            "hash must be 32 bytes, got {}",
            hash.len()
        )));
    }

    if public_key.x.is_empty() || public_key.y.is_empty() {
        return Err(Error::InvalidParam("empty public key".into()));
    }

    if signature.r.is_empty() || signature.s.is_empty() {
        return Err(Error::InvalidParam("empty signature".into()));
    }

    if (signature.r.len() + signature.s.len()) & 1 == 1 {
        return Err(verify_failed());
    }

    let onb = onb_tables(params)?;
    let ec2m = build_ec2m(params)?;
    let field_len = ec2m.len;
    let m = params.field.f[0] as usize;

    let mut n = WordArray::from_le_bytes(&params.n);
    n.change_len(field_len);
    let n_bit_len = int_bit_len(&n);

    let wr = WordArray::from_le_bytes(&signature.r);
    let ws = WordArray::from_le_bytes(&signature.s);

    if int_is_zero(&wr) || int_is_zero(&ws) || int_cmp(&wr, &n) >= 0 || int_cmp(&ws, &n) >= 0 {
        return Err(verify_failed());
    }

    let mut h = WordArray::from_le_bytes(hash);
    int_truncate(&mut h, m);
    h.change_len(field_len);
    if let Some(t) = onb.as_ref() {
        t.onb_to_pb(&mut h);
    }
    if int_is_zero(&h) {
        h.buf[0] = 1;
    }

    let base = field_point_from_ba(&params.base_x, &params.base_y, field_len, onb.as_ref());
    let pub_key = field_point_from_ba(&public_key.x, &public_key.y, field_len, onb.as_ref());

    let mut r_point = EcPoint::with_len(field_len);
    ec2m_dual_mul(&ec2m, &base, &ws, &pub_key, &wr, &mut r_point);

    let mut r1 = WordArray::with_zero(field_len);
    gf2m_mod_mul(&ec2m.gf2m, &r_point.x, &h, &mut r1);
    if let Some(t) = onb.as_ref() {
        t.pb_to_onb(&mut r1);
    }
    int_truncate(&mut r1, n_bit_len - 1);

    if !int_equals(&r1, &wr) {
        return Err(verify_failed());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dstu4145::FieldPolynomial;

    #[test]
    fn rejects_wrong_hash_length() {
        let params = CurveParams {
            field: FieldPolynomial {
                f: vec![163, 7, 6, 3, 0],
                a: 1,
            },
            is_onb: false,
            b: vec![1],
            n: vec![1],
            base_x: vec![1],
            base_y: vec![1],
        };
        let pk = PublicKey {
            x: vec![1],
            y: vec![1],
        };
        let sig = Signature::from_be(vec![1], vec![1]);
        let err = verify(&params, &pk, &[0u8; 16], &sig).unwrap_err();
        assert!(matches!(err, Error::InvalidParam(_)));
    }
}
