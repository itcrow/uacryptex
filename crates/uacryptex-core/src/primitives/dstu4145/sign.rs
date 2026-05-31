//! DSTU 4145 signature generation (polynomial and ONB basis).

use super::verify::{build_ec2m_with_onb, field_point_from_ba, onb_tables};
use super::{CurveParams, PublicKey, Signature};
use crate::math::{ec2m_mul, gf2m_mod_add, gf2m_mod_mul, int_add, int_bit_len, int_cmp, int_div, int_is_zero, int_mul, int_sub, int_truncate, EcPoint, WordArray};
use crate::primitives::dstu4145::prng::RandomBytes;
use crate::{Error, Result};

/// Derive affine public key Q = d·G.
pub fn public_key_from_private(params: &CurveParams, private_key: &[u8]) -> Result<PublicKey> {
    params.validate()?;
    let onb = onb_tables(params)?;
    let ec2m = build_ec2m_with_onb(params, onb.as_ref())?;
    let field_len = ec2m.len;
    let mut n = WordArray::from_le_bytes(&params.n);
    n.change_len(field_len);
    let mut d = WordArray::from_le_bytes(private_key);
    d.change_len(field_len);
    if int_is_zero(&d) || int_cmp(&d, &n) >= 0 {
        return Err(Error::InvalidParam("invalid private key".into()));
    }
    let base = field_point_from_ba(&params.base_x, &params.base_y, field_len, onb.as_ref());
    let mut q = EcPoint::with_len(field_len);
    ec2m_mul(&ec2m, &base, &d, &mut q);
    let qy = q.y.clone();
    gf2m_mod_add(&q.x, &qy, &mut q.y);
    if let Some(t) = onb.as_ref() {
        t.pb_to_onb(&mut q.x);
        t.pb_to_onb(&mut q.y);
    }

    let q_len = (params.field_degree() as usize + 7) >> 3;
    Ok(PublicKey {
        x: q.x.to_le_bytes_len(q_len),
        y: q.y.to_le_bytes_len(q_len),
    })
}

fn truncate_be_bytes(buf: &mut [u8], bit_len: usize) {
    let byte_off = bit_len >> 3;
    if byte_off >= buf.len() {
        return;
    }
    buf[byte_off] &= ((1u8 << (bit_len & 7)) - 1) as u8;
    for b in buf.iter_mut().skip(byte_off + 1) {
        *b = 0;
    }
}

/// Generate a DSTU private key scalar (`dstu4145_generate_privkey`).
pub fn generate_private_key(params: &CurveParams, rng: &mut dyn RandomBytes) -> Result<Vec<u8>> {
    params.validate()?;
    let field_len = (params.field_degree() as usize + 7) >> 3;
    let mut n = WordArray::from_le_bytes(&params.n);
    n.change_len(field_len);
    let n_bit_len = int_bit_len(&n);
    let key_len = (n_bit_len + 7) / 8;
    let mut d = vec![0u8; key_len];
    loop {
        rng.fill(&mut d)?;
        truncate_be_bytes(&mut d, n_bit_len - 1);
        if d.iter().any(|&b| b != 0) {
            return Ok(d);
        }
    }
}

/// Sign a 32-byte digest with a private key (Cryptonite `ByteArray` / LE octets).
pub fn sign(
    params: &CurveParams,
    private_key: &[u8],
    hash: &[u8],
    rng: &mut dyn RandomBytes,
) -> Result<Signature> {
    params.validate()?;

    if hash.len() != 32 {
        return Err(Error::InvalidParam(format!(
            "hash must be 32 bytes, got {}",
            hash.len()
        )));
    }

    if private_key.is_empty() {
        return Err(Error::InvalidParam("empty private key".into()));
    }

    let onb = onb_tables(params)?;
    let ec2m = build_ec2m_with_onb(params, onb.as_ref())?;
    let field_len = ec2m.len;
    let m = params.field_degree() as usize;

    let mut n = WordArray::from_le_bytes(&params.n);
    n.change_len(field_len);
    let n_bit_len = int_bit_len(&n);

    let mut d = WordArray::from_le_bytes(private_key);
    d.change_len(field_len);
    if int_is_zero(&d) || int_cmp(&d, &n) >= 0 {
        return Err(Error::InvalidParam("invalid private key".into()));
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
    let mut e;
    let mut wr = WordArray::with_zero(field_len);
    let mut ws = WordArray::with_zero(field_len);
    let mut res = WordArray::with_zero(2 * field_len);
    let mut rec = EcPoint::with_len(field_len);
    let mut e_bytes = vec![0u8; field_len * 8];

    loop {
        loop {
            rng.fill(&mut e_bytes)?;
            e = WordArray::from_le_bytes(&e_bytes);
            e.change_len(field_len);
            int_truncate(&mut e, n_bit_len - 1);

            ec2m_mul(&ec2m, &base, &e, &mut rec);
            gf2m_mod_mul(&ec2m.gf2m, &rec.x, &h, &mut wr);
            if let Some(t) = onb.as_ref() {
                t.pb_to_onb(&mut wr);
            }
            int_truncate(&mut wr, n_bit_len - 1);
            if !int_is_zero(&wr) {
                break;
            }
        }

        int_mul(&d, &wr, &mut res);
        int_div(&res, &n, None, Some(&mut ws));
        let mut sum = WordArray::with_zero(field_len);
        let carry = int_add(&e, &ws, &mut sum);
        ws = sum;
        if carry > 0 || int_cmp(&ws, &n) >= 0 {
            let n_copy = n.clone();
            let mut reduced = WordArray::with_zero(field_len);
            int_sub(&ws, &n_copy, &mut reduced);
            ws = reduced;
        }
        if !int_is_zero(&ws) {
            break;
        }
    }

    let ln = (n_bit_len + 7) >> 3;
    Ok(Signature::from_le(
        wr.to_le_bytes_len(ln),
        ws.to_le_bytes_len(ln),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dstu4145::curves::ParamsId;
    use crate::primitives::dstu4145::params::PublicKey;
    use crate::primitives::dstu4145::prng::SliceRandom;
    use crate::primitives::dstu4145::verify;

    fn decode_be_hex(s: &str) -> Vec<u8> {
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        let mut v = hex::decode(s).unwrap();
        v.reverse();
        v
    }

    fn decode_le_hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn public_key_matches_utest_m257() {
        let params = ParamsId::M257Pb.curve_params().unwrap();
        let d = decode_le_hex("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
        let exp_x =
            decode_le_hex("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
        let exp_y =
            decode_le_hex("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01");
        let pk = public_key_from_private(&params, &d).unwrap();
        assert_eq!(pk.x, exp_x, "qx mismatch");
        assert_eq!(pk.y, exp_y, "qy mismatch");
    }

    #[test]
    fn sign_components_satisfy_verify_equation_m163() {
        use crate::math::{
            ec2m_dual_mul, gf2m_mod_mul, int_bit_len, int_equals, int_is_zero, int_truncate,
            EcPoint, WordArray,
        };
        use crate::primitives::dstu4145::verify::{build_ec2m, field_point_from_ba};

        let params = ParamsId::M163Pb.curve_params().unwrap();
        let d = vec![0x42u8; 10];
        let hash =
            decode_be_hex("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
        let pk = public_key_from_private(&params, &d).unwrap();
        let mut rng = SliceRandom::new(vec![0x42; 64]);
        let sig = sign(&params, &d, &hash, &mut rng).unwrap();

        let ec2m = build_ec2m(&params).unwrap();
        let field_len = ec2m.len;
        let m = params.field_degree() as usize;
        let mut n = WordArray::from_le_bytes(&params.n);
        n.change_len(field_len);
        let n_bit_len = int_bit_len(&n);

        let wr = WordArray::from_le_bytes(&sig.r);
        let ws = WordArray::from_le_bytes(&sig.s);
        let mut h = WordArray::from_le_bytes(&hash);
        int_truncate(&mut h, m);
        h.change_len(field_len);
        if int_is_zero(&h) {
            h.buf[0] = 1;
        }

        let base = field_point_from_ba(&params.base_x, &params.base_y, field_len, None);
        let pub_key = field_point_from_ba(&pk.x, &pk.y, field_len, None);
        let mut r_point = EcPoint::with_len(field_len);
        ec2m_dual_mul(&ec2m, &base, &ws, &pub_key, &wr, &mut r_point);
        let mut r1 = WordArray::with_zero(field_len);
        gf2m_mod_mul(&ec2m.gf2m, &r_point.x, &h, &mut r1);
        int_truncate(&mut r1, n_bit_len - 1);

        assert!(
            int_equals(&r1, &wr),
            "verify equation failed: r1 != wr (r={:x?} s={:x?})",
            sig.r,
            sig.s
        );
    }

    #[test]
    fn verify_utest_m257_fixed_signature() {
        let params = ParamsId::M257Pb.curve_params().unwrap();
        let hash =
            decode_le_hex("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
        let pk = PublicKey {
            x: decode_le_hex("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00"),
            y: decode_le_hex("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01"),
        };
        let sig = Signature::from_le(
            decode_le_hex("ace29a89ec34329abf529d109ca838c26b13cc0e14d8663071da94ab198e2e64"),
            decode_le_hex("39b9c25ab0187694ec170221e9135405894bf439c9cefea7f23e4e1a974eca1b"),
        );
        verify::verify(&params, &pk, &hash, &sig).expect("utest verify vector");
    }

    #[test]
    fn sign_verify_roundtrip_m257_utest_vectors() {
        let params = ParamsId::M257Pb.curve_params().unwrap();
        let d = decode_le_hex("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
        let hash =
            decode_le_hex("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
        let pk = PublicKey {
            x: decode_le_hex("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00"),
            y: decode_le_hex("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01"),
        };
        assert_eq!(public_key_from_private(&params, &d).unwrap(), pk);

        let mut rng = SliceRandom::new(vec![0x42; 64]);
        let sig = sign(&params, &d, &hash, &mut rng).unwrap();
        verify(&params, &pk, &hash, &sig).expect("M257 roundtrip");
    }

    #[test]
    fn sign_verify_roundtrip_m163() {
        let params = ParamsId::M163Pb.curve_params().unwrap();
        let d = vec![0x42u8; 10];
        let hash =
            decode_be_hex("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
        let pk = public_key_from_private(&params, &d).unwrap();

        let mut rng = SliceRandom::new(vec![0x42; 64]);
        let sig = sign(&params, &d, &hash, &mut rng).unwrap();
        verify(&params, &pk, &hash, &sig).expect("roundtrip verify");
    }

    #[test]
    fn sign_verify_roundtrip_m173_onb() {
        let params = ParamsId::M173Onb.curve_params().unwrap();
        let d = vec![0x42u8; 12];
        let hash =
            decode_le_hex("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
        let pk = public_key_from_private(&params, &d).unwrap();
        let mut rng = SliceRandom::new(vec![0x55; 64]);
        let sig = sign(&params, &d, &hash, &mut rng).unwrap();
        verify(&params, &pk, &hash, &sig).expect("M173 ONB roundtrip");
    }
}
