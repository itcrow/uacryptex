//! DSTU 4145 public key compression (`dstu4145_compress_pubkey` / `decompress_pubkey`).

use der::Decode;
use super::params::{CurveParams, PublicKey};
use super::verify::{build_ec2m_with_onb, field_point_from_ba, onb_tables};
use crate::math::{
    gf2m_mod_add_assign, gf2m_mod_inv, gf2m_mod_mul, gf2m_mod_solve_quad, gf2m_mod_sqrt, gf2m_mod_sqr,
    gf2m_mod_trace, int_get_bit, int_is_zero, WordArray,
};
use crate::{Error, Result};

/// `dstu4145_get_pubkey`.
pub fn public_key_from_private_key(
    params: &CurveParams,
    private_key: &[u8],
) -> Result<PublicKey> {
    super::sign::public_key_from_private(params, private_key)
}

/// `dstu4145_compress_pubkey`.
pub fn compress_public_key(params: &CurveParams, public_key: &PublicKey) -> Result<Vec<u8>> {
    params.validate()?;
    let onb = onb_tables(params)?;
    let ec2m = build_ec2m_with_onb(params, onb.as_ref())?;
    let field_len = ec2m.len;
    let q_len = (params.field_degree() as usize + 7) >> 3;

    let point = field_point_from_ba(&public_key.x, &public_key.y, field_len, onb.as_ref());

    if int_is_zero(&point.x) {
        return Ok(vec![0u8; q_len]);
    }

    let mut inv_x = WordArray::with_zero(field_len);
    gf2m_mod_inv(&ec2m.gf2m, &point.x, &mut inv_x);
    let mut ratio = WordArray::with_zero(field_len);
    gf2m_mod_mul(&ec2m.gf2m, &inv_x, &point.y, &mut ratio);
    let trace = gf2m_mod_trace(&ec2m.gf2m, &ratio);

    let mut compressed = public_key.x.clone();
    if compressed.len() > q_len {
        compressed.truncate(q_len);
    } else if compressed.len() < q_len {
        compressed.resize(q_len, 0);
    }
    if (compressed[0] ^ (trace as u8)) & 1 != 0 {
        compressed[0] ^= 1;
    }
    Ok(compressed)
}

/// `dstu4145_decompress_pubkey`.
pub fn decompress_public_key(params: &CurveParams, compressed: &[u8]) -> Result<PublicKey> {
    params.validate()?;
    let onb = onb_tables(params)?;
    let ec2m = build_ec2m_with_onb(params, onb.as_ref())?;
    let field_len = ec2m.len;
    let m = params.field_degree() as usize;
    let q_len = (m + 7) >> 3;

    let mut x = WordArray::from_le_bytes(compressed);
    x.change_len(field_len);

    if int_get_bit(&x, m) != 0 || x.buf.iter().skip((m + 63) >> 6).any(|&w| w != 0) {
        return Err(Error::InvalidParam("invalid compressed public key".into()));
    }

    let (qx, qy) = if int_is_zero(&x) {
        let mut y = WordArray::with_zero(field_len);
        gf2m_mod_sqrt(&ec2m.gf2m, &ec2m.b, &mut y);
        (x, y)
    } else {
        let k = (x.buf[0] & 1) as i32;
        if params.is_onb {
            let mut trace = 0i32;
            for i in (0..m).rev() {
                trace ^= int_get_bit(&x, i) as i32;
            }
            if (trace & 1) != ec2m.a {
                x.buf[0] ^= 1;
            }
            if let Some(t) = onb.as_ref() {
                t.onb_to_pb(&mut x);
            }
        } else {
            let trace = gf2m_mod_trace(&ec2m.gf2m, &x);
            if trace != ec2m.a {
                x.buf[0] ^= 1;
            }
        }

        let mut y = WordArray::with_zero(field_len);
        gf2m_mod_sqr(&ec2m.gf2m, &x, &mut y);
        let mut inv = WordArray::with_zero(field_len);
        gf2m_mod_inv(&ec2m.gf2m, &y, &mut inv);
        gf2m_mod_mul(&ec2m.gf2m, &inv, &ec2m.b, &mut y);
        gf2m_mod_add_assign(&mut y, &x);
        if ec2m.a == 1 {
            y.buf[0] ^= 1;
        }

        let mut root = y.clone();
        if !gf2m_mod_solve_quad(&ec2m.gf2m, &y, &mut root) {
            return Err(Error::InvalidParam("invalid compressed public key".into()));
        }

        let mut final_y = root.clone();
        if gf2m_mod_trace(&ec2m.gf2m, &root) == k {
            gf2m_mod_mul(&ec2m.gf2m, &x, &root, &mut final_y);
        } else {
            root.buf[0] ^= 1;
            gf2m_mod_mul(&ec2m.gf2m, &x, &root, &mut final_y);
        }

        if params.is_onb {
            if let Some(t) = onb.as_ref() {
                t.pb_to_onb(&mut final_y);
            }
        }

        (x, final_y)
    };

    Ok(PublicKey {
        x: qx.to_le_bytes_len(q_len),
        y: qy.to_le_bytes_len(q_len),
    })
}

/// SPKI BIT STRING payload: OCTET STRING wrapping compressed coordinates.
pub fn compressed_key_from_spki_bitstring(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.is_empty() {
        return Err(Error::InvalidParam("empty SPKI public key".into()));
    }
    if raw[0] == 0x04 {
        let os = der::asn1::OctetString::from_der(raw)
            .map_err(|e| Error::InvalidParam(format!("SPKI public key octet string: {e}")))?;
        return Ok(os.as_bytes().to_vec());
    }
    Ok(raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dstu4145::curves::ParamsId;

    fn le(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn compress_decompress_matches_utest_m257() {
        let params = ParamsId::M257Pb.curve_params().unwrap();
        let private = le("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
        let pk = public_key_from_private_key(&params, &private).unwrap();
        let expected_q = le("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00");
        let compressed = compress_public_key(&params, &pk).unwrap();
        assert_eq!(compressed, expected_q);
        let restored = decompress_public_key(&params, &compressed).unwrap();
        assert_eq!(restored, pk);
    }
}
