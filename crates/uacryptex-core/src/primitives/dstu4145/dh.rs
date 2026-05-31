//! DSTU 4145 Diffie-Hellman (`dstu4145_dh`).

use super::params::CurveParams;
use super::pubkey::decompress_public_key;
use super::verify::{build_ec2m_with_onb, field_point_from_ba, onb_tables};
use crate::math::{ec2m_mul, gf2m_mod_add, int_cmp, int_is_zero, EcPoint, WordArray};
use crate::{Error, Result};

/// Shared secret from compressed peer public key (`dstu4145_dh`).
pub fn dstu4145_dh(
    params: &CurveParams,
    with_cofactor: bool,
    private_key: &[u8],
    peer_compressed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    params.validate()?;
    let peer = decompress_public_key(params, peer_compressed)?;
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

    let rq = field_point_from_ba(&peer.x, &peer.y, field_len, onb.as_ref());
    let mut r = EcPoint::with_len(field_len);
    ec2m_mul(&ec2m, &rq, &d, &mut r);

    if with_cofactor {
        let mut cofactor = WordArray::with_zero(field_len);
        cofactor.buf[0] = 1;
        let mut scaled = EcPoint::with_len(field_len);
        ec2m_mul(&ec2m, &r, &cofactor, &mut scaled);
        r = scaled;
    }

    if params.is_onb {
        if let Some(t) = onb.as_ref() {
            t.pb_to_onb(&mut r.x);
            t.pb_to_onb(&mut r.y);
        }
    } else {
        let y = r.y.clone();
        gf2m_mod_add(&r.x, &y, &mut r.y);
    }

    let z_len = (params.field_degree() as usize + 7) >> 3;
    Ok((r.x.to_le_bytes_len(z_len), r.y.to_le_bytes_len(z_len)))
}
