//! DSTU 4145-2002 signature verification (C ABI).

use std::os::raw::c_int;

use uacryptex_core::primitives::dstu4145::{
    verify, CurveParams, FieldPolynomial, PublicKey, Signature,
};
use uacryptex_core::{Error, RET_OK};

use crate::error::{bytes_from_ptr, u32_slice_from_ptr, write_error, UacryptexError};

#[allow(clippy::too_many_arguments)]
fn verify_pb_impl(
    f: &[u32],
    a: i32,
    b: &[u8],
    n: &[u8],
    gx: &[u8],
    gy: &[u8],
    qx: &[u8],
    qy: &[u8],
    hash: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<(), Error> {
    if f.len() != 3 && f.len() != 5 {
        return Err(Error::InvalidParam(
            "field polynomial f must have 3 or 5 terms".into(),
        ));
    }

    let params = CurveParams {
        field: FieldPolynomial { f: f.to_vec(), a },
        is_onb: false,
        b: b.to_vec(),
        n: n.to_vec(),
        base_x: gx.to_vec(),
        base_y: gy.to_vec(),
    };

    let public_key = PublicKey {
        x: qx.to_vec(),
        y: qy.to_vec(),
    };

    let signature = Signature::from_le(r, s);
    verify(&params, &public_key, hash, &signature)
}

/// Verify a DSTU 4145 signature over GF(2^m) in polynomial basis.
///
/// Octet encoding (Cryptonite-compatible):
/// - `b`, `n`, `gx`, `gy`, `qx`, `qy`, `hash`: `ByteArray` from `ba_alloc_from_be_hex_string`
/// - `r`, `s`: `ByteArray` from `ba_alloc_from_le_hex_string`
///
/// Returns `RET_OK` (0) on success.
#[no_mangle]
pub extern "C" fn uacryptex_dstu4145_verify_pb(
    f: *const u32,
    f_len: usize,
    a: c_int,
    b: *const u8,
    b_len: usize,
    n: *const u8,
    n_len: usize,
    gx: *const u8,
    gx_len: usize,
    gy: *const u8,
    gy_len: usize,
    qx: *const u8,
    qx_len: usize,
    qy: *const u8,
    qy_len: usize,
    hash: *const u8,
    hash_len: usize,
    r: *const u8,
    r_len: usize,
    s: *const u8,
    s_len: usize,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<(), Error> {
        let f = u32_slice_from_ptr(f, f_len).map_err(|code| {
            Error::InvalidParam(format!("invalid field polynomial pointer: code {code}"))
        })?;
        let b = bytes_from_ptr(b, b_len)
            .map_err(|code| Error::InvalidParam(format!("invalid b: code {code}")))?;
        let n = bytes_from_ptr(n, n_len)
            .map_err(|code| Error::InvalidParam(format!("invalid n: code {code}")))?;
        let gx = bytes_from_ptr(gx, gx_len)
            .map_err(|code| Error::InvalidParam(format!("invalid gx: code {code}")))?;
        let gy = bytes_from_ptr(gy, gy_len)
            .map_err(|code| Error::InvalidParam(format!("invalid gy: code {code}")))?;
        let qx = bytes_from_ptr(qx, qx_len)
            .map_err(|code| Error::InvalidParam(format!("invalid qx: code {code}")))?;
        let qy = bytes_from_ptr(qy, qy_len)
            .map_err(|code| Error::InvalidParam(format!("invalid qy: code {code}")))?;
        let hash = bytes_from_ptr(hash, hash_len)
            .map_err(|code| Error::InvalidParam(format!("invalid hash: code {code}")))?;
        let r = bytes_from_ptr(r, r_len)
            .map_err(|code| Error::InvalidParam(format!("invalid r: code {code}")))?;
        let s = bytes_from_ptr(s, s_len)
            .map_err(|code| Error::InvalidParam(format!("invalid s: code {code}")))?;

        verify_pb_impl(f, a, b, n, gx, gy, qx, qy, hash, r, s)
    };

    match run() {
        Ok(()) => RET_OK,
        Err(e) => write_error(err, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uacryptex_core::RET_VERIFY_FAILED;

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
    fn verify_pn_kat_via_ffi() {
        let f = [163u32, 7, 6, 3, 0];
        let b = decode_be_hex("5ff6108462a2dc8210ab403925e638a19c1455d21");
        let n = decode_be_hex("400000000000000000002bec12be2262d39bcf14d");
        let gx = decode_be_hex("72d867f93a93ac27df9ff01affe74885c8c540420");
        let gy = decode_be_hex("0224a9c3947852b97c5599d5f4ab81122adc3fd9b");
        let qx = decode_be_hex("57de7fde023ff929cb6ac785ce4b79cf64abdc2da");
        let qy = decode_be_hex("3e85444324bcf06ad85abf6ad7b5f34770532b9aa");
        let hash =
            decode_be_hex("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
        let r = decode_le_hex("a7088d06937ade9af524a4800d4a01aa0c2cea7402");
        let s = decode_le_hex("ca5a61b332a3d65b0f238c8e2b83317395860d1002");

        let mut err = UacryptexError::default();
        let rc = uacryptex_dstu4145_verify_pb(
            f.as_ptr(),
            f.len(),
            1,
            b.as_ptr(),
            b.len(),
            n.as_ptr(),
            n.len(),
            gx.as_ptr(),
            gx.len(),
            gy.as_ptr(),
            gy.len(),
            qx.as_ptr(),
            qx.len(),
            qy.as_ptr(),
            qy.len(),
            hash.as_ptr(),
            hash.len(),
            r.as_ptr(),
            r.len(),
            s.as_ptr(),
            s.len(),
            &mut err,
        );
        assert_eq!(rc, RET_OK, "err={:?}", err);
    }

    #[test]
    fn rejects_bad_signature_via_ffi() {
        let f = [163u32, 7, 6, 3, 0];
        let b = decode_be_hex("5ff6108462a2dc8210ab403925e638a19c1455d21");
        let n = decode_be_hex("400000000000000000002bec12be2262d39bcf14d");
        let gx = decode_be_hex("72d867f93a93ac27df9ff01affe74885c8c540420");
        let gy = decode_be_hex("0224a9c3947852b97c5599d5f4ab81122adc3fd9b");
        let qx = decode_be_hex("57de7fde023ff929cb6ac785ce4b79cf64abdc2da");
        let qy = decode_be_hex("3e85444324bcf06ad85abf6ad7b5f34770532b9aa");
        let hash =
            decode_be_hex("09c9c44277910c9aaee486883a2eb95b7180166ddf73532eeb76edaef52247ff");
        let r = decode_le_hex("00000000000000000000000000000000000000000000");
        let s = decode_le_hex("ca5a61b332a3d65b0f238c8e2b83317395860d1002");

        let mut err = UacryptexError::default();
        let rc = uacryptex_dstu4145_verify_pb(
            f.as_ptr(),
            f.len(),
            1,
            b.as_ptr(),
            b.len(),
            n.as_ptr(),
            n.len(),
            gx.as_ptr(),
            gx.len(),
            gy.as_ptr(),
            gy.len(),
            qx.as_ptr(),
            qx.len(),
            qy.as_ptr(),
            qy.len(),
            hash.as_ptr(),
            hash.len(),
            r.as_ptr(),
            r.len(),
            s.as_ptr(),
            s.len(),
            &mut err,
        );
        assert_eq!(rc, RET_VERIFY_FAILED);
    }
}
