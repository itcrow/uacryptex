//! Optimal normal basis (ONB) conversions for DSTU 4145.
//!
//! Port of Cryptonite `dstu4145_params_internal.c` (`init_onb_params`, `onb_to_pb`, `pb_to_onb`).
#![allow(clippy::blocks_in_conditions)]

use std::sync::OnceLock;

use crate::math::word::{WORD_BIT_LEN_MASK, WORD_BIT_LEN_SHIFT};
use crate::math::{gf2m_mod_sqr, int_bit_len, int_get_bit, int_truncate, Gf2mCtx, WordArray};
use crate::{Error, Result};

use super::onb_data::{OnbStaticData, ONB_DATA};

fn simple_mod(a: i32, m: i32) -> i32 {
    if a < m {
        a
    } else {
        a - m
    }
}

fn field_poly(m: u32) -> Vec<i32> {
    match m {
        173 => vec![173, 10, 2, 1, 0],
        179 => vec![179, 4, 2, 1, 0],
        191 => vec![191, 9, 0],
        233 => vec![233, 9, 4, 1, 0],
        431 => vec![431, 5, 3, 1, 0],
        _ => Vec::new(),
    }
}

fn decompress_matrix(compress_mulp: &WordArray, mulp: &mut [u16]) {
    let n = compress_mulp.buf.len();
    let mlen = int_bit_len(compress_mulp).div_ceil(9);
    let mut offset = 0i32;
    let mut i = n as i32;
    let mut j = mlen as i32;

    while {
        i -= 1;
        i >= 0
    } {
        while offset < 64 - 8 && {
            j -= 1;
            j >= 0
        } {
            mulp[j as usize] = ((compress_mulp.buf[n - 1 - i as usize] >> offset) & 0x1ff) as u16;
            offset += 9;
        }

        if {
            j -= 1;
            j >= 0
        } {
            if offset != 64 {
                mulp[j as usize] =
                    ((compress_mulp.buf[n - 1 - i as usize] >> offset) & 0x1ff) as u16;
            } else {
                mulp[j as usize] = 0;
            }
            offset -= 64 - 9;
            if i > 0 {
                mulp[j as usize] |=
                    ((compress_mulp.buf[n - 1 - (i - 1) as usize] << (9 - offset)) & 0x1ff) as u16;
            }
        }
    }
}

fn multiply_onb(x: &WordArray, y: &WordArray, mulp: &[u16], m: usize, r: &mut WordArray) {
    r.buf.fill(0);
    for j in 0..m {
        let mut bit = 0u32;
        for i in 0..m - 1 {
            let t1 = int_get_bit(
                y,
                simple_mod(mulp[2 * i] as i32 + j as i32 + 1, m as i32) as usize,
            );
            let t2 = int_get_bit(
                y,
                simple_mod(mulp[2 * i + 1] as i32 + j as i32 + 1, m as i32) as usize,
            );
            let t3 = int_get_bit(x, simple_mod(i as i32 + j as i32 + 1, m as i32) as usize);
            bit ^= (t1 ^ t2) & t3;
        }
        bit ^= int_get_bit(
            y,
            simple_mod(mulp[2 * m - 2] as i32 + j as i32 + 1, m as i32) as usize,
        ) & int_get_bit(
            x,
            simple_mod(m as i32 - 1 + j as i32 + 1, m as i32) as usize,
        );
        let woff = j >> WORD_BIT_LEN_SHIFT as usize;
        r.buf[woff] ^= (bit as u64) << (j as u64 & WORD_BIT_LEN_MASK);
    }
}

#[derive(Clone)]
pub struct OnbTables {
    pub m: usize,
    pub to_pb: Vec<WordArray>,
    pub to_onb: Vec<WordArray>,
}

impl OnbTables {
    pub fn for_field_degree(m: u32) -> Result<Self> {
        static CACHE: OnceLock<Vec<Option<OnbTables>>> = OnceLock::new();
        let cache =
            CACHE.get_or_init(|| ONB_DATA.iter().map(|d| OnbTables::build(d).ok()).collect());
        let idx = ONB_DATA
            .iter()
            .position(|d| d.m == m)
            .ok_or_else(|| Error::Unsupported(format!("ONB not supported for GF(2^{m})")))?;
        cache[idx]
            .clone()
            .ok_or_else(|| Error::Internal("failed to build ONB tables".into()))
    }

    fn build(data: &OnbStaticData) -> Result<Self> {
        let m = data.m as usize;
        let mulp_len = 2 * m - 1;
        let mut mulp = vec![0u16; mulp_len];

        let compress_words = data.compress_matrix.len() / 8;
        let compress = WordArray::from_le_bytes(&data.compress_matrix[..compress_words * 8]);
        decompress_matrix(&compress, &mut mulp);

        let words = (m + 63) >> 6;
        let f = field_poly(data.m);
        let gf2m = Gf2mCtx::new(&f);

        let mut root1 = WordArray::from_le_bytes(&data.root1[..words * 8]);
        root1.change_len(words);
        let mut root2 = WordArray::from_le_bytes(&data.root2[..words * 8]);
        root2.change_len(words);

        let mut to_pb = Vec::with_capacity(m);
        to_pb.push(root1);
        for i in 1..m {
            let mut next = WordArray::with_zero(words);
            gf2m_mod_sqr(&gf2m, &to_pb[i - 1], &mut next);
            to_pb.push(next);
        }

        let mut to_onb = Vec::with_capacity(m);
        let mut v0 = WordArray::with_zero(words);
        v0.buf.fill(u64::MAX);
        int_truncate(&mut v0, m);
        to_onb.push(v0);
        for i in 1..m {
            let mut next = WordArray::with_zero(words);
            multiply_onb(&to_onb[i - 1], &root2, &mulp, m, &mut next);
            to_onb.push(next);
        }

        Ok(Self { m, to_pb, to_onb })
    }

    pub fn onb_to_pb(&self, x: &mut WordArray) {
        let n = x.buf.len();
        let mut r = WordArray::with_zero(n);
        for (j, uj) in self.to_pb.iter().enumerate().take(self.m) {
            let k = self.m - 1 - j;
            let xj = int_get_bit(x, k);
            for i in 0..self.m {
                let woff = i >> WORD_BIT_LEN_SHIFT as usize;
                r.buf[woff] ^= (xj as u64) << (i as u64 & WORD_BIT_LEN_MASK) & uj.buf[woff];
            }
        }
        x.buf.copy_from_slice(&r.buf);
    }

    pub fn pb_to_onb(&self, x: &mut WordArray) {
        let n = x.buf.len();
        let mut r = WordArray::with_zero(n);
        for (j, vj) in self.to_onb.iter().enumerate().take(self.m) {
            let xj = int_get_bit(x, j);
            for i in 0..self.m {
                let k = self.m - 1 - i;
                let woff = k >> WORD_BIT_LEN_SHIFT as usize;
                let bit = (vj.buf[woff] >> (k as u64 & WORD_BIT_LEN_MASK)) & 1;
                r.buf[i >> WORD_BIT_LEN_SHIFT as usize] ^=
                    (xj as u64 & bit) << (i as u64 & WORD_BIT_LEN_MASK);
            }
        }
        x.buf.copy_from_slice(&r.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wa_from_be_hex(s: &str) -> WordArray {
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        let mut v = hex::decode(s).unwrap();
        v.reverse();
        WordArray::from_le_bytes(&v)
    }

    fn assert_onb_pb_roundtrip(m: u32, onb_hex: &str, pb_hex: &str) {
        let tables = OnbTables::for_field_degree(m).unwrap();
        let onb = wa_from_be_hex(onb_hex);
        let pb = wa_from_be_hex(pb_hex);
        let mut actual = onb.clone();
        actual.change_len(tables.to_pb[0].buf.len());
        tables.onb_to_pb(&mut actual);
        assert_eq!(actual.buf[..pb.buf.len()], pb.buf, "onb_to_pb m={m}");
        tables.pb_to_onb(&mut actual);
        assert_eq!(actual.buf[..onb.buf.len()], onb.buf, "pb_to_onb m={m}");
    }

    #[test]
    fn onb_pb_roundtrip_m173_utest() {
        assert_onb_pb_roundtrip(
            173,
            "043D7E139319F43BA00944915740E1E6651B06E278C7",
            "01eec7c8f700a6aedbd1461bfd4e13f7a34be03124b2",
        );
    }

    #[test]
    fn onb_pb_roundtrip_m179_utest() {
        assert_onb_pb_roundtrip(
            179,
            "19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB",
            "0004c8a1d80932e32d11d5cc8c5c61d708d9c7ec4072c6e0",
        );
    }

    #[test]
    fn onb_pb_roundtrip_m431_utest() {
        assert_onb_pb_roundtrip(
            431,
            "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299",
            "0000513dc8305b5444dca36bf9c383216d191f9457d222eb612dea8cc5a073e37e17ed41b01d8152af26d45d676c728f814ba7f6014e4d55",
        );
    }

    #[test]
    fn onb_pb_utest_fixed_vectors() {
        let tables = OnbTables::for_field_degree(173).unwrap();
        let mut actual = wa_from_be_hex("0000000000000001053bc43edb5401d73e045d608f6cd71a");
        let pb = wa_from_be_hex("00001cd30e064b7d1f84f2654dafefb6341a69ed2de6f7be");
        actual.change_len(tables.to_pb[0].buf.len());
        tables.onb_to_pb(&mut actual);
        assert_eq!(actual.buf[..pb.buf.len()], pb.buf);

        let mut actual2 = pb.clone();
        actual2.change_len(tables.to_pb[0].buf.len());
        let onb = wa_from_be_hex("0000000000000001053bc43edb5401d73e045d608f6cd71a");
        tables.pb_to_onb(&mut actual2);
        assert_eq!(actual2.buf[..onb.buf.len()], onb.buf);
    }
}
