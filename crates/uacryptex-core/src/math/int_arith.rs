//! Multi-word integer multiply/divide (Cryptonite `math_int_internal.c`, ARCH64).

use super::word::{WordArray, WORD_BIT_LENGTH, WORD_BIT_LEN_MASK};

const HALF_WORD_BIT_LENGTH: u32 = 32;
const HALF_WORD_MASK: u64 = 0xffff_ffff;

#[derive(Clone, Copy, Default, Debug)]
struct Dword {
    hi: u64,
    lo: u64,
}

fn word_lo(a: u64) -> u64 {
    a & HALF_WORD_MASK
}

fn word_hi(a: u64) -> u64 {
    a >> HALF_WORD_BIT_LENGTH
}

fn words_len(a: &[u64]) -> usize {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return i + 1;
        }
    }
    1
}

fn words_lshift(a: &[u64], len: usize, shift: i32, out: &mut [u64]) {
    let m = (shift as usize) & WORD_BIT_LEN_MASK as usize;
    let s = WORD_BIT_LENGTH - m;
    let mut j = len as i32 - 1 - (shift >> 6);
    let mut i = len as i32 - 1;
    if m == 0 {
        while j >= 0 {
            out[i as usize] = a[j as usize];
            i -= 1;
            j -= 1;
        }
    } else {
        while j > 0 {
            out[i as usize] = (a[j as usize] << m) | (a[j as usize - 1] >> s);
            i -= 1;
            j -= 1;
        }
        if j >= 0 {
            out[i as usize] = a[j as usize] << m;
            i -= 1;
        }
    }
    while i >= 0 {
        out[i as usize] = 0;
        i -= 1;
    }
}

fn words_rshift(a_hi: u64, a: &[u64], len: usize, shift: usize, out: &mut [u64]) {
    let m = shift & WORD_BIT_LEN_MASK as usize;
    let s = WORD_BIT_LENGTH - m;
    let mut j = shift >> 6;
    let mut i = 0usize;
    if m == 0 {
        while j < len {
            out[i] = a[j];
            i += 1;
            j += 1;
        }
    } else {
        while j < len.saturating_sub(1) {
            out[i] = (a[j + 1] << s) | (a[j] >> m);
            i += 1;
            j += 1;
        }
        if j < len {
            out[i] = a[j] >> m;
            i += 1;
        }
    }
    while i < len {
        out[i] = 0;
        i += 1;
    }
    if !out.is_empty() && m != 0 {
        out[len - 1] |= a_hi.wrapping_shl(s as u32);
    }
}

fn word_lshift_64(a: u64, shift: i32) -> Dword {
    let shift = shift & 63;
    if shift == 0 {
        Dword { hi: 0, lo: a }
    } else if shift < WORD_BIT_LENGTH as i32 {
        Dword {
            hi: a >> (WORD_BIT_LENGTH as i32 - shift),
            lo: a << shift,
        }
    } else {
        Dword {
            hi: a << (shift - WORD_BIT_LENGTH as i32),
            lo: 0,
        }
    }
}

fn word_add_word(a: Dword, b: u64) -> Dword {
    let out_lo = a.lo.wrapping_add(b);
    let hi = if out_lo < a.lo {
        a.hi.wrapping_add(1)
    } else {
        a.hi
    };
    Dword { hi, lo: out_lo }
}

fn word_add(a: Dword, b: Dword) -> Dword {
    let out_lo = a.lo.wrapping_add(b.lo);
    let mut hi = a.hi.wrapping_add(b.hi);
    if out_lo < a.lo {
        hi = hi.wrapping_add(1);
    }
    Dword { hi, lo: out_lo }
}

fn word_sub(a: Dword, b: Dword) -> Dword {
    let hi = if a.lo < b.lo {
        a.hi.wrapping_sub(b.hi).wrapping_sub(1)
    } else {
        a.hi.wrapping_sub(b.hi)
    };
    Dword {
        hi,
        lo: a.lo.wrapping_sub(b.lo),
    }
}

fn word_sub_word(a: Dword, b: u64) -> Dword {
    let hi = if a.lo < b { a.hi.wrapping_sub(1) } else { a.hi };
    Dword {
        hi,
        lo: a.lo.wrapping_sub(b),
    }
}

fn word_cmp(a: Dword, b: Dword) -> i32 {
    if a.hi > b.hi {
        1
    } else if a.hi < b.hi || a.lo < b.lo {
        -1
    } else if a.lo > b.lo {
        1
    } else {
        0
    }
}

fn word_mul_64(a: u64, b: u64) -> Dword {
    let a_lo = word_lo(a);
    let a_hi = word_hi(a);
    let b_lo = word_lo(b);
    let b_hi = word_hi(b);
    let ab_hi = a_hi * b_hi;
    let ab_mid = a_hi * b_lo;
    let ba_mid = b_hi * a_lo;
    let ab_lo = a_lo * b_lo;
    let carry_bit = word_hi(
        word_lo(ab_mid)
            .wrapping_add(word_lo(ba_mid))
            .wrapping_add(word_hi(ab_lo)),
    );
    Dword {
        lo: (ab_mid << HALF_WORD_BIT_LENGTH)
            .wrapping_add(ba_mid << HALF_WORD_BIT_LENGTH)
            .wrapping_add(ab_lo),
        hi: ab_hi
            .wrapping_add(word_hi(ab_mid))
            .wrapping_add(word_hi(ba_mid))
            .wrapping_add(carry_bit),
    }
}

fn word_lshift_b(b: u64, shift: i32) -> Dword {
    if shift <= 0 {
        Dword { hi: 0, lo: b }
    } else if shift < WORD_BIT_LENGTH as i32 {
        Dword {
            hi: b >> (WORD_BIT_LENGTH as i32 - shift),
            lo: b << shift,
        }
    } else if shift < 2 * WORD_BIT_LENGTH as i32 {
        Dword {
            hi: b << (shift - WORD_BIT_LENGTH as i32),
            lo: 0,
        }
    } else {
        Dword::default()
    }
}

fn word_lshift_one(shift: i32) -> Dword {
    if shift < WORD_BIT_LENGTH as i32 {
        word_lshift_64(1, shift)
    } else if shift < 2 * WORD_BIT_LENGTH as i32 {
        Dword {
            hi: 1u64 << (shift - WORD_BIT_LENGTH as i32),
            lo: 0,
        }
    } else {
        Dword::default()
    }
}

fn word_div(a: Dword, b: u64) -> (Dword, u64) {
    let mut qh = Dword::default();
    let mut rh = a;
    let b_bit_len = super::word::word_bit_len(b);

    while rh.hi > 0 || rh.lo >= b {
        let mut rshift = super::word::word_bit_len(rh.hi) as i32;
        rshift += if rshift == 0 {
            super::word::word_bit_len(rh.lo) as i32
        } else {
            WORD_BIT_LENGTH as i32
        };
        rshift -= b_bit_len as i32;

        if word_cmp(rh, word_lshift_b(b, rshift)) < 0 {
            rshift -= 1;
        }

        let dword = word_lshift_b(b, rshift);
        rh = word_sub(rh, dword);
        qh = word_add(qh, word_lshift_one(rshift));
    }

    (qh, rh.lo)
}

pub fn words_mul_64(a: &[u64], b: &[u64], len: usize, out: &mut [u64]) {
    out.fill(0);
    for i in 0..len {
        let mut c = Dword::default();
        for j in 0..len {
            let aibj = word_mul_64(a[i], b[j]);
            c = word_add_word(aibj, c.hi);
            c = word_add_word(c, out[i + j]);
            out[i + j] = c.lo;
        }
        out[i + len] = c.hi;
    }
}

pub fn words_add_64(a: &[u64], b: &[u64], len: usize, out: &mut [u64]) -> u64 {
    let mut sum = Dword::default();
    for i in 0..len {
        sum = Dword { lo: sum.hi, hi: 0 };
        sum = word_add_word(sum, a[i]);
        sum = word_add_word(sum, b[i]);
        out[i] = sum.lo;
    }
    sum.hi
}

pub fn words_sub_64(a: &[u64], b: &[u64], len: usize, out: &mut [u64]) -> u64 {
    let mut sub = Dword::default();
    let mask = 1u64 << (WORD_BIT_LENGTH - 1);
    for i in 0..len {
        if sub.hi & mask != 0 {
            sub = Dword { hi: 0, lo: a[i] };
            sub = word_sub_word(sub, b[i]);
            sub = word_sub_word(sub, 1);
        } else {
            sub = Dword { hi: 0, lo: a[i] };
            sub = word_sub_word(sub, b[i]);
        }
        out[i] = sub.lo;
    }
    sub.hi
}

pub fn words_div(
    a: &[u64],
    b: &[u64],
    len: usize,
    mut q: Option<&mut [u64]>,
    mut r: Option<&mut [u64]>,
) {
    let a_len = len * 2;
    let aa_len = a_len + 1;
    let mut aa = vec![0u64; aa_len];
    aa[..a_len].copy_from_slice(a);
    let mut bb = vec![0u64; len];
    bb.copy_from_slice(b);

    if let Some(qbuf) = q.as_deref_mut() {
        qbuf.fill(0);
    }
    if let Some(rbuf) = r.as_deref_mut() {
        rbuf.fill(0);
    }

    let a_act_len = words_len(&aa[..a_len]);
    let aa_last_word_off = a_act_len;
    let b_act_len = words_len(&bb);
    let bb_last_word_off = b_act_len - 1;

    let norm_shift = WORD_BIT_LENGTH - super::word::word_bit_len(bb[bb_last_word_off]);
    let mut aa_shift = vec![0u64; aa_len];
    words_lshift(
        &aa[..=a_act_len],
        a_act_len + 1,
        norm_shift as i32,
        &mut aa_shift,
    );
    aa = aa_shift;
    let mut bb_shift = vec![0u64; len];
    words_lshift(&bb, b_act_len, norm_shift as i32, &mut bb_shift);
    bb = bb_shift;

    let rounds = a_act_len as i32 - b_act_len as i32;
    for j in 0..=rounds {
        let mut c = Dword::default();
        let tdiv = Dword {
            hi: aa[aa_last_word_off - j as usize],
            lo: aa[aa_last_word_off - (j as usize + 1)],
        };
        let (mut qhdw, rhw) = word_div(tdiv, bb[bb_last_word_off]);
        let mut rhdw = Dword { hi: 0, lo: rhw };

        if b_act_len > 1 {
            let mut edw = Dword::default();
            let mut fdw = Dword::default();
            if qhdw.hi == 0 {
                edw = word_mul_64(qhdw.lo, bb[bb_last_word_off - 1]);
                fdw = Dword {
                    hi: rhdw.lo,
                    lo: aa[aa_last_word_off - (2 + j as usize)],
                };
            }
            if qhdw.hi > 0 || word_cmp(edw, fdw) > 0 {
                qhdw = word_sub_word(qhdw, 1);
                rhdw = word_add_word(rhdw, bb[bb_last_word_off]);
                if rhdw.hi == 0 {
                    if qhdw.hi != 1 || qhdw.lo != 0 {
                        edw = word_mul_64(qhdw.lo, bb[bb_last_word_off - 1]);
                        fdw = Dword {
                            hi: rhdw.lo,
                            lo: aa[aa_last_word_off - (2 + j as usize)],
                        };
                    }
                    if (qhdw.hi == 1 && qhdw.lo == 0) || word_cmp(edw, fdw) > 0 {
                        qhdw = word_sub_word(qhdw, 1);
                    }
                }
            }
        }

        for i in (0..=bb_last_word_off).rev() {
            let mut d = word_mul_64(qhdw.lo, bb[bb_last_word_off - i]);
            d = word_add(d, c);
            c = Dword { hi: 0, lo: d.hi };
            if aa[aa_last_word_off - (i + j as usize + 1)] < d.lo {
                c = word_add_word(c, 1);
            }
            aa[aa_last_word_off - (i + j as usize + 1)] =
                aa[aa_last_word_off - (i + j as usize + 1)].wrapping_sub(d.lo);
        }

        let borrow = aa[aa_last_word_off - j as usize] < c.lo;
        aa[aa_last_word_off - j as usize] = aa[aa_last_word_off - j as usize].wrapping_sub(c.lo);

        if borrow {
            c = Dword::default();
            for i in (0..b_act_len).rev() {
                c = word_add_word(c, aa[aa_last_word_off - (i + j as usize + 1)]);
                c = word_add_word(c, bb[bb_last_word_off - i]);
                aa[aa_last_word_off - (i + j as usize + 1)] = c.lo;
                c = Dword { hi: 0, lo: c.hi };
            }
            aa[aa_last_word_off - j as usize] =
                aa[aa_last_word_off - j as usize].wrapping_add(c.lo);
            qhdw = word_sub_word(qhdw, 1);
        }

        if let Some(qbuf) = q.as_deref_mut() {
            qbuf[(rounds - j) as usize] = qhdw.lo;
        }
        let _ = rhw;
    }

    if let Some(rbuf) = r {
        words_rshift(0, &aa, b_act_len, norm_shift, rbuf);
    }
}

pub fn int_mul(a: &WordArray, b: &WordArray, out: &mut WordArray) {
    assert_eq!(a.buf.len(), b.buf.len());
    assert_eq!(out.buf.len(), 2 * a.buf.len());
    words_mul_64(&a.buf, &b.buf, a.buf.len(), &mut out.buf);
}

pub fn int_add(a: &WordArray, b: &WordArray, out: &mut WordArray) -> u64 {
    assert_eq!(a.buf.len(), b.buf.len());
    words_add_64(&a.buf, &b.buf, a.buf.len(), &mut out.buf)
}

pub fn int_sub(a: &WordArray, b: &WordArray, out: &mut WordArray) -> u64 {
    words_sub_64(&a.buf, &b.buf, a.buf.len(), &mut out.buf)
}

pub fn int_div(a: &WordArray, b: &WordArray, q: Option<&mut WordArray>, r: Option<&mut WordArray>) {
    assert_eq!(a.buf.len(), 2 * b.buf.len());
    words_div(
        &a.buf,
        &b.buf,
        b.buf.len(),
        q.map(|q| q.buf.as_mut_slice()),
        r.map(|r| r.buf.as_mut_slice()),
    );
}

pub fn int_rshift(a_hi: u64, a: &WordArray, shift: usize, out: &mut WordArray) {
    assert_eq!(a.buf.len(), out.buf.len());
    words_rshift(a_hi, &a.buf, a.buf.len(), shift, &mut out.buf);
}

pub fn int_sqr(a: &WordArray, out: &mut WordArray) {
    int_mul(a, a, out);
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
        WordArray::from_be_bytes(&hex::decode(s).expect("hex"))
    }

    /// Cryptonite `utest_math_int.c::int_mul_test`.
    #[test]
    fn int_mul_matches_cryptonite() {
        let a = wa_from_be_hex("173de2965cf7b2433dad8c8bbe4129a09ff7266b4fc0de92a80fabd2fab81206");
        let b = wa_from_be_hex("29fa4ea390474d027bddb12e9268dd53177c539c8989bbdb820fa51193c24a70");
        let exp = wa_from_be_hex(
            "3cfa2dd1044d41dc772fd1524b566c0926918a0ac24fef52b14fbcd7b74d3eeaccb02b36df1fdf1eec2da6dd5bc15dd1777d6a2c9ab7bf5ce90eb0400499ea0",
        );
        let mut act = WordArray::with_zero(2 * a.buf.len());
        int_mul(&a, &b, &mut act);
        assert_eq!(act.buf, exp.buf);
    }

    /// Cryptonite `utest_math_int.c::int_div_test1`.
    #[test]
    fn int_div_test1_matches_cryptonite() {
        let a = wa_from_be_hex("4BCC0130F40762CD4BCC0130F40762CE");
        let b = wa_from_be_hex("4BCC0130F40762CD");
        let exp_q = wa_from_be_hex("00000000000000010000000000000001");
        let exp_r = wa_from_be_hex("0000000000000001");

        let mut q = WordArray::with_zero(a.buf.len());
        let mut r = WordArray::with_zero(b.buf.len());
        int_div(&a, &b, Some(&mut q), Some(&mut r));

        assert_eq!(q.buf, exp_q.buf, "quotient mismatch");
        assert_eq!(r.buf, exp_r.buf, "remainder mismatch");
    }

    #[test]
    fn int_div_m163_sized_smoke() {
        let field_len = 3usize;
        let mut a = WordArray::with_zero(2 * field_len);
        let mut b = WordArray::with_zero(field_len);
        a.buf[0] = 0x1234;
        a.buf[1] = 0x5678;
        b.buf[0] = 0x42;
        b.buf[2] = 1; // n-like high bit
        let mut r = WordArray::with_zero(field_len);
        int_div(&a, &b, None, Some(&mut r));
        assert!(!r.buf.iter().all(|&w| w == 0));
    }

    #[test]
    fn int_div_test2_remainder_only() {
        let a = wa_from_be_hex("000000000000000000f7f6a8a6f56a5f8f73a2f658f2a7a3f65823f6e58276c1");
        let b = wa_from_be_hex("000000000a98b678a965b654a78b900a");
        let exp_r = wa_from_be_hex("000000000690f0f08aa10b25b03ac515");
        let mut r = WordArray::with_zero(b.buf.len());
        int_div(&a, &b, None, Some(&mut r));
        assert_eq!(r.buf, exp_r.buf);
    }

    #[test]
    fn int_mul_params2_a_times_one_layout() {
        let a = wa_from_be_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94",
        );
        let one = WordArray::with_one(a.buf.len());
        let mut ab = WordArray::with_zero(2 * a.buf.len());
        int_mul(&a, &one, &mut ab);
        assert_eq!(&ab.buf[..a.buf.len()], a.buf.as_slice());
        assert!(ab.buf[a.buf.len()..].iter().all(|&w| w == 0));
    }

    /// Cryptonite `utest_math_int.c::int_div_test4` — dividend `< divisor`, remainder equals dividend.
    #[test]
    fn int_div_test4_matches_cryptonite() {
        let mut a = wa_from_be_hex("800000000000000000000000000000000000000000000000000000000000042c");
        let b = wa_from_be_hex("8000000000000000000000000000000000000000000000000000000000000431");
        let exp_r = wa_from_be_hex("800000000000000000000000000000000000000000000000000000000000042c");
        a.change_len(2 * b.buf.len());
        let mut q = WordArray::with_zero(a.buf.len());
        let mut r = WordArray::with_zero(b.buf.len());
        int_div(&a, &b, Some(&mut q), Some(&mut r));
        assert_eq!(r.buf, exp_r.buf);
    }

    /// `int_div` remainder when dividend is `a` zero-extended to 512 bits (i.e. `a*1`).
    #[test]
    fn int_div_params2_a_times_one() {
        let p = wa_from_be_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
        );
        let a = wa_from_be_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94",
        );
        let one = WordArray::with_one(a.buf.len());
        let mut ab = WordArray::with_zero(2 * a.buf.len());
        int_mul(&a, &one, &mut ab);
        let mut r = WordArray::with_zero(p.buf.len());
        int_div(&ab, &p, None, Some(&mut r));
        assert_eq!(r.buf, a.buf, "a*1 mod p via int_div");
    }

    /// Params set 2: y² mod p reduction (GOST3410 test vector base point).
    #[test]
    fn int_div_params2_py_sqr_mod_p() {
        let p = wa_from_be_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97",
        );
        let y = wa_from_be_hex(
            "8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14",
        );
        let mut yy = WordArray::with_zero(2 * y.buf.len());
        int_sqr(&y, &mut yy);
        let mut r = WordArray::with_zero(p.buf.len());
        int_div(&yy, &p, None, Some(&mut r));
        let exp = wa_from_be_hex("a4");
        assert_eq!(r.buf[..exp.buf.len()], exp.buf, "y^2 mod p remainder");
    }

    /// Cryptonite `utest_math_int.c::int_div_test2`.
    #[test]
    fn int_div_test2_matches_cryptonite() {
        let a = wa_from_be_hex("000000000000000000f7f6a8a6f56a5f8f73a2f658f2a7a3f65823f6e58276c1");
        let b = wa_from_be_hex("000000000a98b678a965b654a78b900a");
        let exp_q =
            wa_from_be_hex("000000000000000000000000000000000000000176682e6ecbc286973627b5e");
        let exp_r = wa_from_be_hex("000000000690f0f08aa10b25b03ac515");

        let mut q = WordArray::with_zero(a.buf.len());
        let mut r = WordArray::with_zero(b.buf.len());
        int_div(&a, &b, Some(&mut q), Some(&mut r));

        assert_eq!(q.buf, exp_q.buf, "quotient mismatch");
        assert_eq!(r.buf, exp_r.buf, "remainder mismatch");
    }
}
