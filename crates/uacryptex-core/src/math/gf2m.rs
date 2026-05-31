//! GF(2^m) arithmetic (Cryptonite `math_gf2m_internal.c`, ARCH64 path).
#![allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]

use super::int::{int_bit_len, int_get_bit, int_is_one, int_is_zero, int_lshift};
use super::word::{wa_len, WordArray, WORD_BIT_LENGTH, WORD_BIT_LEN_MASK, WORD_BIT_LEN_SHIFT};

/// Cryptonite `WA_LEN(_bytes)`: byte count to word count.
#[inline]
pub fn wa_len_bytes(bytes: usize) -> usize {
    wa_len(bytes)
}

#[inline]
fn word_lshift(word: u64, bit: u32) -> u64 {
    if bit >= WORD_BIT_LENGTH as u32 {
        0
    } else {
        word << bit
    }
}

#[inline]
fn word_rshift(word: u64, bit: u32) -> u64 {
    if bit >= WORD_BIT_LENGTH as u32 {
        0
    } else {
        word >> bit
    }
}

const GF2M_SQR_PRECOMP: [u16; 256] = [
    0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015, 0x0040, 0x0041, 0x0044, 0x0045,
    0x0050, 0x0051, 0x0054, 0x0055, 0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
    0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155, 0x0400, 0x0401, 0x0404, 0x0405,
    0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
    0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515, 0x0540, 0x0541, 0x0544, 0x0545,
    0x0550, 0x0551, 0x0554, 0x0555, 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
    0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055, 0x1100, 0x1101, 0x1104, 0x1105,
    0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
    0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440, 0x1441, 0x1444, 0x1445,
    0x1450, 0x1451, 0x1454, 0x1455, 0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
    0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555, 0x4000, 0x4001, 0x4004, 0x4005,
    0x4010, 0x4011, 0x4014, 0x4015, 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
    0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140, 0x4141, 0x4144, 0x4145,
    0x4150, 0x4151, 0x4154, 0x4155, 0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
    0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455, 0x4500, 0x4501, 0x4504, 0x4505,
    0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
    0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015, 0x5040, 0x5041, 0x5044, 0x5045,
    0x5050, 0x5051, 0x5054, 0x5055, 0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
    0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155, 0x5400, 0x5401, 0x5404, 0x5405,
    0x5410, 0x5411, 0x5414, 0x5415, 0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
    0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544, 0x5545,
    0x5550, 0x5551, 0x5554, 0x5555,
];

#[derive(Clone, Debug)]
pub struct Gf2mCtx {
    pub f: Vec<i32>,
    pub f_ext: WordArray,
    pub len: usize,
}

impl Gf2mCtx {
    /// Cryptonite `gf2m_alloc` / `gf2m_init`. `f` must end with `0`.
    pub fn new(f: &[i32]) -> Self {
        assert!(!f.is_empty());
        assert_eq!(f[f.len() - 1], 0);

        let len = (f[0] as usize >> WORD_BIT_LEN_SHIFT) + 1;
        let mut f_ext = WordArray::with_zero(len);

        let start = if f[2] == 0 { 2 } else { 4 };
        for i in (0..=start).rev() {
            let idx = (f[i] as usize) >> WORD_BIT_LEN_SHIFT;
            f_ext.buf[idx] |= 1u64 << (f[i] as u64 & WORD_BIT_LEN_MASK);
        }

        Self {
            f: f.to_vec(),
            f_ext,
            len,
        }
    }
}

#[derive(Default)]
struct Dword {
    hi: u64,
    lo: u64,
}

macro_rules! word_lshift_and_xor {
    ($x:expr, $y:expr, $res:expr, $i:expr) => {
        if ($y & (1u64 << $i)) != 0 {
            $res.hi ^= $x >> (64 - $i);
            $res.lo ^= $x << $i;
        }
    };
}

fn gf2m_mul_64_fast(x: u64, y: u64) -> Dword {
    let mut res = Dword::default();
    word_lshift_and_xor!(x, y, res, 63);
    word_lshift_and_xor!(x, y, res, 62);
    word_lshift_and_xor!(x, y, res, 61);
    word_lshift_and_xor!(x, y, res, 60);
    word_lshift_and_xor!(x, y, res, 59);
    word_lshift_and_xor!(x, y, res, 58);
    word_lshift_and_xor!(x, y, res, 57);
    word_lshift_and_xor!(x, y, res, 56);
    word_lshift_and_xor!(x, y, res, 55);
    word_lshift_and_xor!(x, y, res, 54);
    word_lshift_and_xor!(x, y, res, 53);
    word_lshift_and_xor!(x, y, res, 52);
    word_lshift_and_xor!(x, y, res, 51);
    word_lshift_and_xor!(x, y, res, 50);
    word_lshift_and_xor!(x, y, res, 49);
    word_lshift_and_xor!(x, y, res, 48);
    word_lshift_and_xor!(x, y, res, 47);
    word_lshift_and_xor!(x, y, res, 46);
    word_lshift_and_xor!(x, y, res, 45);
    word_lshift_and_xor!(x, y, res, 44);
    word_lshift_and_xor!(x, y, res, 43);
    word_lshift_and_xor!(x, y, res, 42);
    word_lshift_and_xor!(x, y, res, 41);
    word_lshift_and_xor!(x, y, res, 40);
    word_lshift_and_xor!(x, y, res, 39);
    word_lshift_and_xor!(x, y, res, 38);
    word_lshift_and_xor!(x, y, res, 37);
    word_lshift_and_xor!(x, y, res, 36);
    word_lshift_and_xor!(x, y, res, 35);
    word_lshift_and_xor!(x, y, res, 34);
    word_lshift_and_xor!(x, y, res, 33);
    word_lshift_and_xor!(x, y, res, 32);
    word_lshift_and_xor!(x, y, res, 31);
    word_lshift_and_xor!(x, y, res, 30);
    word_lshift_and_xor!(x, y, res, 29);
    word_lshift_and_xor!(x, y, res, 28);
    word_lshift_and_xor!(x, y, res, 27);
    word_lshift_and_xor!(x, y, res, 26);
    word_lshift_and_xor!(x, y, res, 25);
    word_lshift_and_xor!(x, y, res, 24);
    word_lshift_and_xor!(x, y, res, 23);
    word_lshift_and_xor!(x, y, res, 22);
    word_lshift_and_xor!(x, y, res, 21);
    word_lshift_and_xor!(x, y, res, 20);
    word_lshift_and_xor!(x, y, res, 19);
    word_lshift_and_xor!(x, y, res, 18);
    word_lshift_and_xor!(x, y, res, 17);
    word_lshift_and_xor!(x, y, res, 16);
    word_lshift_and_xor!(x, y, res, 15);
    word_lshift_and_xor!(x, y, res, 14);
    word_lshift_and_xor!(x, y, res, 13);
    word_lshift_and_xor!(x, y, res, 12);
    word_lshift_and_xor!(x, y, res, 11);
    word_lshift_and_xor!(x, y, res, 10);
    word_lshift_and_xor!(x, y, res, 9);
    word_lshift_and_xor!(x, y, res, 8);
    word_lshift_and_xor!(x, y, res, 7);
    word_lshift_and_xor!(x, y, res, 6);
    word_lshift_and_xor!(x, y, res, 5);
    word_lshift_and_xor!(x, y, res, 4);
    word_lshift_and_xor!(x, y, res, 3);
    word_lshift_and_xor!(x, y, res, 2);
    word_lshift_and_xor!(x, y, res, 1);
    if y & 1 != 0 {
        res.lo ^= x;
    }
    res
}

fn wa_swap(x: &WordArray, y: &mut WordArray) {
    for i in 0..x.buf.len() {
        y.buf[i] = x.buf[x.buf.len() - 1 - i];
    }
}

fn gf2m_mul_256(x: &[u64], y: &[u64], len: usize, mode: bool, r: &mut [u64]) {
    let indx = if mode { len } else { len - 4 };

    let (x0, x1, x2, x3, y0, y1, y2, y3) = if mode && indx >= 4 {
        (
            x[indx - 4],
            x[indx - 3],
            x[indx - 2],
            x[indx - 1],
            y[indx - 4],
            y[indx - 3],
            y[indx - 2],
            y[indx - 1],
        )
    } else {
        let mut mul256 = [0u64; 4];
        mul256[4 - indx..].copy_from_slice(&x[..indx]);
        let (x0, x1, x2, x3) = (mul256[0], mul256[1], mul256[2], mul256[3]);

        mul256.fill(0);
        mul256[4 - indx..].copy_from_slice(&y[..indx]);
        (x0, x1, x2, x3, mul256[0], mul256[1], mul256[2], mul256[3])
    };

    let res = gf2m_mul_64_fast(x0, y0);
    let (x00, x01) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x1, y1);
    let (x10, x11) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x2, y2);
    let (x20, x21) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x3, y3);
    let (x30, x31) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x0 ^ x1, y0 ^ y1);
    let (y00, y01) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x2 ^ x3, y2 ^ y3);
    let (y10, y11) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x0 ^ x2, y0 ^ y2);
    let (a00, a01) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x1 ^ x3, y1 ^ y3);
    let (a10, a11) = (res.hi, res.lo);
    let res = gf2m_mul_64_fast(x0 ^ x1 ^ x2 ^ x3, y0 ^ y1 ^ y2 ^ y3);
    let (d0, d1) = (res.hi, res.lo);

    let e32 = x31 ^ x21 ^ x30;
    let e31 = e32 ^ x11 ^ x20;
    let e30 = e31 ^ x01 ^ x10;
    let e20 = e30 ^ x31 ^ x00;
    let e10 = e20 ^ x21 ^ x30;
    let e00 = e10 ^ x11 ^ x20;
    let c = a01 ^ a10;

    let mut mul256 = [0u64; 8];
    mul256[7] = x31;
    mul256[6] = y11 ^ e32;
    mul256[5] = a11 ^ e31 ^ y10;
    mul256[4] = d1 ^ a11 ^ y01 ^ y11 ^ e30 ^ c;
    mul256[3] = d0 ^ a00 ^ y00 ^ y10 ^ e20 ^ c;
    mul256[2] = y01 ^ e10 ^ a00;
    mul256[1] = y00 ^ e00;
    mul256[0] = x00;

    if !mode {
        let copy_len = 2 * indx - 4;
        r[..copy_len].copy_from_slice(&mul256[2 * (4 - indx)..2 * (4 - indx) + copy_len]);

        let mut i = copy_len;
        for j in 4..8 {
            r[i] ^= mul256[j];
            i += 1;
        }
        let mut i = 4;
        for j in 2 * (4 - indx)..8 {
            r[i] ^= mul256[j];
            i += 1;
        }
        return;
    }

    if indx >= 4 {
        r[2 * (indx - 4)..2 * (indx - 4) + 8].copy_from_slice(&mul256);
    } else {
        r[..2 * indx].copy_from_slice(&mul256[2 * (4 - indx)..2 * (4 - indx) + 2 * indx]);
    }
}

fn gf2m_mul_64(x: &[u64], y: &[u64], r: &mut [u64]) {
    let res = gf2m_mul_64_fast(x[0], y[0]);
    r[0] = res.hi;
    r[1] = res.lo;
}

fn gf2m_mul_128(x: &[u64], y: &[u64], r: &mut [u64]) {
    let _ = x.len();
    let res = gf2m_mul_64_fast(x[0], y[0]);
    let a00 = res.hi;
    let mut c = res.lo;

    let res = gf2m_mul_64_fast(x[1], y[1]);
    let a11 = res.lo;
    c ^= res.hi;

    let res = gf2m_mul_64_fast(x[0] ^ x[1], y[0] ^ y[1]);
    let b00 = res.hi;
    let b11 = res.lo;

    r[3] = a11;
    r[2] = b11 ^ a11 ^ c;
    r[1] = b00 ^ a00 ^ c;
    r[0] = a00;
}

fn gf2m_xor_assign(out: &mut WordArray, other: &WordArray) {
    assert_eq!(out.buf.len(), other.buf.len());
    for i in 0..out.buf.len() {
        out.buf[i] ^= other.buf[i];
    }
}

pub fn gf2m_mod_add(a: &WordArray, b: &WordArray, out: &mut WordArray) {
    assert_eq!(a.buf.len(), b.buf.len());
    assert_eq!(a.buf.len(), out.buf.len());
    for i in 0..out.buf.len() {
        out.buf[i] = a.buf[i] ^ b.buf[i];
    }
}

/// In-place XOR: `out ^= other` (Cryptonite aliasing for `gf2m_mod_add(out, other, out)`).
pub fn gf2m_mod_add_assign(out: &mut WordArray, other: &WordArray) {
    gf2m_xor_assign(out, other);
}

/// Field add with C-style operand/output aliasing.
fn wa_same(a: &WordArray, b: &WordArray) -> bool {
    std::ptr::eq(a as *const WordArray, b as *const WordArray)
}

pub fn gf2m_mod_add_alias(a: &WordArray, b: &WordArray, out: &mut WordArray) {
    if wa_same(a, out) {
        gf2m_mod_add_assign(out, b);
    } else if wa_same(b, out) {
        gf2m_mod_add_assign(out, a);
    } else {
        gf2m_mod_add(a, b, out);
    }
}

pub fn gf2m_mod_mul_alias(ctx: &Gf2mCtx, a: &WordArray, b: &WordArray, out: &mut WordArray) {
    if wa_same(a, out) || wa_same(b, out) {
        let ac = a.clone();
        let bc = b.clone();
        gf2m_mod_mul(ctx, &ac, &bc, out);
    } else {
        gf2m_mod_mul(ctx, a, b, out);
    }
}

pub fn gf2m_mod_sqr_alias(ctx: &Gf2mCtx, a: &WordArray, out: &mut WordArray) {
    if wa_same(a, out) {
        let ac = a.clone();
        gf2m_mod_sqr(ctx, &ac, out);
    } else {
        gf2m_mod_sqr(ctx, a, out);
    }
}

pub fn gf2m_mod(ctx: &Gf2mCtx, a: &mut WordArray, out: &mut WordArray) {
    assert_eq!(a.buf.len(), 2 * ctx.len);
    assert_eq!(out.buf.len(), ctx.len);

    let mut deg_a = int_bit_len(a) as i32 - 1;
    let deg_f = ctx.f[0];
    let alen = (2 * ctx.len) as i32;

    if deg_a < deg_f {
        a.copy_part(0, ctx.len, out);
        return;
    }

    let a_woff0 = alen - 1 - (ctx.f[0] >> WORD_BIT_LEN_SHIFT as i32);
    let a_woff1 = alen - 1 - (ctx.f[1] >> WORD_BIT_LEN_SHIFT as i32);
    let a_woff2 = alen - 1 - (ctx.f[2] >> WORD_BIT_LEN_SHIFT as i32);
    let a_boff0 = (ctx.f[0] & WORD_BIT_LEN_MASK as i32) as u32;
    let a_boff1 = (ctx.f[1] & WORD_BIT_LEN_MASK as i32) as u32;
    let a_boff2 = (ctx.f[2] & WORD_BIT_LEN_MASK as i32) as u32;

    let (a_woff3, a_boff3) = if ctx.f[2] != 0 {
        (
            alen - 1 - (ctx.f[3] >> WORD_BIT_LEN_SHIFT as i32),
            (ctx.f[3] & WORD_BIT_LEN_MASK as i32) as u32,
        )
    } else {
        (0, 0)
    };

    let mut i = (deg_a - (deg_f - a_boff0 as i32)) >> WORD_BIT_LEN_SHIFT as i32;

    if a_woff0 == i {
        let t = word_rshift(a.buf[alen as usize - 1], a_boff0);
        let j = a_woff1 - i;
        a.buf[alen as usize - 1] ^= word_lshift(t, a_boff0);
        a.buf[alen as usize - 1 - j as usize] ^= word_lshift(t, a_boff1);
        if j != 0 && a_boff1 != 0 {
            a.buf[alen as usize - j as usize] ^= word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff1);
        }

        let j = a_woff2 - i;
        a.buf[alen as usize - 1 - j as usize] ^= word_lshift(t, a_boff2);
        if j != 0 && a_boff2 != 0 {
            a.buf[alen as usize - j as usize] ^= word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff2);
        }

        if ctx.f[2] != 0 {
            let j = a_woff3 - i;
            a.buf[alen as usize - 1 - j as usize] ^= word_lshift(t, a_boff3);
            if j != 0 && a_boff3 != 0 {
                a.buf[alen as usize - j as usize] ^=
                    word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff3);
            }
            a.buf[i as usize] ^= t;
        }
        i -= 1;
    }

    while deg_a >= deg_f {
        while i >= 0 {
            let a_woff0i = a_woff0 - i;
            let a_woff1i = a_woff1 - i;
            let a_woff2i = a_woff2 - i;

            let t = word_rshift(a.buf[alen as usize - 1 - a_woff0i as usize], a_boff0)
                | word_lshift(
                    a.buf[alen as usize - a_woff0i as usize],
                    WORD_BIT_LENGTH as u32 - a_boff0,
                );

            a.buf[alen as usize - 1 - a_woff0i as usize] ^= word_lshift(t, a_boff0);
            a.buf[alen as usize - a_woff0i as usize] ^=
                word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff0);
            a.buf[alen as usize - 1 - a_woff1i as usize] ^= word_lshift(t, a_boff1);
            if a_boff1 != 0 {
                a.buf[alen as usize - a_woff1i as usize] ^=
                    word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff1);
            }
            a.buf[alen as usize - 1 - a_woff2i as usize] ^= word_lshift(t, a_boff2);

            if ctx.f[2] != 0 {
                let a_woff3i = a_woff3 - i;
                let a_woff4i = alen - 1 - i;
                if a_boff2 != 0 {
                    a.buf[alen as usize - a_woff2i as usize] ^=
                        word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff2);
                }
                a.buf[alen as usize - 1 - a_woff3i as usize] ^= word_lshift(t, a_boff3);
                if a_boff3 != 0 {
                    a.buf[alen as usize - a_woff3i as usize] ^=
                        word_rshift(t, WORD_BIT_LENGTH as u32 - a_boff3);
                }
                a.buf[alen as usize - 1 - a_woff4i as usize] ^= t;
            }
            i -= 1;
        }

        deg_a = int_bit_len(a) as i32 - 1;
        i = (deg_a - (deg_f - a_boff0 as i32)) >> WORD_BIT_LEN_SHIFT as i32;
    }

    a.copy_part(0, ctx.len, out);
}

pub fn gf2m_mod_sqr(ctx: &Gf2mCtx, a: &WordArray, out: &mut WordArray) {
    assert_eq!(a.buf.len(), ctx.len);
    assert_eq!(out.buf.len(), ctx.len);

    let mut sqr = WordArray::with_zero(2 * ctx.len);

    for i in 0..ctx.len {
        let w = a.buf[i];
        sqr.buf[2 * i + 1] = (GF2M_SQR_PRECOMP[((w >> 56) & 0xff) as usize] as u64) << 48
            | (GF2M_SQR_PRECOMP[((w >> 48) & 0xff) as usize] as u64) << 32
            | (GF2M_SQR_PRECOMP[((w >> 40) & 0xff) as usize] as u64) << 16
            | GF2M_SQR_PRECOMP[((w >> 32) & 0xff) as usize] as u64;
        sqr.buf[2 * i] = (GF2M_SQR_PRECOMP[((w >> 24) & 0xff) as usize] as u64) << 48
            | (GF2M_SQR_PRECOMP[((w >> 16) & 0xff) as usize] as u64) << 32
            | (GF2M_SQR_PRECOMP[((w >> 8) & 0xff) as usize] as u64) << 16
            | GF2M_SQR_PRECOMP[(w & 0xff) as usize] as u64;
    }

    gf2m_mod(ctx, &mut sqr, out);
}

pub fn gf2m_mul_opt(ctx: &Gf2mCtx, x1: &WordArray, y1: &WordArray, r1: &mut WordArray) {
    assert_eq!(x1.buf.len(), ctx.len);
    assert_eq!(y1.buf.len(), ctx.len);
    assert_eq!(r1.buf.len(), 2 * ctx.len);

    let n = ctx.len;

    if n > wa_len_bytes(64) {
        let y_len = int_bit_len(y1);
        r1.zero();
        let mut ash = x1.clone();
        ash.change_len(2 * x1.buf.len());
        let mut shifted = WordArray::with_zero(ash.buf.len());

        for i in 0..y_len {
            if i != 0 {
                int_lshift(&ash, 1, &mut shifted);
                std::mem::swap(&mut ash, &mut shifted);
            }
            if int_get_bit(y1, i) != 0 {
                gf2m_xor_assign(r1, &ash);
            }
        }
        return;
    }

    let mut x = WordArray::with_zero(x1.buf.len());
    let mut y = WordArray::with_zero(y1.buf.len());
    let mut r = WordArray::with_zero(r1.buf.len());

    wa_swap(x1, &mut x);
    wa_swap(y1, &mut y);

    if n <= wa_len_bytes(32) {
        gf2m_mul_256(&x.buf, &y.buf, n, true, &mut r.buf);
        wa_swap(&r, r1);
        return;
    }

    if ctx.f[0] == 257 {
        r.buf[0] = 0;
        r.buf[1] = if x.buf[0] == 1 && y.buf[0] == 1 { 1 } else { 0 };
        gf2m_mul_256(&x.buf, &y.buf, n, true, &mut r.buf);

        if x.buf[0] == 1 {
            for i in 1..wa_len_bytes(36) {
                r.buf[i + 1] ^= y.buf[i];
            }
        }

        if y.buf[0] == 1 {
            for i in 1..wa_len_bytes(36) {
                r.buf[i + 1] ^= x.buf[i];
            }
        }

        wa_swap(&r, r1);
        return;
    }

    let s = if 2 * n > wa_len_bytes(96) {
        2 * n - wa_len_bytes(96)
    } else {
        0
    };

    gf2m_mul_256(&x.buf, &y.buf, n, true, &mut r.buf);
    let copy_len = 2 * n - wa_len_bytes(64) - s;
    let chunk = r.buf[wa_len_bytes(32) + s..wa_len_bytes(32) + s + copy_len].to_vec();
    r.buf[s..s + copy_len].copy_from_slice(&chunk);

    let mut i = 2 * n as i32 - wa_len_bytes(64) as i32;
    let mut j = 2 * n as i32 - wa_len_bytes(32) as i32;
    while j < 2 * n as i32 {
        r.buf[i as usize] ^= r.buf[j as usize];
        i += 1;
        j += 1;
    }

    let mut x_poly = [0u64; 32];
    let mut y_poly = [0u64; 32];
    let mut dt_poly = [0u64; 64];

    x_poly[..wa_len_bytes(32)].copy_from_slice(&x.buf[n - wa_len_bytes(32)..]);
    let mut idx = wa_len_bytes(64) - n;
    for word in x.buf[..n - wa_len_bytes(32)].iter() {
        x_poly[idx] ^= word;
        idx += 1;
    }

    y_poly[..wa_len_bytes(32)].copy_from_slice(&y.buf[n - wa_len_bytes(32)..]);
    idx = wa_len_bytes(64) - n;
    for word in y.buf[..n - wa_len_bytes(32)].iter() {
        y_poly[idx] ^= word;
        idx += 1;
    }

    gf2m_mul_256(&x_poly, &y_poly, wa_len_bytes(32), true, &mut dt_poly);
    let mut i = s as i32;
    let mut j = wa_len_bytes(96) as i32 - 2 * n as i32 + s as i32;
    while j < wa_len_bytes(64) as i32 {
        r.buf[i as usize] ^= dt_poly[j as usize];
        i += 1;
        j += 1;
    }

    if n <= wa_len_bytes(40) {
        gf2m_mul_64(&x.buf, &y.buf, &mut dt_poly);
        for i in 0..wa_len_bytes(16) {
            r.buf[i] ^= dt_poly[i];
            r.buf[i + wa_len_bytes(32)] ^= dt_poly[i];
        }
    } else if n <= wa_len_bytes(48) {
        gf2m_mul_128(&x.buf, &y.buf, &mut dt_poly);
        let j = (wa_len_bytes(48) - n) * 2;
        let mut i = wa_len_bytes(32) - 1 - j;
        loop {
            r.buf[i] ^= dt_poly[i + j];
            r.buf[i + wa_len_bytes(32)] ^= dt_poly[i + j];
            if i == 0 {
                break;
            }
            i -= 1;
        }
    } else {
        gf2m_mul_256(&x.buf, &y.buf, n, false, &mut r.buf);
    }

    wa_swap(&r, r1);
}

pub fn gf2m_mod_mul(ctx: &Gf2mCtx, a: &WordArray, b: &WordArray, out: &mut WordArray) {
    assert_eq!(a.buf.len(), ctx.len);
    assert_eq!(b.buf.len(), ctx.len);
    assert_eq!(out.buf.len(), ctx.len);

    let mut out2 = WordArray::with_zero(2 * a.buf.len());
    gf2m_mul_opt(ctx, a, b, &mut out2);
    gf2m_mod(ctx, &mut out2, out);
}

pub fn gf2m_mod_gcd(
    a: &WordArray,
    b: &WordArray,
    gcd: Option<&mut WordArray>,
    ka: Option<&mut WordArray>,
    kb: Option<&mut WordArray>,
) {
    assert_eq!(a.buf.len(), b.buf.len());
    let n = a.buf.len();

    let mut t1 = a.clone();
    let mut t2 = b.clone();
    let mut t3 = WordArray::with_one(n);
    let mut t4 = WordArray::with_zero(n);
    let mut dt = WordArray::with_zero(n);

    while int_bit_len(&t1) > 1 {
        let mut i = int_bit_len(&t1) as i32 - int_bit_len(&t2) as i32;

        if i < 0 {
            std::mem::swap(&mut t1, &mut t2);
            std::mem::swap(&mut t3, &mut t4);
            i = -i;
        }

        int_lshift(&t2, i as usize, &mut dt);
        gf2m_xor_assign(&mut t1, &dt);
        int_lshift(&t4, i as usize, &mut dt);
        gf2m_xor_assign(&mut t3, &dt);
    }

    if let Some(g) = gcd {
        t1.copy_to(g);
    }
    if let Some(k) = ka {
        t3.copy_to(k);
    }
    if let Some(k) = kb {
        t4.copy_to(k);
    }
}

pub fn gf2m_mod_inv(ctx: &Gf2mCtx, a: &WordArray, out: &mut WordArray) {
    assert!(!int_is_zero(a));

    if int_is_one(a) {
        a.copy_to(out);
        return;
    }

    gf2m_mod_gcd(a, &ctx.f_ext, None, Some(out), None);
}

pub fn gf2m_mod_trace(ctx: &Gf2mCtx, a: &WordArray) -> i32 {
    let mut tr = a.clone();
    let mut tmp = WordArray::with_zero(tr.buf.len());

    for _ in 0..ctx.f[0] - 1 {
        gf2m_mod_sqr(ctx, &tr, &mut tmp);
        gf2m_mod_add(a, &tmp, &mut tr);
    }

    if tr.buf[0] != 0 {
        1
    } else {
        0
    }
}

fn gf2m_mod_htrace(ctx: &Gf2mCtx, a: &WordArray, htrace: &mut WordArray) {
    let mut ht = a.clone();
    let mut tmp = WordArray::with_zero(ht.buf.len());
    let mut i = (ctx.f[0] - 1) / 2 - 1;
    while i >= 0 {
        gf2m_mod_sqr(ctx, &ht, &mut tmp);
        gf2m_mod_sqr(ctx, &tmp, &mut ht);
        for i in 0..ht.buf.len() {
            ht.buf[i] ^= a.buf[i];
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    ht.copy_to(htrace);
}

pub fn gf2m_mod_solve_quad(ctx: &Gf2mCtx, a: &WordArray, out: &mut WordArray) -> bool {
    if gf2m_mod_trace(ctx, a) != 0 {
        return false;
    }
    gf2m_mod_htrace(ctx, a, out);
    true
}

pub fn gf2m_mod_sqrt(ctx: &Gf2mCtx, a: &WordArray, out: &mut WordArray) {
    let mut cur = a.clone();
    let mut nxt = WordArray::with_zero(cur.buf.len());
    for _ in 0..ctx.f[0] - 1 {
        gf2m_mod_sqr(ctx, &cur, &mut nxt);
        std::mem::swap(&mut cur, &mut nxt);
    }
    cur.copy_to(out);
}
