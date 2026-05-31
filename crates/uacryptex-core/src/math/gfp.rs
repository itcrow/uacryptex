//! Prime field GF(p) arithmetic (Cryptonite `math_gfp_internal.c`).

use super::int::{
    int_bit_len, int_cmp, int_equals, int_get_bit, int_is_one, int_is_zero, int_word_len,
};
use super::int_arith::{int_add, int_div, int_mul, int_rshift, int_sqr, int_sub};
use super::int::int_lshift;
use super::word::{WordArray, WORD_BIT_LENGTH};

#[derive(Clone, Debug)]
pub struct GfpCtx {
    pub p: WordArray,
    pub one: WordArray,
    pub two: WordArray,
    invert_const: WordArray,
}

impl GfpCtx {
    pub fn new(p: &WordArray) -> Self {
        let len = p.buf.len();
        let one = WordArray::with_one(len);
        let mut two = WordArray::with_zero(len);
        two.buf[0] = 2;

        let mut two_power_plen = WordArray::with_zero(2 * len);
        two_power_plen.buf[int_word_len(p)] = 1;
        let mut two_power_plen_mod_p = WordArray::with_zero(len);
        int_div(&two_power_plen, p, None, Some(&mut two_power_plen_mod_p));
        let invert_const = gfp_mod_inv_core(&two_power_plen_mod_p, p)
            .expect("invert_const must exist for valid prime");

        Self {
            p: p.clone(),
            one,
            two,
            invert_const,
        }
    }
}

fn wa_rshift1(w: &mut WordArray) {
    let src = w.clone();
    int_rshift(0, &src, 1, w);
}

fn wa_rshift1_carry(w: &mut WordArray, carry: u64) {
    let src = w.clone();
    int_rshift(carry, &src, 1, w);
}

fn wa_lshift1(w: &mut WordArray) {
    let src = w.clone();
    int_lshift(&src, 1, w);
}

fn wa_add_into(out: &mut WordArray, other: &WordArray) -> u64 {
    let src = out.clone();
    int_add(&src, other, out)
}

fn wa_sub_into(out: &mut WordArray, other: &WordArray) -> u64 {
    let src = out.clone();
    int_sub(&src, other, out)
}

fn gfp_mod_inv_ext_euclid(in_: &WordArray, p: &WordArray) -> Option<WordArray> {
    let len = in_.buf.len();
    let mut q = WordArray::with_zero(2 * len);
    let mut r = WordArray::with_zero(len);
    let mut x1 = WordArray::with_zero(len);
    let mut x2 = WordArray::with_one(len);
    let mut x = WordArray::with_zero(len);
    let mut tmp = WordArray::with_zero(len);

    let mut a = in_.clone();
    a.change_len(2 * len);
    let mut b = p.clone();

    if int_is_zero(&b) {
        return None;
    }

    while !int_is_zero(&b) {
        int_div(&a, &b, Some(&mut q), Some(&mut r));
        q.copy_part(0, len, &mut tmp);
        int_mul(&tmp, &x1, &mut a);
        int_div(&a, p, None, Some(&mut tmp));
        if int_sub(&x2, &tmp, &mut x) != 0 {
            wa_add_into(&mut x, p);
        }

        a.copy_from_slice(&b);
        std::mem::swap(&mut b, &mut r);
        std::mem::swap(&mut x2, &mut x1);
        std::mem::swap(&mut x1, &mut x);
    }

    if int_is_one(&a) {
        Some(x2)
    } else {
        None
    }
}

fn gfp_mod_inv_binary(x: &WordArray, p: &WordArray) -> Option<WordArray> {
    if int_is_one(x) {
        return Some(x.clone());
    }

    let len = x.buf.len();
    let mut a = x.clone();
    let mut b = p.clone();
    let mut c = WordArray::with_one(len);
    let mut d = WordArray::with_zero(len);

    while !int_is_one(&a) && !int_is_one(&b) {
        while int_get_bit(&a, 0) == 0 {
            wa_rshift1(&mut a);
            let c_hi = if int_get_bit(&c, 0) == 1 {
                wa_add_into(&mut c, p)
            } else {
                0
            };
            wa_rshift1_carry(&mut c, c_hi);
        }

        while int_get_bit(&b, 0) == 0 {
            wa_rshift1(&mut b);
            let carry = if int_get_bit(&d, 0) == 1 {
                wa_add_into(&mut d, p)
            } else {
                0
            };
            wa_rshift1_carry(&mut d, carry);
        }

        if int_cmp(&a, &b) >= 0 {
            wa_sub_into(&mut a, &b);
            if wa_sub_into(&mut c, &d) != 0 {
                wa_add_into(&mut c, p);
            }
        } else {
            wa_sub_into(&mut b, &a);
            if wa_sub_into(&mut d, &c) != 0 {
                wa_add_into(&mut d, p);
            }
        }
    }

    Some(if int_is_one(&a) { c } else { d })
}

pub fn gfp_mod_inv_core(x: &WordArray, p: &WordArray) -> Option<WordArray> {
    assert!(!int_is_zero(x));
    assert!(!int_is_zero(p));
    if (p.buf[0] & 1) == 0 {
        gfp_mod_inv_ext_euclid(x, p)
    } else {
        gfp_mod_inv_binary(x, p)
    }
}

pub fn gfp_mod_add(ctx: &GfpCtx, a: &WordArray, b: &WordArray, out: &mut WordArray) {
    let mut t = WordArray::with_zero(a.buf.len());
    if int_add(a, b, &mut t) > 0 || int_cmp(&t, &ctx.p) >= 0 {
        int_sub(&t, &ctx.p, out);
    } else {
        out.copy_from_slice(&t);
    }
}

pub fn gfp_mod_sub(ctx: &GfpCtx, a: &WordArray, b: &WordArray, out: &mut WordArray) {
    let mut t = WordArray::with_zero(a.buf.len());
    if int_sub(a, b, &mut t) != 0 {
        int_add(&t, &ctx.p, out);
    } else {
        out.copy_from_slice(&t);
    }
}

pub fn gfp_mod(ctx: &GfpCtx, a: &WordArray, out: &mut WordArray) {
    assert_eq!(a.buf.len(), 2 * ctx.p.buf.len());
    int_div(a, &ctx.p, None, Some(out));
}

pub fn gfp_mod_mul(ctx: &GfpCtx, a: &WordArray, b: &WordArray, out: &mut WordArray) {
    let mut ab = WordArray::with_zero(2 * a.buf.len());
    int_mul(a, b, &mut ab);
    gfp_mod(ctx, &ab, out);
}

pub fn gfp_mod_sqr(ctx: &GfpCtx, a: &WordArray, out: &mut WordArray) {
    let mut aa = WordArray::with_zero(2 * a.buf.len());
    int_sqr(a, &mut aa);
    gfp_mod(ctx, &aa, out);
}

pub fn gfp_mod_inv(ctx: &GfpCtx, in_: &WordArray) -> Option<WordArray> {
    if (ctx.p.buf[0] & 1) == 0 {
        return gfp_mod_inv_ext_euclid(in_, &ctx.p);
    }

    if int_equals(in_, &ctx.one) {
        return Some(in_.clone());
    }

    let len = in_.buf.len();
    let mut a = in_.clone();
    let mut b = ctx.p.clone();
    let mut c = WordArray::with_one(len);
    let mut d = WordArray::with_zero(len);
    let mut k = 0usize;
    let mut carry = 0u64;

    while !int_is_zero(&b) {
        if int_get_bit(&b, 0) == 0 {
            wa_rshift1(&mut b);
            carry = c.buf[len - 1] >> (WORD_BIT_LENGTH - 1);
            wa_lshift1(&mut c);
        } else if int_get_bit(&a, 0) == 0 {
            wa_rshift1(&mut a);
            wa_lshift1(&mut d);
        } else if int_cmp(&b, &a) >= 0 {
            wa_sub_into(&mut b, &a);
            wa_rshift1(&mut b);
            wa_add_into(&mut d, &c);
            carry = c.buf[len - 1] >> (WORD_BIT_LENGTH - 1);
            wa_lshift1(&mut c);
        } else {
            wa_sub_into(&mut a, &b);
            wa_rshift1(&mut a);
            wa_add_into(&mut c, &d);
            wa_lshift1(&mut d);
        }
        k += 1;
    }

    if carry > 0 || int_cmp(&c, &ctx.p) >= 0 {
        wa_sub_into(&mut c, &ctx.p);
    }

    let bit_len = int_word_len(&ctx.p) * WORD_BIT_LENGTH;
    while k > bit_len {
        carry = 0;
        if int_get_bit(&c, 0) == 1 {
            carry = wa_add_into(&mut c, &ctx.p);
        }
        wa_rshift1_carry(&mut c, carry);
        k -= 1;
    }

    let mut out = WordArray::with_zero(len);
    gfp_mod_mul(ctx, &c, &ctx.invert_const, &mut out);
    Some(out)
}

/// `gfp_mod_pow` — binary exponentiation in GF(p).
pub fn gfp_mod_pow(ctx: &GfpCtx, a: &WordArray, exp: &WordArray, out: &mut WordArray) {
    let mut acc = ctx.one.clone();
    let len = int_bit_len(exp);
    if len == 0 {
        out.copy_from_slice(&acc);
        return;
    }
    for i in (0..len).rev() {
        let mut sqr = WordArray::with_zero(acc.buf.len());
        gfp_mod_sqr(ctx, &acc, &mut sqr);
        if int_get_bit(exp, i) == 1 {
            gfp_mod_mul(ctx, a, &sqr, &mut acc);
        } else {
            acc = sqr;
        }
    }
    out.copy_from_slice(&acc);
}

fn gfp_mod_lucas_seq(
    ctx: &GfpCtx,
    a: &WordArray,
    b: &WordArray,
    k: &WordArray,
    ck: &mut WordArray,
    bk: &mut WordArray,
) {
    let mut b0 = ctx.one.clone();
    let mut b1 = ctx.one.clone();
    let mut c0 = ctx.two.clone();
    let mut c1 = a.clone();
    let len = ctx.p.buf.len();

    for i in (0..int_bit_len(k)).rev() {
        let mut next_b0 = WordArray::with_zero(len);
        gfp_mod_mul(ctx, &b0, &b1, &mut next_b0);
        b0 = next_b0;

        if int_get_bit(k, i) == 1 {
            let mut next_b1 = WordArray::with_zero(len);
            gfp_mod_mul(ctx, &b0, b, &mut next_b1);
            b1 = next_b1;

            let mut next_c0 = WordArray::with_zero(len);
            gfp_mod_mul(ctx, &c0, &c1, &mut next_c0);
            let mut t = WordArray::with_zero(len);
            gfp_mod_mul(ctx, &b0, a, &mut t);
            let mut c0_new = WordArray::with_zero(len);
            gfp_mod_sub(ctx, &next_c0, &t, &mut c0_new);
            c0 = c0_new;

            let mut next_c1 = WordArray::with_zero(len);
            gfp_mod_sqr(ctx, &c1, &mut next_c1);
            let mut t2 = WordArray::with_zero(len);
            gfp_mod_add(ctx, &b1, &b1, &mut t2);
            let mut c1_new = WordArray::with_zero(len);
            gfp_mod_sub(ctx, &next_c1, &t2, &mut c1_new);
            c1 = c1_new;
        } else {
            b1 = b0.clone();

            let mut next_c1 = WordArray::with_zero(len);
            gfp_mod_mul(ctx, &c0, &c1, &mut next_c1);
            let mut t = WordArray::with_zero(len);
            gfp_mod_mul(ctx, &b0, a, &mut t);
            let mut c1_new = WordArray::with_zero(len);
            gfp_mod_sub(ctx, &next_c1, &t, &mut c1_new);
            c1 = c1_new;

            let mut next_c0 = WordArray::with_zero(len);
            gfp_mod_sqr(ctx, &c0, &mut next_c0);
            let mut t2 = WordArray::with_zero(len);
            gfp_mod_add(ctx, &b0, &b0, &mut t2);
            let mut c0_new = WordArray::with_zero(len);
            gfp_mod_sub(ctx, &next_c0, &t2, &mut c0_new);
            c0 = c0_new;
        }
    }

    ck.copy_from_slice(&c0);
    bk.copy_from_slice(&b0);
}

/// `gfp_mod_sqrt` — returns `true` when `a` is a quadratic residue mod `p`.
pub fn gfp_mod_sqrt(ctx: &GfpCtx, a: &WordArray, out: &mut WordArray) -> bool {
    assert_eq!(a.buf.len(), ctx.p.buf.len());
    assert_eq!(out.buf.len(), ctx.p.buf.len());

    if int_is_zero(a) || int_is_one(a) {
        out.copy_from_slice(a);
        return true;
    }

    let mut b = WordArray::with_zero(ctx.p.buf.len());
    let mut c = WordArray::with_zero(ctx.p.buf.len());
    let mut d = WordArray::with_zero(ctx.p.buf.len());
    let mut e = WordArray::with_zero(ctx.p.buf.len());
    let mut k = WordArray::with_zero(ctx.p.buf.len());
    let mut t = WordArray::with_zero(ctx.p.buf.len());

    if (ctx.p.buf[0] & 3) == 3 {
        int_rshift(0, &ctx.p, 2, &mut b);
        let mut exp = b.clone();
        int_add(&b, &ctx.one, &mut exp);
        gfp_mod_pow(ctx, a, &exp, &mut c);
        gfp_mod_sqr(ctx, &c, &mut d);
        if int_equals(&d, a) {
            out.copy_from_slice(&c);
            return true;
        }
        false
    } else if (ctx.p.buf[0] & 7) == 5 {
        gfp_mod_add(ctx, a, a, &mut b);
        int_rshift(0, &ctx.p, 3, &mut d);
        gfp_mod_pow(ctx, &b, &d, &mut c);
        gfp_mod_sqr(ctx, &c, &mut e);
        gfp_mod_mul(ctx, &e, &b, &mut t);
        gfp_mod_sub(ctx, &t, &ctx.one, &mut e);
        gfp_mod_mul(ctx, &e, &c, &mut t);
        gfp_mod_mul(ctx, a, &t, &mut k);
        gfp_mod_sqr(ctx, &k, &mut c);
        if int_equals(&c, a) {
            out.copy_from_slice(&k);
            return true;
        }
        false
    } else {
        int_sub(&ctx.p, &ctx.one, &mut e);
        k.zero();
        let carry = int_add(&ctx.p, &ctx.one, &mut k);
        let k_src = k.clone();
        int_rshift(carry, &k_src, 1, &mut k);
        c.copy_from_slice(a);

        let mut trial = ctx.two.clone();
        loop {
            if int_cmp(&trial, &ctx.p) >= 0 {
                return false;
            }
            gfp_mod_lucas_seq(ctx, &trial, &c, &k, &mut d, &mut b);
            if int_cmp(&b, &ctx.one) > 0 && int_cmp(&b, &e) < 0 {
                return false;
            }

            let carry = if int_get_bit(&d, 0) == 1 {
                let mut tmp = d.clone();
                int_add(&d, &ctx.p, &mut tmp)
            } else {
                0
            };
            let d_src = d.clone();
            int_rshift(carry, &d_src, 1, &mut d);
            gfp_mod_sqr(ctx, &d, &mut b);
            if int_equals(&b, a) {
                out.copy_from_slice(&d);
                return true;
            }

            let mut next = trial.clone();
            int_add(&trial, &ctx.one, &mut next);
            trial = next;
        }
    }
}

#[cfg(all(test, feature = "legacy-gost3410"))]
mod tests {
    use super::*;
    use crate::primitives::gost3410::ParamsId;

    fn be_hex(w: &WordArray) -> String {
        let mut b = w.to_le_bytes();
        b.reverse();
        hex::encode(b)
    }

    #[test]
    fn gfp_mul_two_times_two() {
        let params = ParamsId::Id1.curve_params().unwrap();
        let gfp = &params.ec.gfp;
        let mut two = WordArray::with_zero(gfp.p.buf.len());
        two.buf[0] = 2;
        let mut out = WordArray::with_zero(gfp.p.buf.len());
        gfp_mod_mul(gfp, &two, &two, &mut out);
        assert_eq!(out.buf[0], 4, "2*2 mod p");
    }

    #[test]
    fn gfp_py_sqr_matches_reference() {
        let params = ParamsId::Id1.curve_params().unwrap();
        let mut sqr = WordArray::with_zero(params.ec.len);
        gfp_mod_sqr(&params.ec.gfp, &params.base.y, &mut sqr);
        assert_eq!(
            be_hex(&sqr),
            "5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b94"
        );
    }

    #[test]
    fn gfp_mod_mul_params2_a_times_one() {
        let params = ParamsId::Id2.curve_params().unwrap();
        let gfp = &params.ec.gfp;
        let mut ax = gfp.one.clone();
        gfp_mod_mul(gfp, &params.ec.a, &gfp.one, &mut ax);
        assert_eq!(ax.buf, params.ec.a.buf, "a*1 mod p must equal a");
    }

    /// Cryptonite `utest_math_gfp.c::gfp_mod_inv_test`.
    #[test]
    fn gfp_mod_inv_matches_cryptonite() {
        let p = WordArray::from_be_bytes(
            &hex::decode("8000000000000000000000000000000000000000000000000000000000000431").unwrap(),
        );
        let gfp = GfpCtx::new(&p);
        let a = WordArray::from_be_bytes(
            &hex::decode("f8811c92b8e561e8ad129635c42bbab41529b0b2b6ff41fe61834e85d7ed3139").unwrap(),
        );
        let exp = WordArray::from_le_bytes(
            &hex::decode("c8d4263cafe677ec48ca08d33b78371c90d30385c59a296a75cc59c1d0fc505c").unwrap(),
        );
        let act = gfp_mod_inv(&gfp, &a).expect("inverse");
        assert_eq!(act.buf, exp.buf);
    }
}
