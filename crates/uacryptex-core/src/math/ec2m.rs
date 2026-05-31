//! Elliptic curves over GF(2^m): y² + xy = x³ + ax² + b (Cryptonite `math_ec2m_internal.c`).

use super::ec_point::EcPoint;
use super::gf2m::{
    gf2m_mod_add, gf2m_mod_add_assign, gf2m_mod_inv, gf2m_mod_mul, gf2m_mod_sqr, Gf2mCtx,
};
use super::int::{int_bit_len, int_get_bit, int_is_zero};
use super::word::WordArray;

#[derive(Clone, Debug)]
pub struct EcGf2mCtx {
    pub gf2m: Gf2mCtx,
    pub a: i32,
    pub b: WordArray,
    pub len: usize,
}

impl EcGf2mCtx {
    pub fn new(f: &[i32], a: i32, b: &WordArray) -> Self {
        assert!(f.len() == 3 || f.len() == 5);
        let gf2m = Gf2mCtx::new(f);
        let len = gf2m.len;
        let mut b_wa = b.clone();
        b_wa.change_len(len);
        Self {
            gf2m,
            a,
            b: b_wa,
            len,
        }
    }
}

fn fa_xor_into(out: &mut WordArray, other: &WordArray) {
    gf2m_mod_add_assign(out, other);
}

fn fa_mul_into(ctx: &Gf2mCtx, out: &mut WordArray, a: &WordArray, b: &WordArray) {
    gf2m_mod_mul(ctx, a, b, out);
}

fn fa_mul_acc(ctx: &Gf2mCtx, acc: &mut WordArray, other: &WordArray) {
    let left = acc.clone();
    gf2m_mod_mul(ctx, &left, other, acc);
}

fn fa_mul_left(ctx: &Gf2mCtx, out: &mut WordArray, left: &WordArray) {
    let right = out.clone();
    gf2m_mod_mul(ctx, left, &right, out);
}

fn fa_sqr_into(ctx: &Gf2mCtx, out: &mut WordArray, a: &WordArray) {
    gf2m_mod_sqr(ctx, a, out);
}

fn fa_sqr_acc(ctx: &Gf2mCtx, acc: &mut WordArray) {
    let a = acc.clone();
    gf2m_mod_sqr(ctx, &a, acc);
}

pub fn ec2m_is_on_curve(ctx: &EcGf2mCtx, px: &WordArray, py: &WordArray) -> bool {
    let mut t1 = WordArray::with_zero(ctx.len);
    let mut t2 = WordArray::with_zero(ctx.len);

    gf2m_mod_add(px, py, &mut t1);
    fa_mul_acc(&ctx.gf2m, &mut t1, py);

    fa_sqr_into(&ctx.gf2m, &mut t2, px);
    if ctx.a == 1 {
        fa_xor_into(&mut t1, &t2);
    }

    fa_mul_left(&ctx.gf2m, &mut t2, px);
    fa_xor_into(&mut t1, &t2);
    fa_xor_into(&mut t1, &ctx.b);

    int_is_zero(&t1)
}

fn ec2m_double_inner(
    ctx: &EcGf2mCtx,
    px: &WordArray,
    py: &WordArray,
    pz: &WordArray,
    r: &mut EcPoint,
) {
    if int_is_zero(px) {
        r.set_infinity();
        return;
    }

    let mut t1 = WordArray::with_zero(ctx.len);
    let mut t2 = WordArray::with_zero(ctx.len);

    fa_sqr_into(&ctx.gf2m, &mut t1, px);
    fa_sqr_into(&ctx.gf2m, &mut r.z, pz);
    fa_sqr_into(&ctx.gf2m, &mut t2, &r.z);
    fa_mul_acc(&ctx.gf2m, &mut t2, &ctx.b);
    fa_mul_acc(&ctx.gf2m, &mut r.z, &t1);

    fa_sqr_acc(&ctx.gf2m, &mut t1);
    gf2m_mod_add(&t1, &t2, &mut r.x);

    fa_sqr_into(&ctx.gf2m, &mut t1, py);
    fa_xor_into(&mut t1, &t2);
    if ctx.a == 1 {
        fa_xor_into(&mut t1, &r.z);
    }

    fa_mul_acc(&ctx.gf2m, &mut t1, &r.x);
    fa_mul_into(&ctx.gf2m, &mut r.y, &r.z, &t2);
    fa_xor_into(&mut r.y, &t1);
}

pub fn ec2m_double(ctx: &EcGf2mCtx, p: &EcPoint, r: &mut EcPoint) {
    if std::ptr::eq(p, r) {
        ec2m_double_inplace(ctx, r);
    } else {
        ec2m_double_inner(ctx, &p.x, &p.y, &p.z, r);
    }
}

fn ec2m_double_inplace(ctx: &EcGf2mCtx, r: &mut EcPoint) {
    let px = r.x.clone();
    let py = r.y.clone();
    let pz = r.z.clone();
    ec2m_double_inner(ctx, &px, &py, &pz, r);
}

pub fn ec2m_add(
    ctx: &EcGf2mCtx,
    p: &EcPoint,
    qx: &WordArray,
    qy: &WordArray,
    sign: i32,
    r: &mut EcPoint,
) {
    ec2m_add_impl(ctx, p, qx, qy, sign, r);
}

fn ec2m_add_affine_to(ctx: &EcGf2mCtx, r: &mut EcPoint, qx: &WordArray, qy: &WordArray, sign: i32) {
    let p = r.clone();
    ec2m_add_impl(ctx, &p, qx, qy, sign, r);
}

fn ec2m_add_impl(
    ctx: &EcGf2mCtx,
    p: &EcPoint,
    qx: &WordArray,
    qy: &WordArray,
    sign: i32,
    r: &mut EcPoint,
) {
    if int_is_zero(qx) && int_is_zero(qy) {
        r.copy_from(p);
        return;
    }

    if int_is_zero(&p.x) && int_is_zero(&p.y) {
        qx.copy_to(&mut r.x);
        if sign == 1 {
            qy.copy_to(&mut r.y);
        } else {
            gf2m_mod_add(qx, qy, &mut r.y);
        }
        r.z.set_one();
        return;
    }

    let mut t1 = WordArray::with_zero(ctx.len);
    let mut t2 = WordArray::with_zero(ctx.len);
    let mut t3 = WordArray::with_zero(ctx.len);

    fa_sqr_into(&ctx.gf2m, &mut t1, &p.z);
    if sign == -1 {
        gf2m_mod_add(qx, qy, &mut t2);
        fa_mul_acc(&ctx.gf2m, &mut t1, &t2);
    } else {
        fa_mul_acc(&ctx.gf2m, &mut t1, qy);
    }

    fa_xor_into(&mut t1, &p.y);
    fa_mul_into(&ctx.gf2m, &mut t2, qx, &p.z);
    fa_xor_into(&mut t2, &p.x);

    if int_is_zero(&t1) && int_is_zero(&t2) {
        ec2m_double(ctx, p, r);
        return;
    }

    if int_is_zero(&t2) {
        r.set_infinity();
        return;
    }

    fa_mul_into(&ctx.gf2m, &mut t3, &t2, &p.z);
    fa_sqr_into(&ctx.gf2m, &mut r.z, &t3);

    fa_sqr_acc(&ctx.gf2m, &mut t2);
    fa_xor_into(&mut t2, &t1);
    if ctx.a == 1 {
        fa_xor_into(&mut t2, &t3);
    }

    fa_mul_acc(&ctx.gf2m, &mut t2, &t3);
    fa_sqr_into(&ctx.gf2m, &mut r.x, &t1);
    fa_xor_into(&mut r.x, &t2);

    if sign == 1 {
        gf2m_mod_add(qx, qy, &mut t2);
    } else {
        qy.copy_to(&mut t2);
    }
    fa_sqr_into(&ctx.gf2m, &mut r.y, &r.z);
    fa_mul_acc(&ctx.gf2m, &mut r.y, &t2);

    fa_mul_into(&ctx.gf2m, &mut t2, qx, &r.z);
    fa_xor_into(&mut t2, &r.x);

    fa_mul_acc(&ctx.gf2m, &mut t1, &t3);
    fa_xor_into(&mut t1, &r.z);

    fa_mul_acc(&ctx.gf2m, &mut t1, &t2);
    fa_xor_into(&mut r.y, &t1);
}

pub fn ec2m_point_to_affine(ctx: &EcGf2mCtx, p: &mut EcPoint) {
    if int_is_zero(&p.x) && int_is_zero(&p.y) {
        p.z.set_one();
        return;
    }

    let mut t = WordArray::with_zero(ctx.len);
    gf2m_mod_inv(&ctx.gf2m, &p.z, &mut t);
    fa_mul_acc(&ctx.gf2m, &mut p.x, &t);
    fa_sqr_acc(&ctx.gf2m, &mut t);
    fa_mul_acc(&ctx.gf2m, &mut p.y, &t);
    p.z.set_one();
}

/// Field degree `m` — fixed scan length so scalar bit length is not leaked.
#[cfg(feature = "ct-scalar-mul")]
fn ec2m_scalar_bits(ctx: &EcGf2mCtx) -> usize {
    ctx.gf2m.f[0] as usize
}

#[cfg(feature = "ct-scalar-mul")]
fn wa_cmov_u32(bit: u32, when_one: &WordArray, when_zero: &WordArray, out: &mut WordArray) {
    let mask = 0u64.wrapping_sub(bit as u64);
    for i in 0..out.buf.len() {
        out.buf[i] = (when_one.buf[i] & mask) | (when_zero.buf[i] & !mask);
    }
}

/// Add affine point `Q` when `bit == 1`, else add infinity (no-op for `r`).
#[cfg(feature = "ct-scalar-mul")]
fn ec2m_cond_add_affine(
    ctx: &EcGf2mCtx,
    r: &mut EcPoint,
    qx: &WordArray,
    qy: &WordArray,
    sign: i32,
    bit: u32,
) {
    let zero = WordArray::with_zero(ctx.len);
    let mut sel_x = WordArray::with_zero(ctx.len);
    let mut sel_y = WordArray::with_zero(ctx.len);
    wa_cmov_u32(bit, qx, &zero, &mut sel_x);
    wa_cmov_u32(bit, qy, &zero, &mut sel_y);
    ec2m_add_affine_to(ctx, r, &sel_x, &sel_y, sign);
}

#[cfg(not(feature = "ct-scalar-mul"))]
fn ec2m_mul_legacy(ctx: &EcGf2mCtx, p: &EcPoint, k: &WordArray, r: &mut EcPoint) {
    let p_work = p.clone();
    r.set_infinity();

    let len = int_bit_len(k);
    for i in (0..len).rev() {
        ec2m_double_inplace(ctx, r);
        if int_get_bit(k, i) != 0 {
            ec2m_add_affine_to(ctx, r, &p_work.x, &p_work.y, 1);
        }
    }

    ec2m_point_to_affine(ctx, r);
}

/// Fixed-length double-and-add without secret-dependent branches (conditional add via cmov).
#[cfg(feature = "ct-scalar-mul")]
fn ec2m_mul_ct(ctx: &EcGf2mCtx, p: &EcPoint, k: &WordArray, r: &mut EcPoint) {
    let p_work = p.clone();
    r.set_infinity();

    let bits = ec2m_scalar_bits(ctx);
    for i in (0..bits).rev() {
        ec2m_double_inplace(ctx, r);
        ec2m_cond_add_affine(ctx, r, &p_work.x, &p_work.y, 1, int_get_bit(k, i));
    }

    ec2m_point_to_affine(ctx, r);
}

pub fn ec2m_mul(ctx: &EcGf2mCtx, p: &EcPoint, k: &WordArray, r: &mut EcPoint) {
    #[cfg(feature = "ct-scalar-mul")]
    ec2m_mul_ct(ctx, p, k, r);
    #[cfg(not(feature = "ct-scalar-mul"))]
    ec2m_mul_legacy(ctx, p, k, r);
}

#[cfg(not(feature = "ct-scalar-mul"))]
fn ec2m_dual_mul_legacy(
    ctx: &EcGf2mCtx,
    p: &EcPoint,
    m: &WordArray,
    q: &EcPoint,
    n: &WordArray,
    r: &mut EcPoint,
) {
    r.set_infinity();

    let mlen = int_bit_len(m);
    let nlen = int_bit_len(n);
    let len = mlen.max(nlen);
    for i in (0..len).rev() {
        ec2m_double_inplace(ctx, r);
        if int_get_bit(m, i) != 0 {
            ec2m_add_affine_to(ctx, r, &p.x, &p.y, 1);
        }
        if int_get_bit(n, i) != 0 {
            ec2m_add_affine_to(ctx, r, &q.x, &q.y, 1);
        }
    }

    ec2m_point_to_affine(ctx, r);
}

#[cfg(feature = "ct-scalar-mul")]
fn ec2m_dual_mul_ct(
    ctx: &EcGf2mCtx,
    p: &EcPoint,
    m: &WordArray,
    q: &EcPoint,
    n: &WordArray,
    r: &mut EcPoint,
) {
    r.set_infinity();

    let bits = ec2m_scalar_bits(ctx);
    for i in (0..bits).rev() {
        ec2m_double_inplace(ctx, r);
        ec2m_cond_add_affine(ctx, r, &p.x, &p.y, 1, int_get_bit(m, i));
        ec2m_cond_add_affine(ctx, r, &q.x, &q.y, 1, int_get_bit(n, i));
    }

    ec2m_point_to_affine(ctx, r);
}

pub fn ec2m_dual_mul(
    ctx: &EcGf2mCtx,
    p: &EcPoint,
    m: &WordArray,
    q: &EcPoint,
    n: &WordArray,
    r: &mut EcPoint,
) {
    #[cfg(feature = "ct-scalar-mul")]
    ec2m_dual_mul_ct(ctx, p, m, q, n, r);
    #[cfg(not(feature = "ct-scalar-mul"))]
    ec2m_dual_mul_legacy(ctx, p, m, q, n, r);
}
