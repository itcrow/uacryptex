//! Elliptic curves over GF(p) (Cryptonite `math_ecp_internal.c` subset).

use super::ec_point::EcPoint;
use super::gfp::{gfp_mod_add, gfp_mod_inv, gfp_mod_mul, gfp_mod_sqr, gfp_mod_sub, GfpCtx};
use super::int::{int_bit_len, int_equals, int_get_bit, int_is_zero};
use super::int_arith::int_sub;
use super::word::WordArray;

#[derive(Clone, Debug)]
pub struct EcGfpCtx {
    pub gfp: GfpCtx,
    pub a: WordArray,
    a_equal_minus_3: bool,
    pub b: WordArray,
    pub len: usize,
}

impl EcGfpCtx {
    pub fn new(p: &WordArray, a: &WordArray, b: &WordArray) -> Self {
        assert_eq!(p.buf.len(), a.buf.len());
        assert_eq!(p.buf.len(), b.buf.len());
        let gfp = GfpCtx::new(p);
        let len = p.buf.len();
        let mut a_minus = WordArray::with_zero(len);
        int_sub(p, a, &mut a_minus);
        let a_equal_minus_3 = int_bit_len(&a_minus) == 2 && a_minus.buf[0] == 3;
        Self {
            gfp,
            a: a.clone(),
            a_equal_minus_3,
            b: b.clone(),
            len,
        }
    }
}

fn gfp_add(ctx: &GfpCtx, a: &WordArray, b: &WordArray) -> WordArray {
    let mut out = WordArray::with_zero(a.buf.len());
    gfp_mod_add(ctx, a, b, &mut out);
    out
}

fn gfp_sub(ctx: &GfpCtx, a: &WordArray, b: &WordArray) -> WordArray {
    let mut out = WordArray::with_zero(a.buf.len());
    gfp_mod_sub(ctx, a, b, &mut out);
    out
}

fn gfp_mul(ctx: &GfpCtx, a: &WordArray, b: &WordArray) -> WordArray {
    let mut out = WordArray::with_zero(a.buf.len());
    gfp_mod_mul(ctx, a, b, &mut out);
    out
}

fn gfp_sqr(ctx: &GfpCtx, a: &WordArray) -> WordArray {
    let mut out = WordArray::with_zero(a.buf.len());
    gfp_mod_sqr(ctx, a, &mut out);
    out
}

pub fn ecp_is_on_curve(ctx: &EcGfpCtx, px: &WordArray, py: &WordArray) -> bool {
    let mut lhs = px.clone();
    let mut t = gfp_sqr(&ctx.gfp, &lhs);
    t = gfp_add(&ctx.gfp, &t, &ctx.a);
    t = gfp_mul(&ctx.gfp, &t, &lhs);
    lhs = gfp_add(&ctx.gfp, &t, &ctx.b);
    let rhs = gfp_sqr(&ctx.gfp, py);
    int_equals(&lhs, &rhs)
}

fn ecp_point_zero(ctx: &EcGfpCtx, p: &mut EcPoint) {
    p.x.zero();
    p.y.zero();
    p.z.copy_from(&ctx.gfp.one);
}

fn ecp_double_point(ctx: &EcGfpCtx, p: &EcPoint, r: &mut EcPoint) {
    if int_is_zero(&p.y) {
        ecp_point_zero(ctx, r);
        return;
    }

    let mut t1 = gfp_sqr(&ctx.gfp, &p.y);
    let mut t2 = gfp_mul(&ctx.gfp, &p.x, &t1);
    t2 = gfp_add(&ctx.gfp, &t2, &t2);
    t2 = gfp_add(&ctx.gfp, &t2, &t2);

    let t3 = if ctx.a_equal_minus_3 {
        let t4_z = gfp_sqr(&ctx.gfp, &p.z);
        let t_sum = gfp_add(&ctx.gfp, &p.x, &t4_z);
        let t_diff = gfp_sub(&ctx.gfp, &p.x, &t4_z);
        let mut t3 = gfp_mul(&ctx.gfp, &t_sum, &t_diff);
        let t4 = gfp_add(&ctx.gfp, &t3, &t3);
        t3 = gfp_add(&ctx.gfp, &t3, &t4);
        t3
    } else {
        let mut t3 = gfp_sqr(&ctx.gfp, &p.x);
        let t4 = gfp_add(&ctx.gfp, &t3, &t3);
        t3 = gfp_add(&ctx.gfp, &t3, &t4);
        let mut t4 = gfp_sqr(&ctx.gfp, &p.z);
        t4 = gfp_sqr(&ctx.gfp, &t4);
        t4 = gfp_mul(&ctx.gfp, &t4, &ctx.a);
        gfp_add(&ctx.gfp, &t3, &t4)
    };

    r.x = gfp_sqr(&ctx.gfp, &t3);
    r.x = gfp_sub(&ctx.gfp, &r.x, &t2);
    r.x = gfp_sub(&ctx.gfp, &r.x, &t2);

    r.z = gfp_mul(&ctx.gfp, &p.y, &p.z);
    r.z = gfp_add(&ctx.gfp, &r.z, &r.z);

    t1 = gfp_add(&ctx.gfp, &t1, &t1);
    t1 = gfp_sqr(&ctx.gfp, &t1);
    let ry_part = gfp_add(&ctx.gfp, &t1, &t1);

    let t1 = gfp_sub(&ctx.gfp, &t2, &r.x);
    let t1 = gfp_mul(&ctx.gfp, &t3, &t1);
    r.y = gfp_sub(&ctx.gfp, &t1, &ry_part);
}

fn ecp_add_point(
    ctx: &EcGfpCtx,
    p: &EcPoint,
    qx: &WordArray,
    qy: &WordArray,
    sign: i32,
    r: &mut EcPoint,
) {
    let p = p.clone();

    if int_is_zero(&p.x) && int_is_zero(&p.y) {
        qx.copy_to(&mut r.x);
        qy.copy_to(&mut r.y);
        r.z.copy_from(&ctx.gfp.one);
        if sign == -1 {
            r.y = gfp_sub(&ctx.gfp, &ctx.gfp.p, &r.y);
        }
        return;
    }

    if int_is_zero(qx) && int_is_zero(qy) {
        r.copy_from(&p);
        return;
    }

    let mut t2 = gfp_sqr(&ctx.gfp, &p.z);
    let mut t1 = gfp_mul(&ctx.gfp, qx, &t2);
    t1 = gfp_sub(&ctx.gfp, &t1, &p.x);

    t2 = gfp_mul(&ctx.gfp, &t2, &p.z);
    t2 = gfp_mul(&ctx.gfp, qy, &t2);
    if sign == -1 {
        t2 = gfp_sub(&ctx.gfp, &ctx.gfp.p, &t2);
    }

    let t3 = gfp_add(&ctx.gfp, &t2, &p.y);
    if int_is_zero(&t1) && int_is_zero(&t3) {
        ecp_point_zero(ctx, r);
        return;
    }

    t2 = gfp_sub(&ctx.gfp, &t2, &p.y);
    if int_is_zero(&t1) && int_is_zero(&t2) {
        ecp_double_point(ctx, &p, r);
        return;
    }

    let t3_sqr = gfp_sqr(&ctx.gfp, &t1);
    let t4 = gfp_mul(&ctx.gfp, &t1, &t3_sqr);
    let t3 = gfp_mul(&ctx.gfp, &p.x, &t3_sqr);
    r.x = gfp_sqr(&ctx.gfp, &t2);
    r.x = gfp_sub(&ctx.gfp, &r.x, &t4);

    r.y = gfp_mul(&ctx.gfp, &t4, &p.y);
    let t4 = gfp_add(&ctx.gfp, &t3, &t3);
    r.x = gfp_sub(&ctx.gfp, &r.x, &t4);

    let t4 = gfp_sub(&ctx.gfp, &t3, &r.x);
    let t4 = gfp_mul(&ctx.gfp, &t2, &t4);
    r.y = gfp_sub(&ctx.gfp, &t4, &r.y);

    r.z = gfp_mul(&ctx.gfp, &p.z, &t1);
}

pub fn ecp_point_to_affine(ctx: &EcGfpCtx, p: &mut EcPoint) {
    if int_is_zero(&p.x) && int_is_zero(&p.y) {
        p.z.copy_from(&ctx.gfp.one);
        return;
    }

    let mut t = gfp_mod_inv(&ctx.gfp, &p.z).expect("z invertible for non-infinity point");
    p.y = gfp_mul(&ctx.gfp, &p.y, &t);
    t = gfp_sqr(&ctx.gfp, &t);
    p.x = gfp_mul(&ctx.gfp, &p.x, &t);
    p.y = gfp_mul(&ctx.gfp, &p.y, &t);
    p.z.copy_from(&ctx.gfp.one);
}

fn ecp_double_inplace(ctx: &EcGfpCtx, r: &mut EcPoint) {
    let p = r.clone();
    ecp_double_point(ctx, &p, r);
}

fn ecp_add_affine_inplace(
    ctx: &EcGfpCtx,
    r: &mut EcPoint,
    qx: &WordArray,
    qy: &WordArray,
    sign: i32,
) {
    let p = r.clone();
    ecp_add_point(ctx, &p, qx, qy, sign, r);
}

pub fn ecp_mul(ctx: &EcGfpCtx, p: &EcPoint, k: &WordArray, r: &mut EcPoint) {
    let p_work = p.clone();
    ecp_point_zero(ctx, r);
    let len = int_bit_len(k);
    for i in (0..len).rev() {
        ecp_double_inplace(ctx, r);
        if int_get_bit(k, i) != 0 {
            ecp_add_affine_inplace(ctx, r, &p_work.x, &p_work.y, 1);
        }
    }
    ecp_point_to_affine(ctx, r);
}

#[cfg(all(test, feature = "legacy-gost3410"))]
fn wa_from_be_hex(s: &str) -> WordArray {
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    WordArray::from_be_bytes(&hex::decode(s).expect("hex"))
}

#[cfg(all(test, feature = "legacy-gost3410"))]
fn ecp_test_ctx() -> (EcGfpCtx, EcPoint, EcPoint) {
    let p = wa_from_be_hex("8000000000000000000000000000000000000000000000000000000000000431");
    let a = wa_from_be_hex("0000000000000000000000000000000000000000000000000000000000000007");
    let b = wa_from_be_hex("5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e");
    let px = wa_from_be_hex("0000000000000000000000000000000000000000000000000000000000000002");
    let py = wa_from_be_hex("08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8");
    let qx = wa_from_be_hex("5300ed9dfa5efed73f12991168761ba52faa68ad4ada5fb161af6c6407b59bba");
    let qy = wa_from_be_hex("2a01f2cbd4dcea9d4cee378f6c51818a2fe4e866252ea8a78bb5909344659234");
    let ctx = EcGfpCtx::new(&p, &a, &b);
    let p_pt = EcPoint::from_affine(&px, &py);
    let q_pt = EcPoint::from_affine(&qx, &qy);
    (ctx, p_pt, q_pt)
}

pub fn ecp_dual_mul(
    ctx: &EcGfpCtx,
    p: &EcPoint,
    k: &WordArray,
    q: &EcPoint,
    n: &WordArray,
    r: &mut EcPoint,
) {
    let p_work = p.clone();
    let q_work = q.clone();
    ecp_point_zero(ctx, r);
    let mlen = int_bit_len(k);
    let nlen = int_bit_len(n);
    let len = mlen.max(nlen);
    for i in (0..len).rev() {
        ecp_double_inplace(ctx, r);
        ecp_point_to_affine(ctx, r);
        if int_get_bit(k, i) != 0 {
            ecp_add_affine_inplace(ctx, r, &p_work.x, &p_work.y, 1);
        }
        if int_get_bit(n, i) != 0 {
            ecp_add_affine_inplace(ctx, r, &q_work.x, &q_work.y, 1);
        }
    }
    ecp_point_to_affine(ctx, r);
}

#[cfg(all(test, feature = "legacy-gost3410"))]
mod tests {
    use super::*;

    /// Cryptonite `utest_math_ecp.c::ecp_point_to_affine_test`.
    #[test]
    fn ecp_point_to_affine_matches_cryptonite() {
        let (ctx, p_exp, _) = ecp_test_ctx();
        let mut q = EcPoint {
            x: wa_from_be_hex("677ac4eedbf00837934048f9f84d8acf7bb5b0f68be8c1147e639346808b0153"),
            y: wa_from_be_hex("0a9dccc14821852a0b41e0fd41839c61a0a11ea6818e2799ef160e2822ae657d"),
            z: wa_from_be_hex("7b724559ef3beaf3bc6f86c4ab2c8254699126cb44f697373319fbc832cdedc6"),
        };
        ecp_point_to_affine(&ctx, &mut q);
        assert_eq!(q.x.buf, p_exp.x.buf);
        assert_eq!(q.y.buf, p_exp.y.buf);
        assert_eq!(q.z.buf, p_exp.z.buf);
    }

    /// Cryptonite `utest_math_ecp.c::ecp_add_test`.
    #[test]
    fn ecp_add_matches_cryptonite() {
        let (ctx, p, q) = ecp_test_ctx();
        let mut r = EcPoint::with_len(ctx.len);
        ecp_add_point(&ctx, &p, &q.x, &q.y, 1, &mut r);
        ecp_point_to_affine(&ctx, &mut r);
        assert_eq!(
            r.x.buf,
            wa_from_be_hex("44ade03bb9757ae320fd6eaa759fe2a373e4c9a14b496763e1ba100a2783a1b6").buf
        );
        assert_eq!(
            r.y.buf,
            wa_from_be_hex("5b17111aa2fcdce4dc894fb481fad5498017f47f5e0fc629145149d9d22c86a5").buf
        );
    }

    /// Cryptonite `utest_math_ecp.c::ecp_double_test` (Q + Q).
    #[test]
    fn ecp_double_matches_cryptonite() {
        let (ctx, _, q) = ecp_test_ctx();
        let mut r = EcPoint::with_len(ctx.len);
        ecp_add_point(&ctx, &q, &q.x, &q.y, 1, &mut r);
        ecp_point_to_affine(&ctx, &mut r);
        assert_eq!(
            r.x.buf,
            wa_from_be_hex("0d750f5c72c129367c8af0e2490a495dbd512efdab4da0cb3bcd357d2fa4d3de").buf
        );
        assert_eq!(
            r.y.buf,
            wa_from_be_hex("1bd1a947a3365692f024ee1f9bd5052d597c11e7edc62ac0624f47d9cc386b32").buf
        );
    }

    /// Base point doubling (2 * P).
    #[test]
    fn ecp_double_base_matches_reference() {
        let (ctx, p, _) = ecp_test_ctx();
        let mut r = EcPoint::with_len(ctx.len);
        ecp_add_point(&ctx, &p, &p.x, &p.y, 1, &mut r);
        ecp_point_to_affine(&ctx, &mut r);
        assert_eq!(
            r.x.buf,
            wa_from_be_hex("6fe27a3e0aced6e9db874c05a9c7395be62e32982ed2a1bc5c92cfc195fe9768").buf
        );
        assert_eq!(
            r.y.buf,
            wa_from_be_hex("2194a807f376b7587d1c37cfc1327eae83f6cbbee4afc1daa94b6fcc19c9a1ff").buf
        );
    }

    /// Cryptonite `utest_math_ecp.c::ecp_mul_test`.
    #[test]
    fn ecp_mul_matches_cryptonite() {
        let (ctx, p, _) = ecp_test_ctx();
        let k = wa_from_be_hex("53b7f9884a337c975998b0b2bbbfafe0d6ff6e663376f920544306e9dae23b77");
        let mut r = EcPoint::with_len(ctx.len);
        ecp_mul(&ctx, &p, &k, &mut r);
        assert_eq!(
            r.x.buf,
            wa_from_be_hex("3fdbdc35ce5129937c4d44d4cda0bcc6372fb2075dac51310ff99d098126aadb").buf
        );
        assert_eq!(
            r.y.buf,
            wa_from_be_hex("74361b924f20efd8d4eaaf58365d6220940bf8c858b6db81893716895545d715").buf
        );
    }
}
