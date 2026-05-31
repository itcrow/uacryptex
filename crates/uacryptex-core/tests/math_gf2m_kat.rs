//! KAT tests ported from Cryptonite `utest_math_gf2m.c`.

use uacryptex_core::math::{
    gf2m_mod, gf2m_mod_inv, gf2m_mod_mul, gf2m_mod_sqr, gf2m_mul_opt, wa_equals, wa_len_from_bits,
    Gf2mCtx, WordArray,
};

fn pad_hex(s: &str) -> String {
    if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    }
}

fn wa_from_be_hex(s: &str) -> WordArray {
    let mut bytes = hex::decode(pad_hex(s)).expect("valid hex");
    bytes.reverse();
    WordArray::from_le_bytes(&bytes)
}

fn wa_from_le_hex(s: &str) -> WordArray {
    WordArray::from_le_bytes(&hex::decode(pad_hex(s)).expect("valid hex"))
}

#[test]
fn gf2m_mod_test() {
    let mut a = wa_from_be_hex(
        "3cb5433a00006574cdff5a65413c1f60f554678654356a123cb5433a00006574cdff5a65413c1f60",
    );
    let f = [163, 7, 6, 3, 0];
    let exp = wa_from_be_hex("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    let mut act = WordArray::with_zero(exp.buf.len());
    a.change_len(2 * wa_len_from_bits(164));

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod(&ctx, &mut a, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn gf2m_mod2_test() {
    let f = [128, 7, 2, 1, 0];
    let mut a = wa_from_be_hex("cae7c4e764cd5150ac266b80cf45b32ee9f5810a8959efc3328993d09f6cb0");
    let exp = wa_from_be_hex("049eea0ac0cd193f126654f4135516d29");
    let mut act = WordArray::with_zero(exp.buf.len());
    a.change_len(2 * wa_len_from_bits(129));

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod(&ctx, &mut a, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn gf2m_mod3_test() {
    let f = [257, 12, 0, 0, 0];
    let mut a = wa_from_be_hex(
        "1251274177579940e38308e7ffef65e24c18f26696c499d0deb33968d751c4b3be30ad40f7ec3fe8fb6907ca57d8bf892a37f21bbb54101eb897bca9939d0930d",
    );
    let mut exp =
        wa_from_be_hex("00000001e22355af08df45492efbc46d3001f18cba8bf9ed4f8da034e0566a77614e2204");
    a.change_len(2 * wa_len_from_bits(258));
    exp.change_len(wa_len_from_bits(258));
    let mut act = WordArray::with_zero(exp.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod(&ctx, &mut a, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn gf2m_mod_sqr_test() {
    let f = [163, 7, 6, 3, 0];
    let a = wa_from_be_hex("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    let exp = wa_from_be_hex("6d61f9ccb2fe18a17183961a09bc7823e7a1380f8");
    let mut act = WordArray::with_zero(exp.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod_sqr(&ctx, &a, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn gf2m_mod_mul_test() {
    let f = [163, 7, 6, 3, 0];
    let a = wa_from_be_hex("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    let exp = wa_from_be_hex("6d61f9ccb2fe18a17183961a09bc7823e7a1380f8");
    let mut act = WordArray::with_zero(exp.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod_mul(&ctx, &a, &a, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn gf2m_mod_inv_test() {
    let f = [163, 7, 6, 3, 0];
    let a = wa_from_be_hex("441e8ab3f7cb0560ae44fa1233ec5cbe15527b010");
    let exp = wa_from_be_hex("02a4549bb5d036d6e9ccd9fa79f8742ce6774b79b");
    let mut act = WordArray::with_zero(exp.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod_inv(&ctx, &a, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn gf2m_mod_mul_gmac_kalina_test() {
    let f = [128, 7, 2, 1, 0];
    let a = wa_from_le_hex("303132333435363738393A3B3C3D3E3F00");
    let b = wa_from_le_hex("C98021FE11626E6924BF8A334C526C0500");
    let exp = wa_from_le_hex("296D5135414F6526F193D10CACA0EE4900");
    let mut act = WordArray::with_zero(exp.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mod_mul(&ctx, &a, &b, &mut act);
    assert!(wa_equals(&exp, &act));
}

#[test]
fn test_multiply_poly_0() {
    let f = [163, 7, 6, 3, 0];
    let a = wa_from_be_hex("000000011dfa21231dfa21230000adfd3faa321232134231");
    let b = wa_from_be_hex("000000011dfa2123028617bf016569be1dfa212345453256");
    let expected = wa_from_le_hex(
        "f671db00ff293fee65f4b240cce719e9e3b1bae942649c0ccc206195a74c36731123191a445551010100000000000000",
    );
    let mut actual = WordArray::with_zero(expected.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mul_opt(&ctx, &a, &b, &mut actual);
    assert!(wa_equals(&expected, &actual));
}

#[test]
fn test_multiply_poly_1() {
    let f = [257, 12, 0];
    let a =
        wa_from_be_hex("000000011dfa21230000adfd454532561dfa21231dfa21230000adfd3faa321232134231");
    let b =
        wa_from_be_hex("00000001000008ed000009270000b0b20004ef60028617bf016569be1dfa212345453256");
    let mut expected = wa_from_be_hex(
        "0000000000000000000000011dfa292b6816edbc85cfd76f401642958e07ae69bbe7ab98d0e30707386a0e988ad9aa5cce712e5025edd44cba8815f0e919e7cc40b2f465ee3f29ff00db71f6",
    );
    expected.change_len(a.buf.len() * 2);
    let mut actual = WordArray::with_zero(expected.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mul_opt(&ctx, &a, &b, &mut actual);
    assert!(wa_equals(&expected, &actual));
}

#[test]
fn test_mul_poly_431() {
    let f = [431, 5, 3, 1, 0];
    let a = wa_from_be_hex(
        "1dfa21230000adfd1dfa21230000adfd3faa3212321342311dfa21230000adfd454532561dfa21231dfa21230000adfd3faa321232134231",
    );
    let b = wa_from_be_hex(
        "000008ed000009271dfa21230000adfd3faa3212321342311dfa21230000adfd454532561dfa2123028617bf016569be1dfa212345453256",
    );
    let expected = wa_from_be_hex(
        "000000e568164966c1db0ea969c3a630c3084a5449523caae86e8acff4e95e08c2cc91743064664945abf07f3a5b64a613c12b13cb157704d0e9df3595c75d83fd39a21132d4249f3c7d339b943b35c8bd168880e9cda0497e1574c7e9bab1e3e919e7cc40b2f465ee3f29ff00db71f6",
    );
    let mut actual = WordArray::with_zero(expected.buf.len());

    let ctx = Gf2mCtx::new(&f);
    gf2m_mul_opt(&ctx, &a, &b, &mut actual);
    assert!(wa_equals(&expected, &actual));
}
