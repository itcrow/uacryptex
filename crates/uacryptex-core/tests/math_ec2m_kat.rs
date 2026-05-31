//! KAT tests ported from Cryptonite `utest_math_ec2m.c`.

use uacryptex_core::math::{
    ec2m_add, ec2m_dual_mul, ec2m_is_on_curve, ec2m_mul, ec2m_point_to_affine, wa_equals,
    EcGf2mCtx, EcPoint, WordArray,
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

struct Ec2mTestData {
    ctx: EcGf2mCtx,
    p: EcPoint,
    q: EcPoint,
}

fn ec2m_test_data_init() -> Ec2mTestData {
    let f = [163, 7, 6, 3, 0];
    let a = 1;
    let b = wa_from_be_hex("00000005ff6108462a2dc8210ab403925e638a19c1455d21");
    let px = wa_from_be_hex("000000072d867f93a93ac27df9ff01affe74885c8c540420");
    let py = wa_from_be_hex("00000000224a9c3947852b97c5599d5f4ab81122adc3fd9b");
    let qx = wa_from_be_hex("000000008110f52a2ae552427bf9c2f206dbe434f424a76b");
    let qy = wa_from_be_hex("0000000054441b6b92939fdfa7cc0dce52c769701691ac84");

    Ec2mTestData {
        ctx: EcGf2mCtx::new(&f, a, &b),
        p: EcPoint::from_affine(&px, &py),
        q: EcPoint::from_affine(&qx, &qy),
    }
}

#[test]
fn ec2m_is_on_curve_test() {
    let td = ec2m_test_data_init();
    assert!(ec2m_is_on_curve(&td.ctx, &td.q.x, &td.q.y));
}

#[test]
fn ec2m_add_test() {
    let td = ec2m_test_data_init();
    let rx_exp = wa_from_be_hex("000000066f0e9a42810c21dcc3573043e7a6e10727925e7c");
    let ry_exp = wa_from_be_hex("0000000555aab1cd55c3b0d67d17bb7a9d28f548fb980783");
    let mut r = EcPoint::with_len(td.ctx.len);

    ec2m_add(&td.ctx, &td.p, &td.q.x, &td.q.y, 1, &mut r);
    ec2m_point_to_affine(&td.ctx, &mut r);

    assert!(wa_equals(&rx_exp, &r.x));
    assert!(wa_equals(&ry_exp, &r.y));
}

#[test]
fn ec2m_sub_test() {
    let td = ec2m_test_data_init();
    let rx_exp = wa_from_be_hex("00000001e67ba30e7775f373f62c8fb61836a2fecdbd8008");
    let ry_exp = wa_from_be_hex("00000002d45c4b53b8f7d11199f08aeeb7c79411a31910e1");
    let mut r = EcPoint::with_len(td.ctx.len);

    ec2m_add(&td.ctx, &td.p, &td.q.x, &td.q.y, -1, &mut r);
    ec2m_point_to_affine(&td.ctx, &mut r);

    assert!(wa_equals(&rx_exp, &r.x));
    assert!(wa_equals(&ry_exp, &r.y));
}

#[test]
fn ec2m_double_test() {
    let td = ec2m_test_data_init();
    let rx_exp = wa_from_be_hex("000000027170e40b937737391674d54681cc2e914f069eca");
    let ry_exp = wa_from_be_hex("00000005a699f5a66c0af086f01a189cb919774e476656b6");
    let mut r = EcPoint::with_len(td.ctx.len);

    ec2m_add(&td.ctx, &td.q, &td.q.x, &td.q.y, 1, &mut r);
    ec2m_point_to_affine(&td.ctx, &mut r);

    assert!(wa_equals(&rx_exp, &r.x));
    assert!(wa_equals(&ry_exp, &r.y));
}

#[test]
fn ec2m_mul_test() {
    let td = ec2m_test_data_init();
    let k = wa_from_be_hex("00000002bbbfafe0d6ff6e5dfc089ba00bf56c8f2fc5e431");
    let rx_exp = wa_from_be_hex("000000008110f52a2ae552427bf9c2f206dbe434f424a76b");
    let ry_exp = wa_from_be_hex("0000000054441b6b92939fdfa7cc0dce52c769701691ac84");
    let mut r = EcPoint::with_len(td.ctx.len);

    ec2m_mul(&td.ctx, &td.p, &k, &mut r);

    assert!(wa_equals(&rx_exp, &r.x));
    assert!(wa_equals(&ry_exp, &r.y));
}

#[test]
fn ec2m_dual_mul_test() {
    let td = ec2m_test_data_init();
    let k = wa_from_be_hex("00000002bbbfafe0d6ff6e5dfc089ba00bf56c8f2fc5e431");
    let n = wa_from_be_hex("0000000563676578f7946ff6e5dfc089b578bf56c8f335c7");
    let rx_exp = wa_from_be_hex("0000000532da0cf67aa06a4097b0e3f67babd2fab0982e2e");
    let ry_exp = wa_from_be_hex("00000001701842a617e5ac49bb48f2c11da4b851c87260c7");
    let mut r = EcPoint::with_len(td.ctx.len);

    ec2m_dual_mul(&td.ctx, &td.p, &k, &td.q, &n, &mut r);

    assert!(wa_equals(&rx_exp, &r.x));
    assert!(wa_equals(&ry_exp, &r.y));
}
