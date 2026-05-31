//! KAT for GOST 34.10-94 public key compress/decompress.
//!
//! Params ID 2: Cryptonite `utest_gost3410.c::utest_compress_decompress_pubkey` (p ≡ 3 mod 4).
//! Params ID 1: roundtrip from `utest_get_pubkey` vectors (p ≡ 1 mod 8, Lucas sqrt).

use uacryptex_core::primitives::gost3410::{
    compress_pubkey, decompress_pubkey, get_pubkey, ParamsId,
};

fn hex_be(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    hex::decode(s).expect("hex")
}

fn compress_decompress_roundtrip(
    params_id: ParamsId,
    d_be: &str,
    exp_qx_be: &str,
    exp_qy_be: &str,
) {
    let params = params_id.curve_params().unwrap();
    let d = hex_be(d_be);
    let exp_qx = hex_be(exp_qx_be);
    let exp_qy = hex_be(exp_qy_be);

    let (qx, qy) = get_pubkey(&params, &d).unwrap();
    assert_eq!(qx, exp_qx);
    assert_eq!(qy, exp_qy);

    let (compressed, last_bit) = compress_pubkey(&params, &qx, &qy).unwrap();
    assert_eq!(compressed, qx);
    assert_eq!(last_bit, (qy[0] & 1) as u8);

    let (dqx, dqy) = decompress_pubkey(&params, &compressed, last_bit).unwrap();
    assert_eq!(dqx, exp_qx);
    assert_eq!(dqy, exp_qy);
}

/// `utest_compress_decompress_pubkey` — params set 2.
#[test]
fn gost3410_compress_decompress_params2() {
    compress_decompress_roundtrip(
        ParamsId::Id2,
        "066E675EB37AE3C5736CE765824D6A8B6CAA5A489F4EEA270767A54D62C971",
        "BBB78FA531C8382A95CF10B8A0ED5EC976E133469390C4EA143138822CF634FD",
        "778CC3183E38EB00BBC65158893C4106079DF770E298A366F627B3217AA233B4",
    );
}

/// Roundtrip for params set 1 — exercises `gfp_mod_sqrt` Lucas branch (p ≡ 1 mod 8).
#[test]
fn gost3410_compress_decompress_params1() {
    compress_decompress_roundtrip(
        ParamsId::Id1,
        "7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28",
        "0BD86FE5D8DB89668F789B4E1DBA8585C5508B45EC5B59D8906DDB70E2492B7F",
        "DA77FF871A10FBDF2766D293C5D164AFBB3C7B973A41C885D11D70D689B4F126",
    );
}
