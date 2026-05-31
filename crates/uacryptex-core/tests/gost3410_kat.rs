//! KAT tests ported from Cryptonite `utest_gost3410.c`.

use uacryptex_core::primitives::gost3410::{get_pubkey, verify, ParamsId};

fn hex_be(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    hex::decode(s).expect("hex")
}

#[test]
fn gost3410_get_pubkey_params1() {
    let params = ParamsId::Id1.curve_params().unwrap();
    let d = hex_be("7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28");
    let exp_qx = hex_be("0BD86FE5D8DB89668F789B4E1DBA8585C5508B45EC5B59D8906DDB70E2492B7F");
    let exp_qy = hex_be("DA77FF871A10FBDF2766D293C5D164AFBB3C7B973A41C885D11D70D689B4F126");

    let (qx, qy) = get_pubkey(&params, &d).unwrap();
    assert_eq!(qx, exp_qx);
    assert_eq!(qy, exp_qy);
}

#[test]
fn gost3410_sign_verify_params1() {
    use uacryptex_core::primitives::dstu4145::SliceRandom;
    use uacryptex_core::primitives::gost3410::{sign, ParamsId};

    let params = ParamsId::Id1.curve_params().unwrap();
    let d = hex_be("7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28");
    let hash = hex_be("2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5");
    let mut rng = SliceRandom::new(vec![0x11; 64]);
    let sig = sign(&params, &d, &hash, &mut rng).unwrap();
    let (qx, qy) = get_pubkey(&params, &d).unwrap();
    let mut qx_be = qx;
    qx_be.reverse();
    let mut qy_be = qy;
    qy_be.reverse();
    verify(&params, &qx_be, &qy_be, &hash, &sig.r, &sig.s).unwrap();
}

#[test]
fn gost3410_verify_params1() {
    let params = ParamsId::Id1.curve_params().unwrap();
    let hash = hex_be("2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5");
    let qx = hex_be("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B");
    let qy = hex_be("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA");
    let r = hex_be("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493");
    let s = hex_be("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40");

    verify(&params, &qx, &qy, &hash, &r, &s).unwrap();
}

#[test]
fn gost3410_get_pubkey_params2() {
    let params = ParamsId::Id2.curve_params().unwrap();
    let d = hex_be("066E675EB37AE3C5736CE765824D6A8B6CAA5A489F4EEA270767A54D62C971");
    let exp_qx = hex_be("BBB78FA531C8382A95CF10B8A0ED5EC976E133469390C4EA143138822CF634FD");
    let exp_qy = hex_be("778CC3183E38EB00BBC65158893C4106079DF770E298A366F627B3217AA233B4");

    let (qx, qy) = get_pubkey(&params, &d).unwrap();
    assert_eq!(qx, exp_qx);
    assert_eq!(qy, exp_qy);
}

#[test]
fn gost3410_sign_verify_params2() {
    use uacryptex_core::primitives::dstu4145::SliceRandom;
    use uacryptex_core::primitives::gost3410::sign;

    let params = ParamsId::Id2.curve_params().unwrap();
    let d = hex_be("066E675EB37AE3C5736CE765824D6A8B6CAA5A489F4EEA270767A54D62C971");
    let hash = hex_be("719BD04194B68A33CAE7F9500ADABA9268719266D9951D681CF84924AAAF975F");
    let mut rng = SliceRandom::new(vec![0x09; 40]);
    let sig = sign(&params, &d, &hash, &mut rng).unwrap();
    let (qx, qy) = get_pubkey(&params, &d).unwrap();
    let mut qx_be = qx;
    qx_be.reverse();
    let mut qy_be = qy;
    qy_be.reverse();
    verify(&params, &qx_be, &qy_be, &hash, &sig.r, &sig.s).unwrap();
}
