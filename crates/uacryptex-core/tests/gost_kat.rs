//! GOST 28147 / GOST 34.311 integration tests (Cryptonite atest / utest vectors).

use uacryptex_core::primitives::gost28147::Gost28147;
use uacryptex_core::primitives::gost34_311::Gost34311;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// `atest_gost28147.c` key_ECB_2 / input_data_ECB_2 with **SBOX 1** (DSTU PRNG set).
///
/// Cryptonite atest uses SBOX 11 (`863e78dd2d60d13c`); SBOX 1 expected output differs.
#[test]
fn gost28147_ecb_8_bytes_sbox1() {
    let key = [
        0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67, 0x15, 0x3d, 0xde, 0x59, 0x33, 0x88, 0x42,
        0x50, 0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c, 0x1c, 0x9c, 0xa0, 0x9a, 0x56, 0xd9,
        0x68, 0xcf,
    ];
    let input = [0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56];
    let expected = hex("a95b645de3a9b547");

    let mut ctx = Gost28147::new();
    ctx.init_ecb(&key).unwrap();
    let mut out = [0u8; 8];
    ctx.ecb_encrypt(&input, &mut out).unwrap();
    assert_eq!(out.as_slice(), expected.as_slice());
}

/// `atest_gost28147.c` key_ECB_1 / input_data_ECB_1 — 24 bytes, **SBOX 1** (not SBOX 11).
#[test]
fn gost28147_ecb_24_bytes_sbox1() {
    let key = [
        0x34, 0x87, 0x24, 0xa4, 0xc1, 0xa6, 0x76, 0x67, 0x15, 0x3d, 0xde, 0x59, 0x33, 0x88, 0x42,
        0x50, 0xe3, 0x24, 0x8c, 0x65, 0x7d, 0x41, 0x3b, 0x8c, 0x1c, 0x9c, 0xa0, 0x9a, 0x56, 0xd9,
        0x68, 0xcf,
    ];
    let input = [
        0x34, 0xc0, 0x15, 0x33, 0xe3, 0x7d, 0x1c, 0x56, 0xe9, 0x43, 0x16, 0x04, 0xf5, 0x7e, 0x37,
        0xa1, 0x8f, 0x90, 0xeb, 0x03, 0x33, 0xa3, 0x33, 0x62,
    ];
    let expected = hex("a95b645de3a9b54742cb3b69e050dd684995422e67d74ed4");

    let mut ctx = Gost28147::new();
    ctx.init_ecb(&key).unwrap();
    let mut out = vec![0u8; 24];
    ctx.ecb_encrypt(&input, &mut out).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn gost28147_rejects_short_key() {
    let mut ctx = Gost28147::new();
    assert!(ctx.init_ecb(&[0u8; 16]).is_err());
}

/// `utest_gost34_311.c` test_1 — zero sync, single 32-byte message block.
#[test]
fn gost34_311_hash_test_1() {
    let sync = hex("0000000000000000000000000000000000000000000000000000000000000000");
    let data = hex("ad26f436f0b627880038727d22e02c97d081ef85260fc96718395091ce224dd7");
    let expected = hex("02d7e8a3c111788bb1b8a489c5e330288728f1c308c2cec08e09265bfa395599");

    let mut ctx = Gost34311::new(&sync).unwrap();
    ctx.update(&data).unwrap();
    let actual = ctx.final_hash().unwrap();
    assert_eq!(&actual[..], expected.as_slice());
}

/// `utest_gost34_311.c` test_2 — non-zero sync.
#[test]
fn gost34_311_hash_test_2() {
    let sync = hex("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    let data = hex("cd944dc9951b5e1eea4a9ebca4e30e4568d48f640d9b228e2df398f767b4eaab");
    let expected = hex("30667bae2a36245ce8abd0e8f84812df7ffd7dfee6289ef6d79624d709f97208");

    let mut ctx = Gost34311::new(&sync).unwrap();
    ctx.update(&data).unwrap();
    let actual = ctx.final_hash().unwrap();
    assert_eq!(&actual[..], expected.as_slice());
}

/// `utest_gost34_311.c` test_3 — 49-byte message (non-block-aligned).
#[test]
fn gost34_311_hash_test_3() {
    let sync = hex("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    let data = hex(
        "9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691d9e4abc889632959d73e0bf139cd71813ebee679e930",
    );
    let expected = hex("9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30");

    let mut ctx = Gost34311::new(&sync).unwrap();
    ctx.update(&data).unwrap();
    let actual = ctx.final_hash().unwrap();
    assert_eq!(&actual[..], expected.as_slice());
}

/// `utest_gost34_311.c` test_4 — same as test_3, split into three `update` calls.
#[test]
fn gost34_311_hash_test_4_chunked() {
    let sync = hex("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
    let data1 = hex("9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691");
    let data2 = hex("d9e4abc889632959d73e0bf139cd71813ebee679e9");
    let data3 = hex("30");
    let expected = hex("9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30");

    let mut ctx = Gost34311::new(&sync).unwrap();
    ctx.update(&data1).unwrap();
    ctx.update(&data2).unwrap();
    ctx.update(&data3).unwrap();
    let actual = ctx.final_hash().unwrap();
    assert_eq!(&actual[..], expected.as_slice());
}

#[test]
fn gost34_311_rejects_short_sync() {
    assert!(Gost34311::new(&[0u8; 16]).is_err());
}
