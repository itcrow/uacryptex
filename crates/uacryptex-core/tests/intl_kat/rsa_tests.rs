//! RSA PKCS#1 v1.5 and OAEP tests from cryptonite `utest_rsa.c`.

use uacryptex_core::primitives::intl::{
    rsa_oaep_decrypt, rsa_oaep_encrypt, rsa_oaep_modulus_valid, rsa_pkcs1_v15_sign_sha1,
    rsa_pkcs1_v15_sign_sha256, rsa_pkcs1_v15_sign_sha384, rsa_pkcs1_v15_sign_sha512,
    rsa_pkcs1_v15_verify_sha1, rsa_pkcs1_v15_verify_sha256, rsa_pkcs1_v15_verify_sha384,
    rsa_pkcs1_v15_verify_sha512, RsaOaepHash,
};

/// Cryptonite `ba_alloc_from_be_hex_string` (reversed byte order in `ByteArray`).
fn decode_cryptonite_be_hex(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let mut v = hex::decode(&s).expect("valid hex");
    v.reverse();
    v
}

fn decode_le_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// `utest_rsa.c` `test_rsa_sign` — fixed SHA-1 signature.
#[test]
fn rsa_sign_sha1_fixed() {
    let n = decode_cryptonite_be_hex(
        "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2b\
         c59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b\
         2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15\
         397183fbf1f0353c9fc991",
    );
    let d = decode_cryptonite_be_hex(
        "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37\
         a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c01\
         89d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010a\
         c51a7799b1ff8483644a3d425",
    );
    let e = decode_cryptonite_be_hex(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000\
         000000000000000000000000000000000000000000000000000000000000000000000000000000\
         000000000000000000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000010001",
    );
    let hash = decode_le_hex("c8919f9087282f2059f112b55faae3c6462f4469");
    let sign_exp = decode_cryptonite_be_hex(
        "28928e19eb86f9c00070a59edf6bf8433a45df495cd1c73613c2129840f48c4a\
         2c24f11df79bc5c0782bcedde97dbbb2acc6e512d19f085027cd575038453d04\
         905413e947e6e1dddbeb3535cdb3d8971fe0200506941056f21243503c83eadd\
         e053ed866c0e0250beddd927a08212aa8ac0efd61631ef89d8d049efb36bb35f",
    );

    let sign = rsa_pkcs1_v15_sign_sha1(&n, &e, &d, &hash).expect("sign");
    assert_eq!(sign, sign_exp);
    rsa_pkcs1_v15_verify_sha1(&n, &e, &hash, &sign).expect("verify");
}

/// `test_rsa_sign2` — SHA-256 sign + verify (LE modulus/exponent).
#[test]
fn rsa_sign_sha256_roundtrip() {
    let hash = decode_le_hex("6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898");
    let e = decode_le_hex("03");
    let n = decode_le_hex(
        "ab5eec8429d4a421c4a9dc7d675c844c8a82e2e5dc213801e14730c6bc34c33d2ac4896608a7e38f6767392caff96b3cf24a86d5748f9c379ee247900eb0a831",
    );
    let d = decode_le_hex(
        "8b6b48c9abc99b8f304ec0eb92136be53228968e0e2b260487c94ffe6d4537631bd85b44b0c4970a459a7b1dcafb47284c87598ef8b4bdcfbe4185b509201b21",
    );

    let sign = rsa_pkcs1_v15_sign_sha256(&n, &e, &d, &hash).expect("sign");
    rsa_pkcs1_v15_verify_sha256(&n, &e, &hash, &sign).expect("verify");
}

/// `test_rsa_sign3` — SHA-384.
#[test]
fn rsa_sign_sha384_roundtrip() {
    let hash = decode_le_hex(
        "6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let n = decode_cryptonite_be_hex(
        "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991",
    );
    let d = decode_cryptonite_be_hex(
        "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425",
    );
    let e = decode_cryptonite_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
    );

    let sign = rsa_pkcs1_v15_sign_sha384(&n, &e, &d, &hash).expect("sign");
    rsa_pkcs1_v15_verify_sha384(&n, &e, &hash, &sign).expect("verify");
}

/// `test_rsa_sign4` — SHA-512.
#[test]
fn rsa_sign_sha512_roundtrip() {
    let hash = decode_le_hex(
        "6cd6ad3edf451bcb6e515af99b549fa5ebed13c4619f1e65239298e39b5e7898aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let n = decode_cryptonite_be_hex(
        "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991",
    );
    let d = decode_cryptonite_be_hex(
        "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425",
    );
    let e = decode_cryptonite_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
    );

    let sign = rsa_pkcs1_v15_sign_sha512(&n, &e, &d, &hash).expect("sign");
    rsa_pkcs1_v15_verify_sha512(&n, &e, &hash, &sign).expect("verify");
}

fn oaep_seed(hash: RsaOaepHash) -> Vec<u8> {
    vec![0x42; hash.hlen()]
}

fn small_rsa_le_key() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let n = decode_le_hex(
        "5f7e4cc092b7d3a830d2000290d8bf175bdddeee82b03ea8d392fcf291602f2c95be8ebe6fc30ccb765facf86cfc5d9dd887aef7ae04e9c5c5855c5fd3a50434",
    );
    let d = decode_le_hex(
        "6bccbaa912210494fd1a44cec5136f046c0c0a045bac895a3cbd2bccec5e647d0d7fb429f52cb3dcf9941dfb9dfd93133b051fa574589b2ed903933fe2c3ad22",
    );
    let e = decode_le_hex("03");
    (n, e, d)
}

fn large_rsa_be_key() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let n = decode_cryptonite_be_hex(
        "c8a2069182394a2ab7c3f4190c15589c56a2d4bc42dca675b34cc950e24663048441e8aa593b2bc59e198b8c257e882120c62336e5cc745012c7ffb063eebe53f3c6504cba6cfe51baa3b6d1074b2f398171f4b1982f4d65caf882ea4d56f32ab57d0c44e6ad4e9cf57a4339eb6962406e350c1b15397183fbf1f0353c9fc991",
    );
    let d = decode_cryptonite_be_hex(
        "5dfcb111072d29565ba1db3ec48f57645d9d8804ed598a4d470268a89067a2c921dff24ba2e37a3ce834555000dc868ee6588b7493303528b1b3a94f0b71730cf1e86fca5aeedc3afa16f65c0189d810ddcd81049ebbd0391868c50edec958b3a2aaeff6a575897e2f20a3ab5455c1bfa55010ac51a7799b1ff8483644a3d425",
    );
    let e = decode_cryptonite_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001",
    );
    (n, e, d)
}

fn oaep_roundtrip(hash: RsaOaepHash, n: &[u8], e: &[u8], d: &[u8], label: Option<&[u8]>) {
    let plain = b"abcdefgh";
    let seed = oaep_seed(hash);
    let cipher = rsa_oaep_encrypt(hash, n, e, plain, label, &seed).expect("oaep encrypt");
    let dec = rsa_oaep_decrypt(hash, n, d, &cipher, label).expect("oaep decrypt");
    assert_eq!(dec, plain);
}

/// `test_rsa_oaep_SHA1`.
#[test]
fn rsa_oaep_sha1_roundtrip() {
    let (n, e, d) = small_rsa_le_key();
    oaep_roundtrip(RsaOaepHash::Sha1, &n, &e, &d, None);
}

/// `test_rsa_oaep_with_not_null_label`.
#[test]
fn rsa_oaep_sha1_with_label() {
    let (n, e, d) = small_rsa_le_key();
    let label = decode_le_hex("aa");
    oaep_roundtrip(RsaOaepHash::Sha1, &n, &e, &d, Some(&label));
}

/// `test_rsa_init_encrypt_oaep_SHA256` — 64-byte modulus too small for SHA-256 OAEP.
#[test]
fn rsa_oaep_sha256_rejects_small_modulus() {
    let (n, e, _) = small_rsa_le_key();
    assert!(!rsa_oaep_modulus_valid(RsaOaepHash::Sha256, &n));
    let err = rsa_oaep_encrypt(
        RsaOaepHash::Sha256,
        &n,
        &e,
        b"abcdefgh",
        None,
        &oaep_seed(RsaOaepHash::Sha256),
    )
    .unwrap_err();
    assert!(matches!(err, uacryptex_core::error::Error::InvalidParam(_)));
}

/// `test_rsa_oaep_SHA256`.
#[test]
fn rsa_oaep_sha256_roundtrip() {
    let (n, e, d) = large_rsa_be_key();
    oaep_roundtrip(RsaOaepHash::Sha256, &n, &e, &d, None);
}

/// `test_rsa_oaep_SHA384`.
#[test]
fn rsa_oaep_sha384_roundtrip() {
    let (n, e, d) = large_rsa_be_key();
    oaep_roundtrip(RsaOaepHash::Sha384, &n, &e, &d, None);
}

/// `test_rsa_oaep_SHA512`.
#[test]
fn rsa_oaep_sha512_roundtrip() {
    let n = decode_le_hex(
        "576ff776be856ff7e053175b1beea7919d01f948058115c3d89fbf7d6994fb528cdd67991f4d05c66381238623ddfaf88fb2adc91acf5e2242fbc2faff9daaacea3a0bdf6931cce8ec91a521da439c114fcc01d1de313e9a192d84afff465c68bb0c1d0e34bdb9a68e8b1125b33d8e4e1222f3991ebcc6dbfb6c5caca4af60907b6500715d9f009257abe1cd6a4976aa3061b66c05611c06033437ab6e8c13d9da323b8bc361a333d392b96ba19ba3412e43017ca422d3b5c1756d27f8bd8ee94d923fb2bf4b0f32ec140985b25c64333e9f349e628cf5a7541de801978e6d03d94a8e089b4d77ff17fea48f6ab783b55a07b55e9f6d3bc0848c914f12697d39",
    );
    let d = decode_le_hex(
        "6bcff5e1818548640cd80cbf9d93087921bfc2f25731833e658a2ba96738fbd927905ae4ddcda05ab59b565de19557a9da6eced57f3a884cfd00ffe94e983fe9d631f1562d3d65587af183883fed24f8ada41a3a09bee1930be7dff75aaa7868974ec5e120f924af26f8a8ed1096ad65dd2a8df426d8f5a9a0789bb554e755eda64300f6e814abb68fc7eb334786f9c675ebce9d0396bdaeac227ac749080de691cc7c072d41c27737b77bf2c067c22b74d700a86d6c3779d6a3f3c4fad309f1330cd5762addb4769db8b058cc3d9877296a7869ecb2a31ae3684501ba094902e631b40512894faabafe6d0a477a02793c5a233f6a9e27805808618a619b5326",
    );
    let e = decode_le_hex("03");
    oaep_roundtrip(RsaOaepHash::Sha512, &n, &e, &d, None);
}
