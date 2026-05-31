//! International algorithm KAT (Cryptonite `atest_*.c`, `utest_rsa.c`).

mod aes_ecb_full;
mod aes_vectors;
mod des_vectors;
mod md5_vectors;
mod rsa_tests;
mod sha1_vectors;

// RSA tests live in `rsa_tests.rs` (utest_rsa.c vectors).

use aes_ecb_full::AES_ECB_FULL_DATA;
use aes_vectors::{AES_CBC_DATA, AES_CFB_DATA, AES_CTR_DATA, AES_OFB_DATA};
use des_vectors::{DES_ECB_DATA, TDES_ECB_DATA};
use md5_vectors::MD5_TEST_DATA;
use sha1_vectors::SHA1_TEST_DATA;
use uacryptex_core::primitives::intl::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_cfb_decrypt, aes_cfb_encrypt, aes_ctr_crypt,
    aes_ecb_decrypt, aes_ecb_encrypt, aes_ofb_crypt, des_ecb_decrypt, des_ecb_encrypt,
    ecdsa_verify_p192, ecdsa_verify_p224, ecdsa_verify_p256, ecdsa_verify_p384, ecdsa_verify_p521,
    hmac_md5, hmac_sha1, hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512, md5_digest,
    md5_digest_chunks, sha1_digest, sha1_digest_chunks, sha224_digest, sha224_digest_chunks,
    sha256_digest, sha256_digest_chunks, sha384_digest, sha384_digest_chunks, sha512_digest,
    sha512_digest_chunks, tdes_ecb_decrypt, tdes_ecb_encrypt,
};

fn decode_le_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex in KAT vector")
}

/// Cryptonite `ba_alloc_from_be_hex_string` (test_utils) byte order.
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

// --- SHA-1 (`atest_sha1.c` `test_sha1` byte vectors) ---

#[test]
fn sha1_core_vectors() {
    struct Case {
        data: &'static [u8],
        expected: [u8; 20],
    }
    const CASES: &[Case] = &[
        Case {
            data: b"a",
            expected: [
                0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d, 0x1d, 0xdc, 0xb9,
                0xea, 0xea, 0xea, 0x37, 0x76, 0x67, 0xb8,
            ],
        },
        Case {
            data: b"abc",
            expected: [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
                0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ],
        },
        Case {
            data: b"message digest",
            expected: [
                0xc1, 0x22, 0x52, 0xce, 0xda, 0x8b, 0xe8, 0x99, 0x4d, 0x5f, 0xa0, 0x29, 0x0a,
                0x47, 0x23, 0x1c, 0x1d, 0x16, 0xaa, 0xe3,
            ],
        },
        Case {
            data: b"abcdefghijklmnopqrstuvwxyz",
            expected: [
                0x32, 0xd1, 0x0c, 0x7b, 0x8c, 0xf9, 0x65, 0x70, 0xca, 0x04, 0xce, 0x37, 0xf2,
                0xa1, 0x9d, 0x84, 0x24, 0x0d, 0x3a, 0x89,
            ],
        },
        Case {
            // `atest_sha1.c` `data[4]` — alternating `abcd…` pattern, not sequential.
            data: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            expected: [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9,
                0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
            ],
        },
        Case {
            data: b"The quick brown fox jumps over the lazy dog",
            expected: [
                0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb,
                0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
            ],
        },
        Case {
            data: b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            expected: [
                0xa4, 0x9b, 0x24, 0x46, 0xa0, 0x2c, 0x64, 0x5b, 0xf4, 0x19, 0xf9, 0x95, 0xb6,
                0x70, 0x91, 0x25, 0x3a, 0x04, 0xa2, 0x59,
            ],
        },
    ];

    for (i, c) in CASES.iter().enumerate() {
        let got = sha1_digest(c.data);
        assert_eq!(got, c.expected, "sha1 core case {i}");
        if c.data.len() >= 2 {
            let chunks = [&c.data[..1], &c.data[1..2], &c.data[2..]];
            assert_eq!(
                sha1_digest_chunks(&chunks),
                c.expected,
                "sha1 chunked case {i}"
            );
        }
    }
}

#[test]
fn sha1_le_hex_vectors() {
    for (i, v) in SHA1_TEST_DATA.iter().enumerate() {
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.hash);
        assert_eq!(
            sha1_digest(&data).as_slice(),
            exp.as_slice(),
            "SHA1_TEST_DATA[{i}]"
        );
    }
}

/// RFC 3174 million-`a` test (slow; Cryptonite `test_sha1`).
#[test]
#[ignore = "expensive; run with --ignored"]
fn sha1_million_a() {
    let expected: [u8; 20] = [
        0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27,
        0x31, 0x65, 0x34, 0x01, 0x6f,
    ];
    // single-byte updates like Cryptonite loop
    let mut h = sha1::Sha1::new();
    use sha1::Digest;
    for _ in 0..1_000_000 {
        h.update([b'a']);
    }
    assert_eq!(h.finalize().as_slice(), expected);
}

// --- SHA-2 (`atest_sha2.c` `test_sha2`) ---

#[test]
fn sha2_core_vectors() {
    let data3 = b"abc";
    let data56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let data112 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    const EXP_3_224: [u8; 28] = [
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55,
        0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
    ];
    const EXP_56_224: [u8; 28] = [
        0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01,
        0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25,
    ];
    const EXP_112_224: [u8; 28] = [
        0xc9, 0x7c, 0xa9, 0xa5, 0x59, 0x85, 0x0c, 0xe9, 0x7a, 0x04, 0xa9, 0x6d, 0xef, 0x6d, 0x99,
        0xa9, 0xe0, 0xe0, 0xe2, 0xab, 0x14, 0xe6, 0xb8, 0xdf, 0x26, 0x5f, 0xc0, 0xb3,
    ];
    const EXP_3_256: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    const EXP_112_256: [u8; 32] = [
        0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92,
        0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe,
        0xe9, 0xd1,
    ];
    const EXP_3_384: [u8; 48] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];
    const EXP_112_384: [u8; 48] = [
        0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b,
        0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2, 0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0,
        0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91,
        0x74, 0x60, 0x39,
    ];
    const EXP_3_512: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    const EXP_112_512: [u8; 64] = [
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14,
        0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88,
        0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4,
        0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b,
        0x87, 0x4b, 0xe9, 0x09,
    ];

    assert_eq!(sha224_digest(data3), EXP_3_224);
    assert_eq!(sha224_digest(data56), EXP_56_224);
    assert_eq!(sha224_digest(data112), EXP_112_224);
    assert_eq!(sha256_digest(data3), EXP_3_256);
    assert_eq!(sha256_digest(data112), EXP_112_256);
    assert_eq!(sha384_digest(data3), EXP_3_384);
    assert_eq!(sha384_digest(data112), EXP_112_384);
    assert_eq!(sha512_digest(data3), EXP_3_512);
    assert_eq!(sha512_digest(data112), EXP_112_512);

    let chunk3 = [&data3[..1], &data3[1..2], &data3[2..]];
    assert_eq!(sha224_digest_chunks(&chunk3), sha224_digest(data3));
    assert_eq!(sha256_digest_chunks(&chunk3), sha256_digest(data3));
    assert_eq!(sha384_digest_chunks(&chunk3), sha384_digest(data3));
    assert_eq!(sha512_digest_chunks(&chunk3), sha512_digest(data3));
}

// --- AES (`atest_aes.c`) ---

#[test]
fn aes_ecb_full_vectors() {
    for (i, v) in AES_ECB_FULL_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = aes_ecb_encrypt(&key, &data).expect("ecb encrypt");
        assert_eq!(enc, exp, "AES ECB encrypt [{i}]");
        let dec = aes_ecb_decrypt(&key, &enc).expect("ecb decrypt");
        assert_eq!(dec, data, "AES ECB roundtrip [{i}]");
    }
}

#[test]
fn aes_cbc_vectors() {
    for (i, v) in AES_CBC_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let iv = decode_le_hex(v.iv);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = aes_cbc_encrypt(&key, &iv, &data).expect("cbc encrypt");
        assert_eq!(enc, exp, "AES CBC encrypt [{i}]");
        let dec = aes_cbc_decrypt(&key, &iv, &enc).expect("cbc decrypt");
        assert_eq!(dec, data, "AES CBC roundtrip [{i}]");
    }
}

#[test]
fn aes_ctr_vectors() {
    for (i, v) in AES_CTR_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let iv = decode_le_hex(v.iv);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = aes_ctr_crypt(&key, &iv, &data).expect("ctr encrypt");
        assert_eq!(enc, exp, "AES CTR encrypt [{i}]");
        let dec = aes_ctr_crypt(&key, &iv, &enc).expect("ctr decrypt");
        assert_eq!(dec, data, "AES CTR roundtrip [{i}]");
    }
}

#[test]
fn aes_cfb_vectors() {
    for (i, v) in AES_CFB_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let iv = decode_le_hex(v.iv);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = aes_cfb_encrypt(&key, &iv, &data).expect("cfb encrypt");
        assert_eq!(enc, exp, "AES CFB encrypt [{i}]");
        let dec = aes_cfb_decrypt(&key, &iv, &enc).expect("cfb decrypt");
        assert_eq!(dec, data, "AES CFB roundtrip [{i}]");
    }
}

#[test]
fn aes_ofb_vectors() {
    for (i, v) in AES_OFB_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let iv = decode_le_hex(v.iv);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = aes_ofb_crypt(&key, &iv, &data).expect("ofb encrypt");
        assert_eq!(enc, exp, "AES OFB encrypt [{i}]");
        let dec = aes_ofb_crypt(&key, &iv, &enc).expect("ofb decrypt");
        assert_eq!(dec, data, "AES OFB roundtrip [{i}]");
    }
}

// --- MD5 (`atest_md5.c` md5_data) ---

#[test]
fn sha1_hmac_vectors() {
    struct Case {
        data: &'static str,
        key_hex: &'static str,
        expected_hex: &'static str,
    }
    const CASES: &[Case] = &[
        Case {
            data: "Hi There",
            key_hex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            expected_hex: "b617318655057264e28bc0b6fb378c8ef146be00",
        },
        Case {
            data: "Test With Truncation",
            key_hex: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            expected_hex: "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        },
        Case {
            data: "Test Using Larger Than Block-Size Key - Hash Key First",
            key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected_hex: "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        },
        Case {
            data: "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected_hex: "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        },
    ];
    for (i, c) in CASES.iter().enumerate() {
        let key = decode_le_hex(c.key_hex);
        let exp = decode_le_hex(c.expected_hex);
        assert_eq!(
            hmac_sha1(&key, c.data.as_bytes()).as_slice(),
            exp.as_slice(),
            "SHA-1 HMAC case {i}"
        );
    }
}

#[test]
fn sha2_hmac_vectors() {
    struct Case {
        key: &'static [u8],
        data: &'static [u8],
        exp224: [u8; 28],
        exp256: [u8; 32],
        exp384: [u8; 48],
        exp512: [u8; 64],
    }
    const KEY0: [u8; 20] = [0x0b; 20];
    const KEY2: [u8; 20] = [0xaa; 20];
    const DATA2: [u8; 50] = [0xdd; 50];
    const CASES: &[Case] = &[
        Case {
            key: &KEY0,
            data: b"Hi There",
            exp224: [
                0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d,
                0xf3, 0x3f, 0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22,
            ],
            exp256: [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ],
            exp384: [
                0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46,
                0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c,
                0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1,
                0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
            ],
            exp512: [
                0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
                0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
                0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
                0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
                0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
            ],
        },
        Case {
            key: b"Jefe",
            data: b"what do ya want for nothing?",
            exp224: [
                0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf, 0x45, 0x69, 0x0f, 0x3a, 0x7e, 0x9e,
                0x6d, 0x0f, 0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00, 0x8f, 0xd0, 0x5e, 0x44,
            ],
            exp256: [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ],
            exp384: [
                0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a,
                0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47, 0xe4, 0x2e, 0xc3, 0x73,
                0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32,
                0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49,
            ],
            exp512: [
                0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
                0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
                0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03,
                0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
                0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37,
            ],
        },
        Case {
            key: &KEY2,
            data: &DATA2,
            exp224: [
                0x7f, 0xb3, 0xcb, 0x35, 0x88, 0xc6, 0xc1, 0xf6, 0xff, 0xa9, 0x69, 0x4d, 0x7d, 0x6a,
                0xd2, 0x64, 0x93, 0x65, 0xb0, 0xc1, 0xf6, 0x5d, 0x69, 0xd1, 0xec, 0x83, 0x33, 0xea,
            ],
            exp256: [
                0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91,
                0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14,
                0xce, 0xd5, 0x65, 0xfe,
            ],
            exp384: [
                0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a, 0x0a, 0xa2, 0xac, 0xe0, 0x14, 0xc8,
                0xa8, 0x6f, 0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb, 0xe8, 0x3e, 0xf4, 0xe5,
                0x59, 0x66, 0x14, 0x4b, 0x2a, 0x5a, 0xb3, 0x9d, 0xc1, 0x38, 0x14, 0xb9, 0x4e, 0x3a,
                0xb6, 0xe1, 0x01, 0xa3, 0x4f, 0x27,
            ],
            exp512: [
                0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89,
                0x0b, 0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36, 0x55, 0xf8, 0x3e, 0x33,
                0xb2, 0x27, 0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4,
                0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07, 0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26,
                0x74, 0x27, 0x88, 0x59, 0xe1, 0x32, 0x92, 0xfb,
            ],
        },
    ];
    for (i, c) in CASES.iter().enumerate() {
        assert_eq!(
            hmac_sha224(c.key, c.data),
            c.exp224,
            "SHA-224 HMAC case {i}"
        );
        assert_eq!(
            hmac_sha256(c.key, c.data),
            c.exp256,
            "SHA-256 HMAC case {i}"
        );
        assert_eq!(
            hmac_sha384(c.key, c.data),
            c.exp384,
            "SHA-384 HMAC case {i}"
        );
        assert_eq!(
            hmac_sha512(c.key, c.data),
            c.exp512,
            "SHA-512 HMAC case {i}"
        );
    }
}

#[test]
fn md5_hmac_vectors() {
    struct Case {
        data: &'static str,
        key_hex: &'static str,
        expected_hex: &'static str,
    }
    const CASES: &[Case] = &[
        Case {
            data: "Hi There",
            key_hex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            expected_hex: "9294727a3638bb1c13f48ef8158bfc9d",
        },
        Case {
            data: "Test With Truncation",
            key_hex: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            expected_hex: "56461ef2342edc00f9bab995690efd4c",
        },
        Case {
            data: "Test Using Larger Than Block-Size Key - Hash Key First",
            key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected_hex: "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
        },
        Case {
            data: "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected_hex: "6f630fad67cda0ee1fb1f562db3aa53e",
        },
    ];
    for (i, c) in CASES.iter().enumerate() {
        let key = decode_le_hex(c.key_hex);
        let exp = decode_le_hex(c.expected_hex);
        assert_eq!(
            hmac_md5(&key, c.data.as_bytes()).as_slice(),
            exp.as_slice(),
            "MD5 HMAC case {i}"
        );
    }
}

#[test]
fn md5_le_hex_vectors() {
    for (i, v) in MD5_TEST_DATA.iter().enumerate() {
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.hash);
        assert_eq!(
            md5_digest(&data).as_slice(),
            exp.as_slice(),
            "MD5_TEST_DATA[{i}]"
        );
        if data.len() >= 2 {
            let chunks = [&data[..1], &data[1..]];
            assert_eq!(
                md5_digest_chunks(&chunks),
                exp.as_slice(),
                "MD5 chunked [{i}]"
            );
        }
    }
}

// --- DES / TDES (`atest_des.c`) ---

#[test]
fn des_ecb_vectors() {
    for (i, v) in DES_ECB_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = des_ecb_encrypt(&key, &data).expect("des ecb encrypt");
        assert_eq!(enc, exp, "DES ECB encrypt [{i}]");
        let dec = des_ecb_decrypt(&key, &enc).expect("des ecb decrypt");
        assert_eq!(dec, data, "DES ECB roundtrip [{i}]");
    }
}

#[test]
fn tdes_ecb_vectors() {
    for (i, v) in TDES_ECB_DATA.iter().enumerate() {
        let key = decode_le_hex(v.key);
        let data = decode_le_hex(v.data);
        let exp = decode_le_hex(v.exp);
        let enc = tdes_ecb_encrypt(&key, &data).expect("tdes ecb encrypt");
        assert_eq!(enc, exp, "TDES ECB encrypt [{i}]");
        let dec = tdes_ecb_decrypt(&key, &enc).expect("tdes ecb decrypt");
        assert_eq!(dec, data, "TDES ECB roundtrip [{i}]");
    }
}

// --- ECDSA (`atest_ecdsa.c`) ---

#[test]
fn ecdsa_verify_p192_vector() {
    let hash = decode_le_hex("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ecdsa_verify_p192(
        &decode_cryptonite_be_hex("8CF149E91FDFE308B66FAD9F82BBB098576FEA6BEACA7377"),
        &decode_cryptonite_be_hex("AB6F6331C39C220BEA716E93722217FFFE727A962402C66D"),
        &hash,
        &decode_cryptonite_be_hex("D693C651109B4EDE0FDAB92779F74D5D8965A16C5881BEED"),
        &decode_cryptonite_be_hex("5BF193AD07A2FE10EEDD70D43A9B14404E3C284907825407"),
    )
    .expect("P-192 verify");
}

#[test]
fn ecdsa_verify_p224_vector() {
    let hash = decode_le_hex("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ecdsa_verify_p224(
        &decode_cryptonite_be_hex("0BF55F03595A7AFB3378969C65021E802C43318A99381F58B01A7DD6"),
        &decode_cryptonite_be_hex("8B5A54E16C41D12B12DB0E9356B4A0AF8FB9C073F23FE753FD16FAEC"),
        &hash,
        &decode_cryptonite_be_hex("8C55714BA398EE461622AD1D03A0C7F754887DA1A7D169AE1DA2122B"),
        &decode_cryptonite_be_hex("1B6F7AA600D086E5F89C22BCE772D09FCEC75EF996CA3429694A860D"),
    )
    .expect("P-224 verify");
}

#[test]
fn ecdsa_verify_p256_vector() {
    let hash = decode_le_hex("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ecdsa_verify_p256(
        &decode_cryptonite_be_hex(
            "772B443BB07ACD53FB22E0F014170EB12E74D0EBBA1581CF4D23F4E6B6CFD3D6",
        ),
        &decode_cryptonite_be_hex(
            "2B0F69465776093479E5B7C73549DF226ACC333F7B5D961186394D44C12045F3",
        ),
        &hash,
        &decode_cryptonite_be_hex(
            "75983BD5D6F48856F3E9A54CDEAA0AD9A43E078E8F8217384B2C185381D818E1",
        ),
        &decode_cryptonite_be_hex(
            "B8DAE388F45FE1842209493BF38CE9AF9DCEBD2A0DA5486D136768C2A06D3F63",
        ),
    )
    .expect("P-256 verify");
}

#[test]
fn ecdsa_verify_p384_vector() {
    let hash = decode_le_hex("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ecdsa_verify_p384(
        &decode_cryptonite_be_hex(
            "C928368C7C90EE01353556847951E2E45E1ABFA2533D2C70EB27B203D8CFE6B66A2C9D8478929D5CB686B457036BDCA1",
        ),
        &decode_cryptonite_be_hex(
            "C9D46DDBDFE2DAB2CFCFC808B8F82393AFEB735F14C5D60616B7BE8336092E04ECD87913214CB9E3A359F33B5C600B0D",
        ),
        &hash,
        &decode_cryptonite_be_hex(
            "786A77C1E35E1B0B8855621938D171A492B51F649E3EB67552DF82030854836D4943A7FE688B2906ABC528D2418F6F5A",
        ),
        &decode_cryptonite_be_hex(
            "A9E00641687C1DCF0E09F25C518EFB627687E198F990CAE365F192268F38122B3E5C905E29981B5468C630BE05840F4C",
        ),
    )
    .expect("P-384 verify");
}

#[test]
fn ecdsa_verify_p521_vector() {
    let hash = decode_le_hex("ac9c2a2ca4eb7c4a9039e658e7f8d7b11aef1f34");
    ecdsa_verify_p521(
        &decode_cryptonite_be_hex(
            "009C4CD55935E8C54F60DE76CF72CC260D65DEB4E3D0D526D9FF825E309B497115CB4723357A5819726E808A590302FD3C776100BF003F81B587BAF98DA180706D2F",
        ),
        &decode_cryptonite_be_hex(
            "01880D89C859724934B8F61ECB21D889D9BEA11F72738735E29C35448DD980F5BEF143C4630384417FB0B7B1013E2465AEEE98D4F3F3D997AF29D31CA1ABC92DD343",
        ),
        &hash,
        &decode_cryptonite_be_hex(
            "003B348A28547ECBB32C4FA4A0C43AC5514581FB26731C7607715270C992FC2D4A4DED1D13E7DC0C80906A341100F9A80B580DC9901351EBB4EB8737ED74BC3A9D96",
        ),
        &decode_cryptonite_be_hex(
            "01FB38E44EC90E55D8DE0DF5836DE66C7C25C7FD3E3121C2F4C90FDB0863793858B55AE1AFBC7EE5993075350527E3A765C45DACBB716708684EB92D0926BED3E9A5",
        ),
    )
    .expect("P-521 verify");
}

// --- Parameter validation ---

#[test]
fn aes_ecb_rejects_invalid_key_length() {
    use uacryptex_core::Error;
    let err = aes_ecb_encrypt(&[0u8; 7], &[0u8; 16]).unwrap_err();
    assert!(matches!(err, Error::InvalidParam(_)));
}

#[test]
fn aes_ecb_rejects_unaligned_input() {
    use uacryptex_core::Error;
    let err = aes_ecb_encrypt(&[0u8; 16], &[0u8; 15]).unwrap_err();
    assert!(matches!(err, Error::InvalidParam(_)));
}

#[test]
fn des_ecb_rejects_invalid_key_length() {
    use uacryptex_core::Error;
    let err = des_ecb_encrypt(&[0u8; 7], &[0u8; 8]).unwrap_err();
    assert!(matches!(err, Error::InvalidParam(_)));
}

#[test]
fn rsa_oaep_rejects_message_too_long() {
    use uacryptex_core::primitives::intl::{rsa_oaep_encrypt, RsaOaepHash};
    let n = vec![0x01u8; 32];
    let e = decode_le_hex("010001");
    let msg = vec![0u8; 64];
    assert!(
        rsa_oaep_encrypt(RsaOaepHash::Sha256, &n, &e, &msg, None, &[0u8; 32]).is_err()
    );
}
