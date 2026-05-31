//! Integration tests using Cryptonite KAT vectors (`testdata/kat/`).

use std::path::PathBuf;

use serde::Deserialize;
use uacryptex_core::primitives::dstu4145::{
    verify, CurveParams, FieldPolynomial, PublicKey, Signature,
};

fn kat_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/kat/dstu4145")
        .join(name)
}

fn decode_be_hex(s: &str) -> Vec<u8> {
    // Cryptonite `ba_alloc_from_be_hex_string`: pad odd-length hex, reverse byte order.
    // Load into `WordArray` via `WordArray::from_le_bytes` (Cryptonite `wa_alloc_from_ba`).
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    let mut v = hex::decode(s).expect("valid hex in KAT file");
    v.reverse();
    v
}

fn decode_le_hex(s: &str) -> Vec<u8> {
    // Cryptonite `ba_alloc_from_le_hex_string`: sequential byte order.
    hex::decode(s).expect("valid hex in KAT file")
}

#[derive(Debug, Deserialize)]
struct VerifyPnKat {
    id: String,
    field: KatField,
    curve: KatCurve,
    public_key: KatPoint,
    hash: String,
    signature: KatSignature,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct KatField {
    f: Vec<u32>,
    a: i32,
}

#[derive(Debug, Deserialize)]
struct KatCurve {
    b: String,
    n: String,
    base_point: KatPoint,
}

#[derive(Debug, Deserialize)]
struct KatPoint {
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
struct KatSignature {
    r: String,
    s: String,
    encoding: String,
}

fn load_verify_pn() -> VerifyPnKat {
    let path = kat_path("verify_pn.json");
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&data).expect("parse verify_pn.json")
}

#[test]
fn verify_pn_kat_vectors_load_and_decode() {
    let kat = load_verify_pn();
    assert_eq!(kat.id, "verify-pn");
    assert_eq!(kat.field.f, vec![163, 7, 6, 3, 0]);
    assert_eq!(kat.hash.len(), 64);
    assert_eq!(decode_be_hex(&kat.hash).len(), 32);

    let (r, s) = match kat.signature.encoding.as_str() {
        "little_endian" => (
            decode_le_hex(&kat.signature.r),
            decode_le_hex(&kat.signature.s),
        ),
        "big_endian" => (
            decode_be_hex(&kat.signature.r),
            decode_be_hex(&kat.signature.s),
        ),
        other => panic!("unknown signature encoding: {other}"),
    };

    assert!(!r.is_empty());
    assert!(!s.is_empty());
}

/// Full verification against Cryptonite `atest_dstu4145::dstu4145_verify_pn`.
#[test]
fn verify_pn_kat_matches_cryptonite() {
    let kat = load_verify_pn();

    let params = CurveParams {
        field: FieldPolynomial {
            f: kat.field.f,
            a: kat.field.a,
        },
        is_onb: false,
        b: decode_be_hex(&kat.curve.b),
        n: decode_be_hex(&kat.curve.n),
        base_x: decode_be_hex(&kat.curve.base_point.x),
        base_y: decode_be_hex(&kat.curve.base_point.y),
    };

    let public_key = PublicKey {
        x: decode_be_hex(&kat.public_key.x),
        y: decode_be_hex(&kat.public_key.y),
    };

    let hash = decode_be_hex(&kat.hash);

    let signature = match kat.signature.encoding.as_str() {
        "little_endian" => Signature::from_le(
            decode_le_hex(&kat.signature.r),
            decode_le_hex(&kat.signature.s),
        ),
        "big_endian" => Signature::from_be(
            decode_be_hex(&kat.signature.r),
            decode_be_hex(&kat.signature.s),
        ),
        other => panic!("unknown signature encoding: {other}"),
    };

    verify(&params, &public_key, &hash, &signature).expect("signature must verify");

    assert_eq!(kat.expected, "valid");
}
