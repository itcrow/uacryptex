//! Cryptographic operation benchmarks (compare with Cryptonite `cryptonitePtest/`).

use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::SignedDataContainer;
use uacryptex_core::pki::crypto::{DigestAdapter, VerifyAdapter};
use uacryptex_core::primitives::dstu4145::{sign, verify, ParamsId, PublicKey, Signature, SliceRandom};
use uacryptex_core::primitives::dstu7564::hash;

fn hex_le(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn m257_verify_fixture() -> (
    uacryptex_core::primitives::dstu4145::CurveParams,
    PublicKey,
    Vec<u8>,
    Signature,
) {
    let params = ParamsId::M257Pb.curve_params().unwrap();
    let hash = hex_le("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    let pk = PublicKey {
        x: hex_le("01799b65a6d2d1cecd08b044d599eecfab8412f599f52ca38ddb431bba38e66c00"),
        y: hex_le("e54176a56aaf5e5bea7c7dbbacfbe6ad1c35bf9743cb534d839d62be68bc4c5a01"),
    };
    let sig = Signature::from_le(
        hex_le("ace29a89ec34329abf529d109ca838c26b13cc0e14d8663071da94ab198e2e64"),
        hex_le("39b9c25ab0187694ec170221e9135405894bf439c9cefea7f23e4e1a974eca1b"),
    );
    (params, pk, hash, sig)
}

fn m257_sign_fixture() -> (
    uacryptex_core::primitives::dstu4145::CurveParams,
    Vec<u8>,
    Vec<u8>,
    SliceRandom,
) {
    let params = ParamsId::M257Pb.curve_params().unwrap();
    let d = hex_le("4854f9d1eeeaab9516288183f164044ec3cdbd00288856db40b4cdf07dfc140900");
    let hash = hex_le("b591f4d5ea42d0005dedf238e8beccc2cb46a944419b6fdd66c57e66c751f683");
    let rng = SliceRandom::new(vec![0x42; 64]);
    (params, d, hash, rng)
}

fn bench_dstu4145_verify(c: &mut Criterion) {
    let (params, pk, digest, sig) = m257_verify_fixture();
    c.bench_function("dstu4145_verify_m257", |b| {
        b.iter(|| verify(black_box(&params), black_box(&pk), black_box(&digest), black_box(&sig)))
    });
}

fn bench_dstu4145_sign(c: &mut Criterion) {
    let (params, d, digest, mut rng) = m257_sign_fixture();
    c.bench_function("dstu4145_sign_m257", |b| {
        b.iter(|| sign(black_box(&params), black_box(&d), black_box(&digest), black_box(&mut rng)))
    });
}

fn bench_kupyna_hash(c: &mut Criterion) {
    let data = vec![0xABu8; 1024];
    c.bench_function("kupyna_32_1kib", |b| {
        b.iter(|| hash(black_box(&data), 32).unwrap())
    });
}

fn bench_cms_verify(c: &mut Criterion) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pki/signed_data.dat");
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let sdata = SignedDataContainer::decode(&der).expect("decode signed_data.dat");
    let cert = Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der")).unwrap();
    let da = DigestAdapter::init_by_cert(&cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();

    c.bench_function("cms_verify_signed_data", |b| {
        b.iter(|| sdata.verify_internal_data(black_box(&da), black_box(&va), 0))
    });
}

criterion_group!(
    benches,
    bench_dstu4145_verify,
    bench_dstu4145_sign,
    bench_kupyna_hash,
    bench_cms_verify
);
criterion_main!(benches);
