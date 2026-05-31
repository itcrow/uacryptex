//! Integration test for Cryptonite `pkiExample` (`pki_example.c`).
//!
//! `pki_example_main_path` generates the full M257 PB hierarchy live (Task 7.1d).
//! `pki_example_fixture_regression` keeps the pre-built fixture subset for regression.

mod pki_example_gen;

use der::asn1::Int;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::{build_signed_data, EnvelopedDataEngine};
use uacryptex_core::pki::crl::Crl;
use uacryptex_core::pki::crypto::{DigestAdapter, MasterPrng, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    default_tsp_digest_aids, etspresp_generate, OcspRequestEngine, OcspResponseEngine,
    ResponderIdType, TspAdapterMap,
};
use uacryptex_core::pki::ocsp::{OcspReq, OcspResponseStatus};
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::storage::pkcs12::{pkcs12_decode, pkcs12_get_sign_adapter, pkcs12_select_key};

use pki_example_gen::PkiExample;

mod fixtures {
    use super::*;

    pub struct FixturePkiExample {
        pub inner: PkiExample,
        pub userfiz_key: &'static [u8],
        pub ocsp_key: &'static [u8],
    }

    impl FixturePkiExample {
        pub fn load() -> Self {
            Self {
                inner: PkiExample {
                    root: Cert::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/root_certificate.cer"
                    ))
                    .expect("root cert"),
                    userfiz: Cert::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
                    ))
                    .expect("userfiz cert"),
                    userur: Cert::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/userur_certificate.cer"
                    ))
                    .expect("userur cert"),
                    ocsp: Cert::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/ocsp_certificate.cer"
                    ))
                    .expect("ocsp cert"),
                    userfiz_store: include_bytes!(
                        "../../../testdata/pki/pki_example/userfiz_private_key_ba.dat"
                    )
                    .to_vec(),
                    userur_store: include_bytes!("../../../testdata/pki/userur_private_key.dat")
                        .to_vec(),
                    ocsp_store: include_bytes!(
                        "../../../testdata/pki/pki_example/ocsp_private_key_ba.dat"
                    )
                    .to_vec(),
                    full_crl: Crl::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/full.crl"
                    ))
                    .expect("full crl"),
                    delta_crl: Crl::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/delta.crl"
                    ))
                    .expect("delta crl"),
                    ocsp_request: OcspReq::decode(include_bytes!(
                        "../../../testdata/pki/pki_example/ocsp_request.der"
                    ))
                    .expect("ocsp request"),
                    tsp_request: include_bytes!(
                        "../../../testdata/pki/pki_example/tsp_request.der"
                    )
                    .to_vec(),
                },
                userfiz_key: include_bytes!(
                    "../../../testdata/pki/pki_example/userfiz_private_key_ba.dat"
                ),
                ocsp_key: include_bytes!(
                    "../../../testdata/pki/pki_example/ocsp_private_key_ba.dat"
                ),
            }
        }
    }
}

fn run_pki_example_flow(fx: &PkiExample) {
    let root_va = fx.root_va().expect("root va");

    // --- PKI hierarchy (generate_*_certificate) ---
    fx.userfiz.verify(&root_va).expect("userfiz chain");
    fx.userur.verify(&root_va).expect("userur chain");
    fx.ocsp.verify(&root_va).expect("ocsp chain");
    assert!(fx.ocsp.is_ocsp_responder().unwrap());

    // --- CRL (generate_crl_container) ---
    fx.full_crl.verify(&root_va).expect("full crl signature");
    fx.delta_crl.verify(&root_va).expect("delta crl signature");
    assert!(!fx.full_crl.is_delta());
    assert!(fx.delta_crl.is_delta());
    assert!(!fx.full_crl.check_cert(&fx.userfiz).unwrap());
    assert!(fx.full_crl.revoked_cert_by_serial(b"463").is_ok());

    // --- OCSP (generate_ocsp_request/response) ---
    let ocsp_va = VerifyAdapter::init_by_cert(&fx.ocsp).unwrap();
    let userfiz_va = VerifyAdapter::init_by_cert(&fx.userfiz).unwrap();
    let ocsp_sa = fx.ocsp_sign_adapter().expect("ocsp sa");
    let da = DigestAdapter::init_default().unwrap();
    let crls = [fx.full_crl.clone(), fx.delta_crl.clone()];

    let mut ocsp_resp_engine = OcspResponseEngine::alloc(
        &root_va,
        &ocsp_sa,
        &crls,
        &da,
        true,
        true,
        ResponderIdType::ByHashKey,
    )
    .unwrap();
    ocsp_resp_engine.set_sign_required(true);
    ocsp_resp_engine.set_crls(&crls).unwrap();

    let ocsp_time = 1_359_151_200;
    let ocsp_response = ocsp_resp_engine
        .generate(&fx.ocsp_request, &userfiz_va, ocsp_time)
        .expect("ocsp response");
    ocsp_response
        .verify(&ocsp_va)
        .expect("ocsp response signature");
    assert_eq!(
        ocsp_response.response_status(),
        OcspResponseStatus::Successful
    );

    let ocsp_req_engine = OcspRequestEngine::alloc(false, &root_va, None, None, &da).unwrap();
    ocsp_req_engine
        .validate_response(&ocsp_response, ocsp_time, 2)
        .expect("ocsp response validation");

    // --- TSP (generate_tsp_request/response) ---
    let userfiz_sa = fx.userfiz_sign_adapter().expect("userfiz sa");
    let mut tsp_map = TspAdapterMap::new();
    tsp_map.add(da.clone_state().unwrap(), userfiz_sa);
    let sn = Int::new(&128u8.to_be_bytes()).unwrap();
    let tsp_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let tsp_response = etspresp_generate(
        &tsp_map,
        &fx.tsp_request,
        &sn,
        &default_tsp_digest_aids().unwrap(),
        tsp_time,
    )
    .expect("tsp response");
    tsp_response
        .verify(&da, &userfiz_va)
        .expect("tsp token verify");

    // --- CMS CAdES-BES (generate_signed_data_container) ---
    let data = vec![0xf0; 100];
    let signed = build_signed_data(&fx.userfiz_sign_adapter().unwrap(), &data, OidId::Data)
        .expect("cms sign");
    signed
        .verify_internal_data(&da, &userfiz_va, 0)
        .expect("cms verify");
    assert_eq!(signed.encapsulated_content().unwrap(), data);

    // --- PKCS#12 roundtrip (private.key encode/decode path) ---
    let mut store =
        pkcs12_decode(None, &fx.userfiz_store, pki_example_gen::STORAGE_PASS).expect("decode p12");
    pkcs12_select_key(
        &mut store,
        Some(pki_example_gen::KEY_ALIAS),
        Some(pki_example_gen::KEY_PASS),
    )
    .expect("select key");
    let roundtrip_sa = pkcs12_get_sign_adapter(&store).expect("roundtrip sa");
    let roundtrip_signed =
        build_signed_data(&roundtrip_sa, &data, OidId::Data).expect("roundtrip cms sign");
    roundtrip_signed
        .verify_internal_data(&da, &userfiz_va, 0)
        .expect("roundtrip cms verify");

    // --- EnvelopedData (generate_enveloped_data_static pattern) ---
    const PLAINTEXT: &[u8] = b"Status message for enveloped data test";
    let originator_dh = fx.userfiz_sign_adapter().unwrap().dh_adapter().unwrap();
    let recipient_dh = fx.userur_sign_adapter().unwrap().dh_adapter().unwrap();
    let prng = MasterPrng::new().unwrap();

    let mut engine = EnvelopedDataEngine::new(&originator_dh);
    engine.set_originator_cert(&fx.userfiz).unwrap();
    engine.set_data(OidId::Data, PLAINTEXT).unwrap();
    engine.set_encryption_oid(OidId::Gost28147Cfb);
    engine.set_save_cert(false);
    engine.set_save_data(true);
    engine.set_prng(prng);
    engine.add_recipient(&fx.userur);

    let (container, external) = engine.generate().unwrap();
    assert!(external.is_none());
    let decrypted = container
        .decrypt_data(None, Some(&fx.userfiz), &recipient_dh, &fx.userur)
        .unwrap();
    assert_eq!(decrypted, PLAINTEXT);
}

#[test]
fn pki_example_main_path() {
    let fx = PkiExample::generate().expect("live pki generation");
    run_pki_example_flow(&fx);
}

#[test]
fn pki_example_fixture_regression() {
    let fx = fixtures::FixturePkiExample::load();
    let root_va = fx.inner.root_va().expect("root va");

    fx.inner.userfiz.verify(&root_va).expect("userfiz chain");
    fx.inner.userur.verify(&root_va).expect("userur chain");
    fx.inner.ocsp.verify(&root_va).expect("ocsp chain");

    let ocsp_va = VerifyAdapter::init_by_cert(&fx.inner.ocsp).unwrap();
    let userfiz_va = VerifyAdapter::init_by_cert(&fx.inner.userfiz).unwrap();
    let ocsp_sa = SignAdapter::init_by_cert(fx.ocsp_key, &fx.inner.ocsp).unwrap();
    let userfiz_sa = SignAdapter::init_by_cert(fx.userfiz_key, &fx.inner.userfiz).unwrap();
    let da = DigestAdapter::init_default().unwrap();
    let crls = [fx.inner.full_crl.clone(), fx.inner.delta_crl.clone()];

    let mut ocsp_resp_engine = OcspResponseEngine::alloc(
        &root_va,
        &ocsp_sa,
        &crls,
        &da,
        true,
        true,
        ResponderIdType::ByHashKey,
    )
    .unwrap();
    ocsp_resp_engine.set_sign_required(true);
    ocsp_resp_engine.set_crls(&crls).unwrap();

    let ocsp_response = ocsp_resp_engine
        .generate(&fx.inner.ocsp_request, &userfiz_va, 1_359_151_200)
        .expect("ocsp response");
    ocsp_response.verify(&ocsp_va).expect("ocsp signature");

    let mut tsp_map = TspAdapterMap::new();
    tsp_map.add(da.clone_state().unwrap(), userfiz_sa);
    let sn = Int::new(&128u8.to_be_bytes()).unwrap();
    let tsp_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    etspresp_generate(
        &tsp_map,
        &fx.inner.tsp_request,
        &sn,
        &default_tsp_digest_aids().unwrap(),
        tsp_time,
    )
    .expect("tsp response");

    let data = vec![0xf0; 100];
    build_signed_data(
        &SignAdapter::init_by_cert(fx.userfiz_key, &fx.inner.userfiz).unwrap(),
        &data,
        OidId::Data,
    )
    .expect("cms sign")
    .verify_internal_data(&da, &userfiz_va, 0)
    .expect("cms verify");
}
