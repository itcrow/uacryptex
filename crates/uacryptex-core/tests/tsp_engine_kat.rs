//! TSP engine KAT (`utest_tsp_request_engine.c`, `utest_tsp_response_engine.c`).

use der::asn1::{Int, ObjectIdentifier};
use der::Encode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter, VerifyAdapter};
use uacryptex_core::pki::engine::{
    default_tsp_digest_aids, etspreq_generate, etspreq_generate_from_gost34311, etspresp_generate,
    TspAdapterMap,
};

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn kat_etspreq_generate_from_gost34311() {
    let hash = hex("891d358a84c6033cf17bac82d77bb5d6791695a08ffce3768d39fbcacf8b29bd");
    let policy = "1.2.804.2.1.1.1.2.2";
    let req = etspreq_generate_from_gost34311(&hash, policy, true).unwrap();
    let expected_policy = ObjectIdentifier::new(policy).unwrap();
    let actual_policy = req
        .policy()
        .unwrap()
        .decode_as::<ObjectIdentifier>()
        .unwrap();
    assert_eq!(actual_policy, expected_policy);
    assert!(req.cert_req());
}

#[test]
fn kat_etspreq_generate() {
    let msg = hex("0123456789ABCDEF");
    let rnd = hex("00FF00AA");
    let policy = ObjectIdentifier::new("1.2.804.2.1.1.1.2.2").unwrap();
    let da = DigestAdapter::init_default().unwrap();

    let req = etspreq_generate(&da, &msg, Some(&rnd), &policy, false).unwrap();
    assert_eq!(
        req.policy()
            .unwrap()
            .decode_as::<ObjectIdentifier>()
            .unwrap(),
        policy
    );
    assert!(!req.cert_req());

    let expected_imprint = hex(
        "3030300C060A2A8624020101010102010420867731CC54E37D615934FD6DE9603BD484B04AF86396512CEDD99161539FE753",
    );
    assert_eq!(req.message_imprint().to_der().unwrap(), expected_imprint);
    assert_eq!(req.nonce().unwrap().as_bytes(), rnd.as_slice());
}

#[test]
fn etspresp_generate_and_verify() {
    let cert = Cert::decode(include_bytes!(
        "../../../testdata/pki/pki_example/userfiz_certificate.cer"
    ))
    .unwrap();
    let private_key =
        include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat");
    let tsp_req = include_bytes!("../../../testdata/pki/pki_example/tsp_request.der");

    let da = DigestAdapter::init_default().unwrap();
    let sa = SignAdapter::init_by_cert(private_key, &cert).unwrap();
    let va = VerifyAdapter::init_by_cert(&cert).unwrap();

    let mut tsp_map = TspAdapterMap::new();
    tsp_map.add(da.clone_state().unwrap(), sa);

    let sn = Int::new(&128u8.to_be_bytes()).unwrap();
    let digest_aids = default_tsp_digest_aids().unwrap();
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let resp = etspresp_generate(&tsp_map, tsp_req, &sn, &digest_aids, current_time).unwrap();
    resp.verify(&da, &va).unwrap();
}
