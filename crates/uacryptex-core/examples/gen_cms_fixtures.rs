//! One-shot CMS fixture generator: `cargo run -p uacryptex-core --example gen_cms_fixtures`

use std::fs;
use std::path::PathBuf;

use der::asn1::SetOfVec;
use der::Encode;
use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::{
    build_signed_data, content_type_attribute, message_digest_attribute,
};
use uacryptex_core::pki::crypto::{DigestAdapter, SignAdapter};
use uacryptex_core::pki::oid::OidId;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki");
    fs::create_dir_all(&root).unwrap();

    let cert = Cert::decode(include_bytes!("../../../testdata/pki/certificate257.der")).unwrap();
    let private_key: [u8; 32] = [
        0x7B, 0x66, 0xB6, 0x2C, 0x23, 0x67, 0x3C, 0x12, 0x99, 0xB8, 0x4A, 0xE4, 0xAA, 0xCF,
        0xBB, 0xCA, 0x1C, 0x50, 0xFC, 0x13, 0x4A, 0x84, 0x6E, 0xF2, 0xE2, 0x4A, 0x37, 0x40,
        0x7D, 0x01, 0xD3, 0x2A,
    ];
    let content = b"\xd0\xa1\xd1\x82\xd0\xb0\xd1\x82\xd1\x83\xd1\x81 \xd0\xbf\xd0\xbe\xd0\xb2\xd1\x96\xd0\xb4\xd0\xbe\xd0\xbc\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xbd\xd1\x8f";

    let sa = SignAdapter::init_by_cert(&private_key, &cert).unwrap();
    let signed_data = build_signed_data(&sa, content, OidId::Data).unwrap();
    fs::write(root.join("signed_data.dat"), signed_data.encode().unwrap()).unwrap();
    fs::copy(root.join("certificate257.der"), root.join("test_sign.cer")).unwrap();

    let mut da = DigestAdapter::init_by_cert(&cert).unwrap();
    da.update(content).unwrap();
    let digest = da.finalize().unwrap();
    let attrs = vec![
        content_type_attribute(OidId::Data).unwrap(),
        message_digest_attribute(&digest).unwrap(),
    ];
    let signed_attrs = SetOfVec::try_from(attrs).unwrap();
    let signed_attrs_der = signed_attrs.to_der().unwrap();
    fs::write(root.join("test_cms_signed_attr.der"), &signed_attrs_der).unwrap();
    fs::write(
        root.join("test_cms_sign.dat"),
        sa.sign_data(&signed_attrs_der).unwrap(),
    )
    .unwrap();

    println!("wrote CMS fixtures to {}", root.display());
}
