//! International algorithms via [RustCrypto](https://github.com/RustCrypto) (delegation + KAT cross-check).

mod aes;
mod des;
mod ecdsa;
mod hmac;
mod md5;
mod rsa;
mod rsa_oaep;
mod sha1;
mod sha2;

pub use aes::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_cfb_decrypt, aes_cfb_encrypt, aes_ctr_crypt,
    aes_ecb_decrypt, aes_ecb_encrypt, aes_ofb_crypt,
};
pub use des::{des_ecb_decrypt, des_ecb_encrypt, tdes_ecb_decrypt, tdes_ecb_encrypt};
pub use ecdsa::{
    build_ecdsa_spki_der, ecdsa_curve_from_oid_str, ecdsa_public_key_from_private,
    ecdsa_public_key_from_spki, ecdsa_sign, ecdsa_verify, is_ecdsa_signature_oid,
    validate_private_key as ecdsa_validate_private_key, EcdsaCurve,
    ecdsa_verify_p192, ecdsa_verify_p224, ecdsa_verify_p256, ecdsa_verify_p384,
    ecdsa_verify_p521,
};
pub use hmac::{hmac_md5, hmac_sha1, hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512};
pub use md5::{md5_digest, md5_digest_chunks};
pub use rsa::{
    rsa_pkcs1_v15_sign_sha1, rsa_pkcs1_v15_sign_sha256, rsa_pkcs1_v15_sign_sha384,
    rsa_pkcs1_v15_sign_sha512, rsa_pkcs1_v15_verify_sha1, rsa_pkcs1_v15_verify_sha256,
    rsa_pkcs1_v15_verify_sha384, rsa_pkcs1_v15_verify_sha512,
};
pub use rsa_oaep::{rsa_oaep_decrypt, rsa_oaep_encrypt, rsa_oaep_modulus_valid, RsaOaepHash};
pub use sha1::{sha1_digest, sha1_digest_chunks};
pub use sha2::{
    sha224_digest, sha224_digest_chunks, sha256_digest, sha256_digest_chunks, sha384_digest,
    sha384_digest_chunks, sha512_digest, sha512_digest_chunks,
};
