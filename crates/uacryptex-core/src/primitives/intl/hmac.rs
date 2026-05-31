//! HMAC via RustCrypto (`hmac` + hash crates).

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use super::md5::md5_digest;

type HmacSha1 = Hmac<Sha1>;
type HmacSha224 = Hmac<Sha224>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha224(key: &[u8], data: &[u8]) -> [u8; 28] {
    let mut mac = HmacSha224::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// MD5-HMAC (bluejekyll `md5` crate has no `Digest` type for `hmac`).
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..16].copy_from_slice(&md5_digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut inner = [IPAD; BLOCK];
    for (i, b) in k.iter().enumerate() {
        inner[i] ^= b;
    }
    let mut inner_msg = inner.to_vec();
    inner_msg.extend_from_slice(data);
    let inner_hash = md5_digest(&inner_msg);

    let mut outer = [OPAD; BLOCK];
    for (i, b) in k.iter().enumerate() {
        outer[i] ^= b;
    }
    let mut outer_msg = outer.to_vec();
    outer_msg.extend_from_slice(&inner_hash);
    md5_digest(&outer_msg)
}
