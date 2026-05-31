//! SHA-2 family via the `sha2` crate.

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

pub fn sha224_digest(data: &[u8]) -> [u8; 28] {
    let mut h = Sha224::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha384_digest(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha512_digest(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// Incremental digest (Cryptonite `test_sha2_core`: 1 + 1 + (len−2) byte updates).
pub fn sha224_digest_chunks(chunks: &[&[u8]]) -> [u8; 28] {
    let mut h = Sha224::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

pub fn sha256_digest_chunks(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

pub fn sha384_digest_chunks(chunks: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

pub fn sha512_digest_chunks(chunks: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}
