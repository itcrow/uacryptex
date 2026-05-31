//! SHA-1 via the `sha1` crate.

use sha1::{Digest, Sha1};

/// One-shot SHA-1 digest (20 bytes).
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Incremental SHA-1 over multiple chunks (Cryptonite `sha1_update` pattern).
pub fn sha1_digest_chunks(chunks: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}
