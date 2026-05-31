//! MD5 via the `md5` crate.

use md5::Context;

/// One-shot MD5 digest (16 bytes).
pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    md5::compute(data).into()
}

/// Incremental MD5 over multiple chunks (Cryptonite `md5_update` pattern).
pub fn md5_digest_chunks(chunks: &[&[u8]]) -> [u8; 16] {
    let mut ctx = Context::new();
    for chunk in chunks {
        ctx.consume(chunk);
    }
    ctx.finalize().into()
}
