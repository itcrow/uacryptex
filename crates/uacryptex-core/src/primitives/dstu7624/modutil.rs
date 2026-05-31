//! Shared helpers for DSTU 7624 modes (padding, GF(2^m) multiply).

use crate::error::Result;
use crate::math::{gf2m_mod_mul, Gf2mCtx, WordArray};

use super::core::{BLOCK_128, BLOCK_256, BLOCK_512};

/// ISO 7816-4 padding (Cryptonite `padding`). Returns `true` if padding was applied.
pub fn kalyna_padding(data: &mut [u8], data_len: &mut usize, block_len: usize) -> bool {
    let padded_byte = block_len - *data_len % block_len;
    if *data_len % block_len != 0 {
        data[*data_len] = 0x80;
        for b in data.iter_mut().skip(*data_len + 1).take(padded_byte - 1) {
            *b = 0;
        }
        *data_len += padded_byte;
        true
    } else {
        false
    }
}

/// ISO 7816-4 unpadding (Cryptonite `unpadding`). Returns new length or `None` on error.
pub fn kalyna_unpadding(data: &[u8], data_len: &mut usize) -> Option<()> {
    if *data_len == 0 {
        return None;
    }
    let mut i = *data_len - 1;
    while i > 0 && data[i] == 0 {
        i -= 1;
    }
    if i == 0 || i == *data_len - 1 {
        return None;
    }
    *data_len = i + 1;
    Some(())
}

pub fn gf2m_ctx_for_block_len(block_len: usize) -> Gf2mCtx {
    let f: [i32; 5] = match block_len {
        BLOCK_128 => [128, 7, 2, 1, 0],
        BLOCK_256 => [256, 10, 5, 2, 0],
        BLOCK_512 => [512, 8, 5, 2, 0],
        _ => panic!("unsupported block length for GF(2^m)"),
    };
    Gf2mCtx::new(&f)
}

/// Port of Cryptonite `gf2m_mul`.
pub fn gf2m_mul_bytes(
    ctx: &Gf2mCtx,
    block_len: usize,
    arg1: &[u8],
    arg2: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let mut wa_arg1 = WordArray::from_le_bytes(&arg1[..block_len]);
    let mut wa_arg2 = WordArray::from_le_bytes(&arg2[..block_len]);
    let mod_len = ctx.len;
    let old_len = wa_arg1.len();
    let mut wa_res = WordArray::with_zero(mod_len);
    wa_arg1.change_len(mod_len);
    wa_arg2.change_len(mod_len);
    gf2m_mod_mul(ctx, &wa_arg1, &wa_arg2, &mut wa_res);
    wa_res.buf.truncate(old_len);
    let bytes = wa_res.to_le_bytes_len(block_len);
    out[..block_len].copy_from_slice(&bytes);
    Ok(())
}

/// XOR two buffers into a new buffer (avoids in-place borrow issues).
pub fn kalyna_xor_to(a: &[u8], b: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    super::core::kalina_xor_bytes(a, b, len, &mut out);
    out
}

/// GF(2^m) multiply returning a new buffer.
pub fn gf2m_mul_to(ctx: &Gf2mCtx, block_len: usize, arg1: &[u8], arg2: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; block_len];
    gf2m_mul_bytes(ctx, block_len, arg1, arg2, &mut out)?;
    Ok(out)
}

pub fn bytes_to_u64_words(in_bytes: &[u8], out: &mut [u64]) {
    for (i, chunk) in in_bytes.chunks(8).enumerate() {
        if i >= out.len() {
            break;
        }
        let mut b = [0u8; 8];
        let take = chunk.len().min(8);
        b[..take].copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(b);
    }
}

pub fn u64_words_to_bytes(words: &[u64], out: &mut [u8]) {
    let src_len = words.len() * 8;
    let n = out.len().min(src_len);
    for (i, &word) in words.iter().enumerate() {
        let bytes = word.to_le_bytes();
        let off = i * 8;
        if off >= n {
            break;
        }
        let take = (n - off).min(8);
        out[off..off + take].copy_from_slice(&bytes[..take]);
    }
}
