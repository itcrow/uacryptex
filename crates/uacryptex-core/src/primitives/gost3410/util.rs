//! Shared byte/word helpers for GOST 34.10-94.

use crate::math::WordArray;

use super::params::MODULE_BYTES;

pub fn load_be_scalar(bytes: &[u8], word_len: usize) -> WordArray {
    let mut padded = bytes.to_vec();
    if padded.len() < MODULE_BYTES {
        let mut prefix = vec![0u8; MODULE_BYTES - padded.len()];
        prefix.extend_from_slice(&padded);
        padded = prefix;
    } else if padded.len() > MODULE_BYTES {
        padded = padded[padded.len() - MODULE_BYTES..].to_vec();
    }
    let mut wa = WordArray::from_be_bytes(&padded);
    wa.change_len(word_len);
    wa
}

pub fn wa_to_be_module(w: &WordArray) -> Vec<u8> {
    let mut out = w.to_le_bytes();
    if out.len() > MODULE_BYTES {
        out.truncate(MODULE_BYTES);
    }
    out.reverse();
    if out.len() < MODULE_BYTES {
        let mut padded = vec![0u8; MODULE_BYTES - out.len()];
        padded.extend(out);
        out = padded;
    }
    out
}
