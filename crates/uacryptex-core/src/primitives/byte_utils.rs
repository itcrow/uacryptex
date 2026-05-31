//! Byte/word helpers matching Cryptonite `byte_utils_internal.c` on little-endian hosts.

/// `uint8_to_uint32`: copy bytes into `u32` words (LE), zero-pad high words.
pub fn uint8_to_uint32(in_bytes: &[u8], out: &mut [u32]) {
    let out_bytes = out.len() * 4;
    let mut buf = [0u8; 32];
    let n = in_bytes.len().min(out_bytes);
    buf[..n].copy_from_slice(&in_bytes[..n]);
    for (i, chunk) in buf[..out_bytes].chunks_exact(4).enumerate() {
        out[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

/// `uint32_to_uint8`: copy `u32` words to bytes (LE), optionally zero-pad.
pub fn uint32_to_uint8(in_words: &[u32], out: &mut [u8]) {
    let src_len = in_words.len() * 4;
    let n = out.len().min(src_len);
    for (i, word) in in_words.iter().enumerate() {
        let bytes = word.to_le_bytes();
        let off = i * 4;
        if off >= n {
            break;
        }
        let take = (n - off).min(4);
        out[off..off + take].copy_from_slice(&bytes[..take]);
    }
    if out.len() > src_len {
        out[src_len..].fill(0);
    }
}

/// `uint64_to_uint8` for a single `u64` (LE).
pub fn uint64_to_uint8(value: u64, out: &mut [u8]) {
    let bytes = value.to_le_bytes();
    let n = out.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    if out.len() > 8 {
        out[8..].fill(0);
    }
}

/// Reverse byte order in place (`uint8_swap` with `in == out`).
pub fn uint8_swap(buf: &mut [u8]) {
    let len = buf.len();
    for i in 0..len / 2 {
        buf.swap(i, len - 1 - i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint8_to_uint32_zero_pads_high_words() {
        let mut out = [0u32; 4];
        uint8_to_uint32(&[0x01, 0x02, 0x03, 0x04, 0x05], &mut out);
        assert_eq!(out[0], 0x04030201);
        assert_eq!(out[1], 0x00000005);
        assert_eq!(out[2], 0);
        assert_eq!(out[3], 0);
    }

    #[test]
    fn uint32_to_uint8_roundtrip() {
        let words = [0x04030201u32, 0x08070605];
        let mut bytes = [0u8; 8];
        uint32_to_uint8(&words, &mut bytes);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let mut out = [0u32; 2];
        uint8_to_uint32(&bytes, &mut out);
        assert_eq!(out, words);
    }

    #[test]
    fn uint64_to_uint8_truncates_and_zero_pads() {
        let mut out = [0xffu8; 12];
        uint64_to_uint8(0x0123456789abcdef, &mut out);
        assert_eq!(&out[..8], &[0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]);
        assert_eq!(&out[8..], &[0, 0, 0, 0]);
    }

    #[test]
    fn uint8_swap_reverses_in_place() {
        let mut buf = [1u8, 2, 3, 4, 5];
        uint8_swap(&mut buf);
        assert_eq!(buf, [5, 4, 3, 2, 1]);
    }
}
