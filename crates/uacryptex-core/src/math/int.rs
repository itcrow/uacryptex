//! Integer helpers on `WordArray` (Cryptonite `math_int_internal` subset).

use super::word::{
    word_bit_len, WordArray, WORD_BIT_LENGTH, WORD_BIT_LEN_MASK, WORD_BIT_LEN_SHIFT,
};

pub fn int_is_zero(a: &WordArray) -> bool {
    a.buf.iter().all(|&w| w == 0)
}

pub fn int_is_one(a: &WordArray) -> bool {
    if a.buf.is_empty() || a.buf[0] != 1 {
        return false;
    }
    a.buf[1..].iter().all(|&w| w == 0)
}

pub fn int_word_len(a: &WordArray) -> usize {
    for i in (0..a.buf.len()).rev() {
        if a.buf[i] != 0 {
            return i + 1;
        }
    }
    1
}

pub fn int_bit_len(a: &WordArray) -> usize {
    let w_len = int_word_len(a);
    if w_len == 0 || (w_len == 1 && a.buf[0] == 0) {
        return 0;
    }
    (w_len - 1) * WORD_BIT_LENGTH + word_bit_len(a.buf[w_len - 1])
}

/// Cryptonite `int_cmp`: lexicographic compare as unsigned big-endian multi-word integer.
pub fn int_cmp(a: &WordArray, b: &WordArray) -> i32 {
    assert!(!a.buf.is_empty() && !b.buf.is_empty());
    let len = a.buf.len().min(b.buf.len());

    for i in (len..a.buf.len()).rev() {
        if a.buf[i] != 0 {
            return 1;
        }
    }
    for i in (len..b.buf.len()).rev() {
        if b.buf[i] != 0 {
            return -1;
        }
    }
    for i in (0..len).rev() {
        if a.buf[i] != b.buf[i] {
            return if a.buf[i] > b.buf[i] { 1 } else { -1 };
        }
    }
    0
}

/// Constant-time equality (no early exit on first differing word).
pub fn int_ct_equals(a: &WordArray, b: &WordArray) -> bool {
    let max_len = a.buf.len().max(b.buf.len());
    let mut diff = 0u64;
    for i in 0..max_len {
        let aw = a.buf.get(i).copied().unwrap_or(0);
        let bw = b.buf.get(i).copied().unwrap_or(0);
        diff |= aw ^ bw;
    }
    diff == 0
}

pub fn int_equals(a: &WordArray, b: &WordArray) -> bool {
    int_ct_equals(a, b)
}

/// Clear all bits at and above `bit_len` (Cryptonite `int_truncate`).
pub fn int_truncate(a: &mut WordArray, bit_len: usize) {
    let word_off = bit_len >> WORD_BIT_LEN_SHIFT;
    if word_off < a.buf.len() {
        let bit = bit_len & WORD_BIT_LEN_MASK as usize;
        if bit == 0 {
            a.buf[word_off] = 0;
        } else {
            a.buf[word_off] &= (1u64 << bit) - 1;
        }
        for w in a.buf.iter_mut().skip(word_off + 1) {
            *w = 0;
        }
    }
}

pub fn int_get_bit(a: &WordArray, bit_num: usize) -> u32 {
    let word_off = bit_num >> WORD_BIT_LEN_SHIFT;
    if word_off >= a.buf.len() {
        return 0;
    }
    ((a.buf[word_off] >> (bit_num as u64 & WORD_BIT_LEN_MASK)) & 1) as u32
}

pub fn int_lshift(a: &WordArray, shift: usize, out: &mut WordArray) {
    assert_eq!(a.buf.len(), out.buf.len());
    let len = a.buf.len();
    let m = shift & WORD_BIT_LEN_MASK as usize;
    let s = WORD_BIT_LENGTH - m;
    let mut j = len as i32 - 1 - (shift >> WORD_BIT_LEN_SHIFT) as i32;
    let mut i = len as i32 - 1;

    if m == 0 {
        while j >= 0 {
            out.buf[i as usize] = a.buf[j as usize];
            i -= 1;
            j -= 1;
        }
    } else {
        while j > 0 {
            out.buf[i as usize] = (a.buf[j as usize] << m) | (a.buf[j as usize - 1] >> s);
            i -= 1;
            j -= 1;
        }
        out.buf[i as usize] = a.buf[j as usize] << m;
        i -= 1;
    }

    while i >= 0 {
        out.buf[i as usize] = 0;
        i -= 1;
    }
}
