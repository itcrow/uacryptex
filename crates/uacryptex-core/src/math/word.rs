//! Multi-precision word arrays (Cryptonite `WordArray`, ARCH64).

pub const WORD_BIT_LENGTH: usize = 64;
pub const WORD_BIT_LEN_MASK: u64 = 0x3f;
pub const WORD_BIT_LEN_SHIFT: u32 = 6;
pub const WORD_BYTE_LENGTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WordArray {
    pub buf: Vec<u64>,
}

impl WordArray {
    pub fn with_zero(len: usize) -> Self {
        Self { buf: vec![0; len] }
    }

    pub fn with_one(len: usize) -> Self {
        let mut buf = vec![0; len];
        if len > 0 {
            buf[0] = 1;
        }
        Self { buf }
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        let len = wa_len(bytes.len());
        let mut buf = vec![0u64; len];
        for (i, chunk) in bytes.chunks(WORD_BYTE_LENGTH).enumerate() {
            let mut word = [0u8; WORD_BYTE_LENGTH];
            word[..chunk.len()].copy_from_slice(chunk);
            buf[i] = u64::from_le_bytes(word);
        }
        Self { buf }
    }

    /// Load field/scalar octets in Cryptonite big-endian `ByteArray` order.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut le = bytes.to_vec();
        le.reverse();
        Self::from_le_bytes(&le)
    }

    pub fn copy_from_slice(&mut self, other: &WordArray) {
        self.buf.copy_from_slice(&other.buf);
    }

    pub fn zero(&mut self) {
        self.buf.fill(0);
    }

    pub fn set_one(&mut self) {
        self.buf.fill(0);
        if !self.buf.is_empty() {
            self.buf[0] = 1;
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn change_len(&mut self, len: usize) {
        self.buf.resize(len, 0);
    }

    pub fn copy_from(&mut self, other: &WordArray) {
        assert!(self.buf.len() >= other.buf.len());
        self.buf[..other.buf.len()].copy_from_slice(&other.buf);
        if self.buf.len() > other.buf.len() {
            self.buf[other.buf.len()..].fill(0);
        }
    }

    /// Cryptonite `wa_copy`: copy `other` into `self`, zeroing any trailing words.
    pub fn copy_to(&self, out: &mut WordArray) {
        assert!(self.buf.len() <= out.buf.len());
        out.buf[..self.buf.len()].copy_from_slice(&self.buf);
        if out.buf.len() > self.buf.len() {
            out.buf[self.buf.len()..].fill(0);
        }
    }

    /// Cryptonite `wa_copy_part`: copy `len` words from `self.buf[off..]`.
    pub fn copy_part(&self, off: usize, len: usize, out: &mut WordArray) {
        assert!(self.buf.len() >= off + len);
        assert_eq!(out.buf.len(), len);
        out.buf.copy_from_slice(&self.buf[off..off + len]);
    }

    pub fn copy_part_from(&mut self, other: &WordArray, off: usize) {
        let len = self.buf.len();
        assert!(len + off <= other.buf.len());
        self.buf.copy_from_slice(&other.buf[off..off + len]);
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len() * WORD_BYTE_LENGTH);
        for &w in &self.buf {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn to_le_bytes_len(&self, byte_len: usize) -> Vec<u8> {
        let mut out = self.to_le_bytes();
        out.truncate(byte_len);
        out
    }

    pub fn swap_words(&self, out: &mut WordArray) {
        assert_eq!(self.buf.len(), out.buf.len());
        for i in 0..self.buf.len() {
            out.buf[i] = self.buf[self.buf.len() - 1 - i];
        }
    }
}

pub fn wa_len(bytes: usize) -> usize {
    bytes.div_ceil(WORD_BYTE_LENGTH)
}

pub fn wa_len_from_bits(bits: usize) -> usize {
    bits.div_ceil(WORD_BIT_LENGTH)
}

pub fn word_bit_len(a: u64) -> usize {
    if a == 0 {
        0
    } else {
        WORD_BIT_LENGTH - a.leading_zeros() as usize
    }
}

pub fn wa_cmp(a: &WordArray, b: &WordArray) -> i32 {
    if a.buf.len() != b.buf.len() {
        return (a.buf.len() as i64 - b.buf.len() as i64) as i32;
    }
    for (x, y) in a.buf.iter().zip(b.buf.iter()) {
        match x.cmp(y) {
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
        }
    }
    0
}

pub fn wa_equals(a: &WordArray, b: &WordArray) -> bool {
    a.buf.len() == b.buf.len() && a.buf == b.buf
}
