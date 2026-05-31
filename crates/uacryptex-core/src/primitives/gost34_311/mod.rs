//! GOST R 34.11-94 hash (GOST 34.311, Cryptonite port).

use crate::primitives::byte_utils::{uint32_to_uint8, uint8_to_uint32};
use crate::primitives::gost28147::{base_cycle32, Gost28147};
use crate::{Error, Result};

const BLOCK_LEN: usize = 32;

#[inline]
fn copy_keys(x1: u32, x2: u32, x3: u32, x4: u32) -> (u32, u32, u32, u32) {
    let y1 = (x1 & 0xff) ^ ((x2 & 0xff) << 8) ^ ((x3 & 0xff) << 16) ^ ((x4 & 0xff) << 24);
    let y2 = ((x1 & 0xff00) >> 8) ^ (x2 & 0xff00) ^ ((x3 & 0xff00) << 8) ^ ((x4 & 0xff00) << 16);
    let y3 =
        ((x1 & 0xff0000) >> 16) ^ ((x2 & 0xff0000) >> 8) ^ (x3 & 0xff0000) ^ ((x4 & 0xff0000) << 8);
    let y4 = ((x1 & 0xff000000) >> 24)
        ^ ((x2 & 0xff000000) >> 16)
        ^ ((x3 & 0xff000000) >> 8)
        ^ (x4 & 0xff000000);
    (y1, y2, y3, y4)
}

#[inline]
fn read_u16_le(buf: &[u8], index: usize) -> u16 {
    let off = index * 2;
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn write_u16_le(buf: &mut [u8], index: usize, value: u16) {
    let bytes = value.to_le_bytes();
    let off = index * 2;
    buf[off] = bytes[0];
    buf[off + 1] = bytes[1];
}

fn mix_transform(a_buf: &[u8], b_buf: &[u8], c_buf: &[u8], out8: &mut [u8]) {
    let a = |i| read_u16_le(a_buf, i);
    let b = |i| read_u16_le(b_buf, i);
    let c = |i| read_u16_le(c_buf, i);

    let (a0, a1, a2, a3, a4, a5, a6, a7) = (a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7));
    let (a8v, a9, a10, a11, a12, a13, a14, a15) =
        (a(8), a(9), a(10), a(11), a(12), a(13), a(14), a(15));
    let (b0, b1, b2, b3, b4, b5, b6, b7) = (b(0), b(1), b(2), b(3), b(4), b(5), b(6), b(7));
    let (b8v, b9, b10, b11, b12, b13, b14, b15) =
        (b(8), b(9), b(10), b(11), b(12), b(13), b(14), b(15));
    let (c0, c1, c2, c3, c4, c5, c6, c7) = (c(0), c(1), c(2), c(3), c(4), c(5), c(6), c(7));
    let (c8v, c9, c10, c11, c12, c13, c14, c15) =
        (c(8), c(9), c(10), c(11), c(12), c(13), c(14), c(15));

    let mut p1 = a1 ^ a4 ^ b1 ^ b5;
    let p2 = a3 ^ a5 ^ a6 ^ a12 ^ b4 ^ b6 ^ b7 ^ b13;
    let mut p3 = a6 ^ a13 ^ b3 ^ b7 ^ b14;
    let p4 = a0 ^ a4 ^ a8v ^ a13 ^ a14 ^ b1 ^ b5 ^ b9 ^ b14 ^ b15 ^ c2 ^ c3 ^ c7 ^ c10 ^ c12 ^ c15;
    let mut p5 = a1 ^ a7 ^ a10 ^ a13 ^ a14 ^ b8v ^ b11 ^ b14 ^ c5 ^ c13;
    let p6 = p1 ^ a8v ^ a11 ^ a14 ^ b9 ^ c6 ^ c7 ^ c10 ^ c13 ^ c14;
    let p7 = p5 ^ a3 ^ a11 ^ b1 ^ b4 ^ c1 ^ c6 ^ c9 ^ c12 ^ c14;
    let p8 = p3 ^ a1 ^ a5 ^ a10 ^ b6 ^ b11 ^ b12 ^ c0 ^ c10;

    p1 ^= a5 ^ a9 ^ a15 ^ b0 ^ b6 ^ b10 ^ b12 ^ c1 ^ c2 ^ c4 ^ c8v ^ c11 ^ c15;
    p3 ^= a3 ^ a7 ^ a12 ^ a15 ^ b0 ^ b2 ^ b4 ^ b8v ^ b13 ^ c2 ^ c14;
    p5 ^= a5 ^ a9 ^ a12 ^ a15 ^ b0 ^ b6 ^ b10 ^ b13;

    write_u16_le(out8, 0, p7 ^ a15 ^ b0 ^ b3 ^ c7 ^ c10 ^ c11 ^ c15);
    write_u16_le(
        out8,
        1,
        p6 ^ a0 ^ a3 ^ b2 ^ b4 ^ b12 ^ b15 ^ c0 ^ c1 ^ c3 ^ c8v ^ c11,
    );
    write_u16_le(out8, 2, p1 ^ a2 ^ a12 ^ b13 ^ b15 ^ c7 ^ c9 ^ c12 ^ c14);
    write_u16_le(
        out8,
        3,
        p8 ^ a0 ^ a12 ^ a15 ^ b0 ^ b13 ^ b15 ^ c1 ^ c5 ^ c8v ^ c9 ^ c13,
    );
    write_u16_le(out8, 4, p3 ^ a0 ^ a11 ^ a14 ^ c1 ^ c6 ^ c9 ^ c10 ^ c11);
    write_u16_le(out8, 5, p4 ^ a2 ^ a3 ^ a7 ^ b3 ^ b4 ^ b8v ^ c11);
    write_u16_le(out8, 6, p1 ^ a3 ^ a8v ^ a14 ^ b3 ^ b4 ^ b9 ^ c0 ^ c13);
    write_u16_le(
        out8,
        7,
        p2 ^ a0 ^ a1 ^ a4 ^ a9 ^ a10 ^ b1 ^ b2 ^ b5 ^ b10 ^ b11 ^ c0 ^ c5 ^ c9 ^ c14 ^ c15,
    );
    write_u16_le(
        out8,
        8,
        p8 ^ a2 ^ a4 ^ a7 ^ a11 ^ b2 ^ b5 ^ b8v ^ c2 ^ c3 ^ c6 ^ c12,
    );
    write_u16_le(
        out8,
        9,
        p2 ^ a2 ^ a7 ^ a8v ^ a11 ^ a14 ^ b3 ^ b8v ^ b9 ^ b12 ^ b15 ^ c1 ^ c3 ^ c4 ^ c7 ^ c11 ^ c13,
    );
    write_u16_le(
        out8,
        10,
        p3 ^ a4 ^ a8v ^ a9 ^ b1 ^ b5 ^ b9 ^ b10 ^ b12 ^ b15 ^ c4 ^ c5 ^ c8v ^ c12,
    );
    write_u16_le(
        out8,
        11,
        p5 ^ a0 ^ a2 ^ a3 ^ a4 ^ a8v ^ b4 ^ b5 ^ b9 ^ b12 ^ c3 ^ c6 ^ c9 ^ c15,
    );
    write_u16_le(
        out8,
        12,
        p4 ^ a5
            ^ a6
            ^ a9
            ^ a10
            ^ a11
            ^ a12
            ^ b6
            ^ b7
            ^ b10
            ^ b11
            ^ b12
            ^ b13
            ^ c0
            ^ c1
            ^ c4
            ^ c6
            ^ c14,
    );
    write_u16_le(
        out8,
        13,
        p5 ^ a6 ^ a11 ^ b1 ^ b3 ^ b7 ^ c0 ^ c4 ^ c7 ^ c8v ^ c11 ^ c12,
    );
    write_u16_le(
        out8,
        14,
        p7 ^ a0 ^ a6 ^ a8v ^ b2 ^ b7 ^ b9 ^ b12 ^ b15 ^ c8v,
    );
    write_u16_le(
        out8,
        15,
        p6 ^ a2 ^ a7 ^ a9 ^ a12 ^ a15 ^ b0 ^ b8v ^ b10 ^ b13 ^ c2 ^ c9 ^ c15,
    );
}

fn generate_keys(h32: &[u32; 8], m32: &[u32; 8]) -> [u32; 32] {
    let mut k = [0u32; 32];

    let (y0, y1, y2, y3) = copy_keys(
        h32[0] ^ m32[0],
        h32[2] ^ m32[2],
        h32[4] ^ m32[4],
        h32[6] ^ m32[6],
    );
    k[0] = y0;
    k[1] = y1;
    k[2] = y2;
    k[3] = y3;

    let (y0, y1, y2, y3) = copy_keys(
        h32[1] ^ m32[1],
        h32[3] ^ m32[3],
        h32[5] ^ m32[5],
        h32[7] ^ m32[7],
    );
    k[4] = y0;
    k[5] = y1;
    k[6] = y2;
    k[7] = y3;

    let k0 = h32[2] ^ m32[4];
    let k1 = h32[4] ^ m32[6];
    let k2 = h32[6] ^ m32[0] ^ m32[2];
    let k3 = h32[0] ^ m32[2] ^ k0;
    let (y0, y1, y2, y3) = copy_keys(k0, k1, k2, k3);
    k[8] = y0;
    k[9] = y1;
    k[10] = y2;
    k[11] = y3;

    let k0 = h32[3] ^ m32[5];
    let k1 = h32[5] ^ m32[7];
    let k2 = h32[7] ^ m32[1] ^ m32[3];
    let k3 = h32[1] ^ m32[3] ^ k0;
    let (y0, y1, y2, y3) = copy_keys(k0, k1, k2, k3);
    k[12] = y0;
    k[13] = y1;
    k[14] = y2;
    k[15] = y3;

    let mut k0 = h32[4] ^ m32[0] ^ m32[2];
    let mut k1 = h32[2] ^ m32[6];
    let mut k2 = k1 ^ h32[0] ^ m32[4] ^ 0x00ffff00;
    let mut k3 = k0 ^ k1 ^ 0x000000ff;
    k0 ^= 0xff00ff00;
    k1 = h32[6] ^ m32[2] ^ m32[4] ^ 0x00ff00ff;
    let (y0, y1, y2, y3) = copy_keys(k0, k1, k2, k3);
    k[16] = y0;
    k[17] = y1;
    k[18] = y2;
    k[19] = y3;

    k0 = h32[5] ^ m32[1] ^ m32[3];
    k1 = h32[3] ^ m32[7];
    k2 = k1 ^ h32[1] ^ m32[5] ^ 0xff0000ff;
    k3 = k0 ^ k1 ^ 0xff00ffff;
    k0 ^= 0xff00ff00;
    k1 = h32[7] ^ m32[3] ^ m32[5] ^ 0x00ff00ff;
    let (y0, y1, y2, y3) = copy_keys(k0, k1, k2, k3);
    k[20] = y0;
    k[21] = y1;
    k[22] = y2;
    k[23] = y3;

    k0 = h32[6] ^ m32[6];
    k3 = k0 ^ h32[4] ^ m32[2] ^ 0xffffffff;
    k0 ^= m32[4] ^ 0x00ff00ff;
    k1 = h32[2] ^ m32[0];
    k2 = k1 ^ h32[4] ^ m32[4] ^ 0x000000ff;
    k1 ^= h32[0] ^ m32[2] ^ m32[6] ^ 0x00ffff00;
    let (y0, y1, y2, y3) = copy_keys(k0, k1, k2, k3);
    k[24] = y0;
    k[25] = y1;
    k[26] = y2;
    k[27] = y3;

    k0 = h32[7] ^ m32[7];
    k3 = k0 ^ h32[5] ^ m32[3] ^ 0xffffffff;
    k0 ^= m32[5] ^ 0x00ff00ff;
    k1 = h32[3] ^ m32[1];
    k2 = k1 ^ h32[5] ^ m32[5] ^ 0xff00ffff;
    k1 ^= h32[1] ^ m32[3] ^ m32[7] ^ 0xff0000ff;
    let (y0, y1, y2, y3) = copy_keys(k0, k1, k2, k3);
    k[28] = y0;
    k[29] = y1;
    k[30] = y2;
    k[31] = y3;

    k
}

fn add(a: &mut [u32; 8], b: &[u32; 8]) {
    let mut carry = 0u64;
    for i in 0..8 {
        carry = a[i] as u64 + b[i] as u64 + (carry >> 32);
        a[i] = carry as u32;
    }
}

/// GOST 34.311 hash context.
pub struct Gost34311 {
    gost: Gost28147,
    m32: [u8; BLOCK_LEN],
    m32_ind: usize,
    m_bit_len: [u32; 8],
    sync: [u8; BLOCK_LEN],
    sigma: [u32; 8],
    hash: [u8; BLOCK_LEN],
}

impl Gost34311 {
    /// `gost34_311_alloc(GOST28147_SBOX_ID_1, sync)`.
    pub fn new(sync: &[u8]) -> Result<Self> {
        if sync.len() != BLOCK_LEN {
            return Err(Error::InvalidParam(format!(
                "gost34_311 sync must be {BLOCK_LEN} bytes"
            )));
        }
        let mut ctx = Self {
            gost: Gost28147::new(),
            m32: [0; BLOCK_LEN],
            m32_ind: 0,
            m_bit_len: [0; 8],
            sync: [0; BLOCK_LEN],
            sigma: [0; 8],
            hash: [0; BLOCK_LEN],
        };
        ctx.sync.copy_from_slice(sync);
        ctx.reset();
        Ok(ctx)
    }

    /// `gost34_311_alloc_user_sbox`.
    pub fn with_user_sbox(sync: &[u8], sbox: &[u8; 128]) -> Result<Self> {
        if sync.len() != BLOCK_LEN {
            return Err(Error::InvalidParam(format!(
                "gost34_311 sync must be {BLOCK_LEN} bytes"
            )));
        }
        let mut ctx = Self {
            gost: Gost28147::from_raw_sbox(sbox),
            m32: [0; BLOCK_LEN],
            m32_ind: 0,
            m_bit_len: [0; 8],
            sync: [0; BLOCK_LEN],
            sigma: [0; 8],
            hash: [0; BLOCK_LEN],
        };
        ctx.sync.copy_from_slice(sync);
        ctx.reset();
        Ok(ctx)
    }

    fn reset(&mut self) {
        self.sigma.fill(0);
        self.m_bit_len.fill(0);
        self.m32.fill(0);
        self.hash.copy_from_slice(&self.sync);
        self.m32_ind = 0;
    }

    fn hash_step(&mut self, m: &[u8]) -> Result<()> {
        let mut hash32 = [0u32; 8];
        let mut m32 = [0u32; 8];
        uint8_to_uint32(&self.hash, &mut hash32);
        uint8_to_uint32(m, &mut m32);

        let keys = generate_keys(&hash32, &m32);
        base_cycle32(self.gost.sbox(), &mut hash32, &keys);

        let mut s = [0u8; BLOCK_LEN];
        uint32_to_uint8(&hash32, &mut s);

        let mut new_hash = [0u8; BLOCK_LEN];
        mix_transform(&self.hash, m, &s, &mut new_hash);
        self.hash.copy_from_slice(&new_hash);
        Ok(())
    }

    fn update_block(&mut self) -> Result<()> {
        let block = self.m32;
        self.hash_step(&block)?;

        self.m_bit_len[0] = self.m_bit_len[0].wrapping_add(256);
        if self.m_bit_len[0] < 256 {
            for word in self.m_bit_len.iter_mut().skip(1) {
                *word = word.wrapping_add(1);
                if *word != 0 {
                    break;
                }
            }
        }

        let mut m32 = [0u32; 8];
        uint8_to_uint32(&self.m32, &mut m32);
        add(&mut self.sigma, &m32);
        Ok(())
    }

    /// `gost34_311_update`.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let mut buf = data;
        loop {
            let room = BLOCK_LEN - self.m32_ind;
            let take = room.min(buf.len());
            self.m32[self.m32_ind..self.m32_ind + take].copy_from_slice(&buf[..take]);
            self.m32_ind += take;
            buf = &buf[take..];

            if buf.is_empty() {
                break;
            }

            self.update_block()?;
            self.m32_ind = 0;
        }
        Ok(())
    }

    /// `gost34_311_final` — returns digest and resets the context (Cryptonite behavior).
    pub fn final_hash(&mut self) -> Result<[u8; BLOCK_LEN]> {
        let bit = (self.m32_ind << 3) as u32;
        self.m_bit_len[0] = self.m_bit_len[0].wrapping_add(bit);
        if self.m_bit_len[0] < bit {
            for word in self.m_bit_len.iter_mut().skip(1) {
                *word = word.wrapping_add(1);
                if *word != 0 {
                    break;
                }
            }
        }

        self.m32[self.m32_ind..].fill(0);

        let mut m32 = [0u32; 8];
        uint8_to_uint32(&self.m32, &mut m32);
        add(&mut self.sigma, &m32);
        m32.fill(0);

        let block = self.m32;
        self.hash_step(&block)?;

        let mut m_bit_len = [0u8; BLOCK_LEN];
        uint32_to_uint8(&self.m_bit_len, &mut m_bit_len);
        self.hash_step(&m_bit_len)?;

        let mut sigma8 = [0u8; BLOCK_LEN];
        uint32_to_uint8(&self.sigma, &mut sigma8);
        self.hash_step(&sigma8)?;

        let out = self.hash;
        self.reset();
        Ok(out)
    }
}

const HMAC_BLOCK_LEN: usize = 32;

/// GOST 34.311 HMAC (`hmac_alloc_gost34_311`, block size 32).
pub fn hmac_gost3411(
    sync: &[u8; BLOCK_LEN],
    key: &[u8],
    data: &[&[u8]],
) -> Result<[u8; BLOCK_LEN]> {
    let key_block = if key.len() > HMAC_BLOCK_LEN {
        let mut hasher = Gost34311::new(sync)?;
        hasher.update(key)?;
        hasher.final_hash()?
    } else {
        let mut block = [0u8; HMAC_BLOCK_LEN];
        block[..key.len()].copy_from_slice(key);
        block
    };

    let mut ipad = key_block;
    let mut opad = key_block;
    for i in 0..HMAC_BLOCK_LEN {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    let mut inner = Gost34311::new(sync)?;
    inner.update(&ipad)?;
    for chunk in data {
        inner.update(chunk)?;
    }
    let inner_hash = inner.final_hash()?;

    let mut outer = Gost34311::new(sync)?;
    outer.update(&opad)?;
    outer.update(&inner_hash)?;
    outer.final_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hmac_gost3411_matches_cryptonite_utest() {
        let sync = [0u8; 32];
        let data1 = hex("CF818CADDFBDCDC940C8A530947427ED1A27949062602DA471ADA0D5CBFF32D8");
        let data2 = hex("00000001");
        let key = b"dn310786dmi1";
        let expected = hex("20df9d6f41f32160b77b4d9394257bee5f71adf35025083e52bfa680296a2f15");

        let actual = hmac_gost3411(&sync, key, &[&data1, &data2]).unwrap();
        assert_eq!(&actual[..], expected.as_slice());
    }

    #[test]
    fn hash_test_1_zero_sync_matches_cryptonite_utest() {
        let sync = hex("0000000000000000000000000000000000000000000000000000000000000000");
        let data = hex("ad26f436f0b627880038727d22e02c97d081ef85260fc96718395091ce224dd7");
        let expected = hex("02d7e8a3c111788bb1b8a489c5e330288728f1c308c2cec08e09265bfa395599");

        let mut ctx = Gost34311::new(&sync).unwrap();
        ctx.update(&data).unwrap();
        let actual = ctx.final_hash().unwrap();
        assert_eq!(&actual[..], expected.as_slice());
    }

    #[test]
    fn hash_test_2_nonzero_sync_matches_cryptonite_utest() {
        let sync = hex("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
        let data = hex("cd944dc9951b5e1eea4a9ebca4e30e4568d48f640d9b228e2df398f767b4eaab");
        let expected = hex("30667bae2a36245ce8abd0e8f84812df7ffd7dfee6289ef6d79624d709f97208");

        let mut ctx = Gost34311::new(&sync).unwrap();
        ctx.update(&data).unwrap();
        let actual = ctx.final_hash().unwrap();
        assert_eq!(&actual[..], expected.as_slice());
    }

    #[test]
    fn hash_test_3_unaligned_message_matches_cryptonite_utest() {
        let sync = hex("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
        let data = hex(
            "9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691d9e4abc889632959d73e0bf139cd71813ebee679e930",
        );
        let expected = hex("9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30");

        let mut ctx = Gost34311::new(&sync).unwrap();
        ctx.update(&data).unwrap();
        let actual = ctx.final_hash().unwrap();
        assert_eq!(&actual[..], expected.as_slice());
    }

    #[test]
    fn hash_test_4_chunked_update_matches_cryptonite_utest() {
        let sync = hex("975ad259b935b5c492e24dd1cc24e0ee8c4c11255c5aa3244119cc3386b10b0a");
        let data1 = hex("9f4f3dfc4dfe5d7b425ece1fb62c81f3795e746d72ee40139e8691");
        let data2 = hex("d9e4abc889632959d73e0bf139cd71813ebee679e9");
        let data3 = hex("30");
        let expected = hex("9d82d03e369b476ecc15cc8b9c73906cd395b63825b5b667a6cb62013788be30");

        let mut ctx = Gost34311::new(&sync).unwrap();
        ctx.update(&data1).unwrap();
        ctx.update(&data2).unwrap();
        ctx.update(&data3).unwrap();
        let actual = ctx.final_hash().unwrap();
        assert_eq!(&actual[..], expected.as_slice());
    }
}
