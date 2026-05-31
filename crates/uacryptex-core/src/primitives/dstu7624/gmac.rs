//! GMAC mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::KalynaCore;
use super::modutil::{
    bytes_to_u64_words, gf2m_ctx_for_block_len, gf2m_mul_to, kalyna_padding, kalyna_xor_to,
    u64_words_to_bytes,
};

/// GMAC context (S-box 1).
pub struct Dstu7624Gmac {
    core: KalynaCore,
    gf2m: crate::math::Gf2mCtx,
    b: [u64; 8],
    h: [u64; 8],
    last_block: [u8; 64],
    last_block_len: usize,
    msg_tot_len: usize,
    q: usize,
}

impl Dstu7624Gmac {
    pub fn init(key: &[u8], block_size: usize, q: usize) -> Result<Self> {
        if !(8..=block_size).contains(&q) {
            return Err(Error::InvalidParam("q".into()));
        }
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_size)?;
        let w = block_size / 8;
        let mut h = [0u64; 8];
        core.basic_transform_state(&mut h[..w]);

        Ok(Self {
            core,
            gf2m: gf2m_ctx_for_block_len(block_size),
            b: [0; 8],
            h,
            last_block: [0; 64],
            last_block_len: 0,
            msg_tot_len: 0,
            q,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut b8 = vec![0u8; block_len];
        let mut h8 = vec![0u8; block_len];
        u64_words_to_bytes(&self.b[..w], &mut b8);
        u64_words_to_bytes(&self.h[..w], &mut h8);

        let data_buf = data;
        let mut data_len = data.len();
        self.msg_tot_len += data_len;

        if self.last_block_len != 0 {
            if self.last_block_len + data_len < block_len {
                self.last_block[self.last_block_len..self.last_block_len + data_len]
                    .copy_from_slice(data_buf);
                self.last_block_len += data_len;
                return Ok(());
            }
            b8 = kalyna_xor_to(
                &self.last_block[..self.last_block_len],
                &b8,
                self.last_block_len,
            );
            let tail_len = block_len - self.last_block_len;
            let tail = kalyna_xor_to(data_buf, &b8[self.last_block_len..], tail_len);
            b8[self.last_block_len..self.last_block_len + tail_len].copy_from_slice(&tail);
            data_len -= tail_len;
        } else if data_len >= block_len {
            b8 = kalyna_xor_to(&data_buf[..block_len], &b8, block_len);
        } else {
            self.last_block[..data_len].copy_from_slice(data_buf);
            self.last_block_len = data_len;
            return Ok(());
        }

        let tail_len = (block_len - data_len % block_len) % block_len;
        data_len -= tail_len;

        let mut i = 0usize;
        while i < data_len {
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
            if i + block_len < data_len {
                b8 = kalyna_xor_to(&data_buf[i..i + block_len], &b8, block_len);
            }
            i += block_len;
        }

        if tail_len != 0 {
            self.last_block[..tail_len].copy_from_slice(&data_buf[i..i + tail_len]);
            self.last_block_len = tail_len;
        }

        bytes_to_u64_words(&b8, &mut self.b[..w]);
        Ok(())
    }

    pub fn final_mac(&mut self) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut b8 = vec![0u8; block_len];
        let mut h8 = vec![0u8; block_len];
        u64_words_to_bytes(&self.b[..w], &mut b8);
        u64_words_to_bytes(&self.h[..w], &mut h8);

        if self.last_block_len != 0 {
            let mut last = self.last_block;
            let mut last_len = self.last_block_len;
            kalyna_padding(&mut last, &mut last_len, block_len);
            b8 = kalyna_xor_to(&last[..last_len], &b8, last_len);
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
        }

        let mut h = [0u64; 8];
        h[0] = (self.msg_tot_len as u64) << 3;
        u64_words_to_bytes(&h[..w], &mut h8);
        h8 = kalyna_xor_to(&h8, &b8, block_len);
        bytes_to_u64_words(&h8, &mut h[..w]);
        self.core.basic_transform_state(&mut h[..w]);
        u64_words_to_bytes(&h[..w], &mut h8);

        Ok(h8[..self.q].to_vec())
    }

    /// One-shot GMAC (Cryptonite `encrypt_gmac`).
    pub fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut data_buf = data.to_vec();
        let mut data_len = data_buf.len();
        kalyna_padding(&mut data_buf, &mut data_len, block_len);

        let mut h = [0u64; 8];
        self.core.basic_transform_state(&mut h[..w]);
        let mut h8 = vec![0u8; block_len];
        u64_words_to_bytes(&h[..w], &mut h8);

        let mut b8 = vec![0u8; block_len];
        let mut i = 0usize;
        while i < data_len {
            b8 = kalyna_xor_to(&data_buf[i..i + block_len], &b8, block_len);
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
            i += block_len;
        }

        h = [0; 8];
        h[0] = (data_len as u64) << 3;
        u64_words_to_bytes(&h[..w], &mut h8);
        h8 = kalyna_xor_to(&h8, &b8, block_len);
        bytes_to_u64_words(&h8, &mut h[..w]);
        self.core.basic_transform_state(&mut h[..w]);
        u64_words_to_bytes(&h[..w], &mut h8);

        Ok(h8[..self.q].to_vec())
    }
}
