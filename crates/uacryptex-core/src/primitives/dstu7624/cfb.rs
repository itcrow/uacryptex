//! CFB mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::{crypt_basic_transform, kalina_xor_bytes, KalynaCore};

/// CFB cipher context (S-box 1).
pub struct Dstu7624Cfb {
    core: KalynaCore,
    gamma: Vec<u8>,
    feed: Vec<u8>,
    used_gamma_len: usize,
    q: usize,
}

impl Dstu7624Cfb {
    pub fn init(key: &[u8], iv: &[u8], q: usize) -> Result<Self> {
        if q == 0 || q > iv.len() {
            return Err(Error::InvalidParam("q".into()));
        }
        if !matches!(q, 1 | 8 | 16 | 32 | 64) {
            return Err(Error::InvalidParam("q must be 1, 8, 16, 32, or 64".into()));
        }
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;
        Ok(Self {
            core,
            gamma: iv.to_vec(),
            feed: iv.to_vec(),
            used_gamma_len: block_len,
            q,
        })
    }

    pub fn block_len(&self) -> usize {
        self.core.block_len()
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.process_encrypt(input)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.process_decrypt(input)
    }

    fn process_encrypt(&self, src: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let q = self.q;
        let mut gamma = self.gamma.clone();
        let mut feed = self.feed.clone();
        let mut offset = self.used_gamma_len;
        let mut out = vec![0u8; src.len()];
        let mut data_off = 0usize;

        if offset != 0 {
            while offset < q && data_off < src.len() {
                out[data_off] = src[data_off] ^ gamma[offset];
                feed[offset] = out[data_off];
                data_off += 1;
                offset += 1;
            }
            if offset == block_len {
                crypt_basic_transform(&self.core, &feed, &mut gamma)?;
                offset = block_len - q;
            }
        }

        if data_off < src.len() {
            while data_off + q <= src.len() {
                kalina_xor_bytes(
                    &src[data_off..data_off + q],
                    &gamma[offset..offset + q],
                    q,
                    &mut out[data_off..data_off + q],
                );
                feed.copy_from_slice(&gamma);
                feed[offset..offset + q].copy_from_slice(&out[data_off..data_off + q]);
                crypt_basic_transform(&self.core, &feed, &mut gamma)?;
                data_off += q;
            }
            while data_off < src.len() {
                let gi = block_len - (src.len() - data_off);
                out[data_off] = src[data_off] ^ gamma[gi];
                feed[offset] = out[data_off];
                data_off += 1;
                offset += 1;
            }
        }

        Ok(out)
    }

    fn process_decrypt(&self, src: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let q = self.q;
        let mut gamma = self.gamma.clone();
        let mut feed = self.feed.clone();
        let mut offset = self.used_gamma_len;
        let mut out = vec![0u8; src.len()];
        let mut data_off = 0usize;

        if offset != 0 {
            while offset < q && data_off < src.len() {
                out[data_off] = src[data_off] ^ gamma[offset];
                feed[offset] = src[data_off];
                data_off += 1;
                offset += 1;
            }
            if offset == block_len {
                crypt_basic_transform(&self.core, &feed, &mut gamma)?;
                offset = block_len - q;
            }
        }

        if data_off < src.len() {
            while data_off + q <= src.len() {
                kalina_xor_bytes(
                    &src[data_off..data_off + q],
                    &gamma[offset..offset + q],
                    q,
                    &mut out[data_off..data_off + q],
                );
                feed.copy_from_slice(&gamma);
                feed[offset..offset + q].copy_from_slice(&src[data_off..data_off + q]);
                crypt_basic_transform(&self.core, &feed, &mut gamma)?;
                data_off += q;
            }
            while data_off < src.len() {
                let gi = block_len - (src.len() - data_off);
                out[data_off] = src[data_off] ^ gamma[gi];
                feed[offset] = src[data_off];
                data_off += 1;
                offset += 1;
            }
        }

        Ok(out)
    }
}
