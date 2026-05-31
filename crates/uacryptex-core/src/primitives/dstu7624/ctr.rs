//! CTR mode for DSTU 7624 (Kalyna).

use crate::error::Result;

use super::core::{crypt_basic_transform, gamma_gen, kalina_xor_bytes, KalynaCore};

/// CTR cipher context (S-box 1).
pub struct Dstu7624Ctr {
    core: KalynaCore,
    gamma: Vec<u8>,
    feed: Vec<u8>,
    used_gamma_len: usize,
}

impl Dstu7624Ctr {
    pub fn init(key: &[u8], iv: &[u8]) -> Result<Self> {
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;

        let mut gamma = iv.to_vec();
        let mut enc = vec![0u8; block_len];
        crypt_basic_transform(&core, &gamma, &mut enc)?;
        gamma.copy_from_slice(&enc);
        let feed = gamma.clone();

        Ok(Self {
            core,
            gamma,
            feed,
            used_gamma_len: block_len,
        })
    }

    pub fn block_len(&self) -> usize {
        self.core.block_len()
    }

    pub fn encrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.process(input)
    }

    pub fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.process(input)
    }

    fn process(&mut self, src: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let mut offset = self.used_gamma_len;
        let mut out = vec![0u8; src.len()];
        let mut data_off = 0usize;

        if offset != 0 {
            while offset < block_len && data_off < src.len() {
                out[data_off] = src[data_off] ^ self.gamma[offset];
                data_off += 1;
                offset += 1;
            }
            if offset == block_len {
                gamma_gen(&mut self.feed);
                crypt_basic_transform(&self.core, &self.feed, &mut self.gamma)?;
                offset = 0;
            }
        }

        if data_off < src.len() {
            while data_off + block_len <= src.len() {
                kalina_xor_bytes(
                    &src[data_off..data_off + block_len],
                    &self.gamma,
                    block_len,
                    &mut out[data_off..data_off + block_len],
                );
                data_off += block_len;
                gamma_gen(&mut self.feed);
                crypt_basic_transform(&self.core, &self.feed, &mut self.gamma)?;
            }
            while data_off < src.len() {
                out[data_off] = src[data_off] ^ self.gamma[offset];
                data_off += 1;
                offset += 1;
            }
        }

        self.used_gamma_len = offset;
        Ok(out)
    }
}
