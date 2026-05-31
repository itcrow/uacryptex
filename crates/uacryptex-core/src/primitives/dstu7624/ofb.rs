//! OFB mode for DSTU 7624 (Kalyna).

use crate::error::Result;

use super::core::{crypt_basic_transform_in_place, KalynaCore};

/// OFB cipher context (S-box 1).
pub struct Dstu7624Ofb {
    core: KalynaCore,
    gamma: Vec<u8>,
    used_gamma_len: usize,
}

impl Dstu7624Ofb {
    pub fn init(key: &[u8], iv: &[u8]) -> Result<Self> {
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;
        Ok(Self {
            core,
            gamma: iv.to_vec(),
            used_gamma_len: 0,
        })
    }

    pub fn block_len(&self) -> usize {
        self.core.block_len()
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.process(input)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.process(input)
    }

    fn process(&self, src: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let mut plain_data = src.to_vec();
        let mut gamma = self.gamma.clone();
        let used_gamma_len = self.used_gamma_len;

        if used_gamma_len != 0 {
            let n = if block_len - used_gamma_len > src.len() {
                src.len()
            } else {
                block_len - used_gamma_len
            };
            for j in 0..n {
                plain_data[j] ^= gamma[used_gamma_len + j];
            }
        }

        let mut i = if used_gamma_len == block_len {
            block_len
        } else {
            used_gamma_len
        };
        while i < src.len() {
            crypt_basic_transform_in_place(&self.core, &mut gamma)?;
            let take = (src.len() - i).min(block_len);
            for j in 0..take {
                plain_data[i + j] ^= gamma[j];
            }
            i += block_len;
        }

        Ok(plain_data)
    }
}
