//! CBC mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::{crypt_basic_transform_in_place, KalynaCore};

/// CBC cipher context (S-box 1).
pub struct Dstu7624Cbc {
    core: KalynaCore,
    gamma: Vec<u8>,
}

impl Dstu7624Cbc {
    pub fn init(key: &[u8], iv: &[u8]) -> Result<Self> {
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;
        Ok(Self {
            core,
            gamma: iv.to_vec(),
        })
    }

    pub fn block_len(&self) -> usize {
        self.core.block_len()
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        if input.len() % block_len != 0 {
            return Err(Error::InvalidParam(
                "data length not multiple of block size".into(),
            ));
        }
        let mut cipher_data = input.to_vec();
        let mut gamma = self.gamma.clone();
        for i in (0..input.len()).step_by(block_len) {
            for j in 0..block_len {
                gamma[j] ^= cipher_data[i + j];
            }
            crypt_basic_transform_in_place(&self.core, &mut gamma)?;
            cipher_data[i..i + block_len].copy_from_slice(&gamma);
        }
        Ok(cipher_data)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        if input.len() % block_len != 0 {
            return Err(Error::InvalidParam(
                "data length not multiple of block size".into(),
            ));
        }
        let mut plain_data = vec![0u8; input.len()];
        let mut gamma = self.gamma.clone();
        for i in (0..input.len()).step_by(block_len) {
            self.core
                .decrypt_block(&input[i..i + block_len], &mut plain_data[i..i + block_len])?;
            for j in 0..block_len {
                plain_data[i + j] ^= gamma[j];
            }
            gamma.copy_from_slice(&input[i..i + block_len]);
        }
        Ok(plain_data)
    }
}
