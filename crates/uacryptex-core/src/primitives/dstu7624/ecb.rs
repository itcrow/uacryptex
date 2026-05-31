//! ECB mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::KalynaCore;

/// ECB cipher context (S-box 1).
pub struct Dstu7624Ecb {
    core: KalynaCore,
}

impl Dstu7624Ecb {
    /// `block_size` is derived from plaintext length in Cryptonite (`ba_get_len(data)`).
    pub fn init(key: &[u8], block_size: usize) -> Result<Self> {
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_size)?;
        Ok(Self { core })
    }

    pub fn block_len(&self) -> usize {
        self.core.block_len()
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() % self.core.block_len() != 0 {
            return Err(Error::InvalidParam(
                "data length not multiple of block size".into(),
            ));
        }
        let mut out = vec![0u8; input.len()];
        let bl = self.core.block_len();
        for (i, chunk) in input.chunks(bl).enumerate() {
            self.core
                .encrypt_block(chunk, &mut out[i * bl..(i + 1) * bl])?;
        }
        Ok(out)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() % self.core.block_len() != 0 {
            return Err(Error::InvalidParam(
                "data length not multiple of block size".into(),
            ));
        }
        let mut out = vec![0u8; input.len()];
        let bl = self.core.block_len();
        for (i, chunk) in input.chunks(bl).enumerate() {
            self.core
                .decrypt_block(chunk, &mut out[i * bl..(i + 1) * bl])?;
        }
        Ok(out)
    }
}
