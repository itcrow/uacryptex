//! CMAC mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::{crypt_basic_transform, crypt_basic_transform_in_place, KalynaCore};
use super::modutil::{bytes_to_u64_words, kalyna_padding, kalyna_xor_to, u64_words_to_bytes};

/// CMAC context (S-box 1).
pub struct Dstu7624Cmac {
    core: KalynaCore,
    state: [u64; 8],
    last_block: [u8; 64],
    last_block_len: usize,
    q: usize,
}

impl Dstu7624Cmac {
    pub fn init(key: &[u8], block_size: usize, q: usize) -> Result<Self> {
        if q == 0 || q > block_size {
            return Err(Error::InvalidParam("q".into()));
        }
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_size)?;
        Ok(Self {
            core,
            state: [0; 8],
            last_block: [0; 64],
            last_block_len: 0,
            q,
        })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut cipher_data = vec![0u8; block_len];
        u64_words_to_bytes(&self.state[..w], &mut cipher_data);

        if self.last_block_len + data.len() <= block_len {
            self.last_block[self.last_block_len..self.last_block_len + data.len()]
                .copy_from_slice(data);
            self.last_block_len += data.len();
            return Ok(());
        }

        let fill = block_len - self.last_block_len;
        self.last_block[self.last_block_len..block_len].copy_from_slice(&data[..fill]);
        cipher_data = xor_transform(&self.core, &self.last_block[..block_len], &cipher_data)?;

        let shifted = &data[fill..];
        let plain_data_len = shifted.len();
        let mut i = 0usize;
        let mut j = block_len;
        while j < plain_data_len {
            cipher_data = xor_transform(&self.core, &shifted[i..i + block_len], &cipher_data)?;
            i += block_len;
            j += block_len;
        }

        self.last_block_len = plain_data_len - i;
        if self.last_block_len != 0 {
            self.last_block[..self.last_block_len]
                .copy_from_slice(&shifted[i..i + self.last_block_len]);
        }

        bytes_to_u64_words(&cipher_data, &mut self.state[..w]);
        Ok(())
    }

    pub fn final_mac(&mut self) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut cipher_data = vec![0u8; block_len];
        u64_words_to_bytes(&self.state[..w], &mut cipher_data);

        let mut last = self.last_block;
        let mut last_len = self.last_block_len;
        let mut rkey = [0u8; 64];
        rkey[0] = u8::from(kalyna_padding(&mut last, &mut last_len, block_len));

        let mut enc_rkey = vec![0u8; block_len];
        crypt_basic_transform(&self.core, &rkey[..block_len], &mut enc_rkey)?;

        let tmp = last[..block_len].to_vec();
        cipher_data = kalyna_xor_to(&tmp, &cipher_data, block_len);
        cipher_data = kalyna_xor_to(&enc_rkey, &cipher_data, block_len);
        crypt_basic_transform_in_place(&self.core, &mut cipher_data)?;

        Ok(cipher_data[..self.q].to_vec())
    }
}

fn xor_transform(core: &KalynaCore, a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    let bl = core.block_len();
    let mut out = kalyna_xor_to(a, b, bl);
    crypt_basic_transform_in_place(core, &mut out)?;
    Ok(out)
}
