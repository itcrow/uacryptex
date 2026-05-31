//! XTS mode for DSTU 7624 (Kalyna).

use crate::error::Result;

use super::core::{crypt_basic_transform, crypt_basic_transform_in_place, KalynaCore};
use super::modutil::{gf2m_ctx_for_block_len, gf2m_mul_bytes, kalyna_xor_to};

/// XTS cipher context (S-box 1).
pub struct Dstu7624Xts {
    core: KalynaCore,
    iv: Vec<u8>,
    gf2m: crate::math::Gf2mCtx,
}

impl Dstu7624Xts {
    pub fn init(key: &[u8], iv: &[u8]) -> Result<Self> {
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;
        Ok(Self {
            core,
            iv: iv.to_vec(),
            gf2m: gf2m_ctx_for_block_len(block_len),
        })
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let plain_size = input.len();
        let padded_len = block_len - plain_size % block_len;
        let mut plain_data = input.to_vec();
        plain_data.resize(plain_size + padded_len, 0);

        let mut gamma = vec![0u8; block_len];
        crypt_basic_transform(&self.core, &self.iv, &mut gamma)?;

        let mut two = vec![0u8; block_len];
        two[0] = 2;

        let loop_len = if padded_len == block_len {
            plain_size
        } else {
            plain_size - block_len
        };

        let mut i = 0usize;
        while i < loop_len {
            self.xts_crypt_block(&mut gamma, &two, &mut plain_data[i..i + block_len], true)?;
            i += block_len;
        }

        if padded_len != block_len {
            i += plain_size % block_len;
            let src = plain_data[i - block_len..i - block_len + padded_len].to_vec();
            plain_data[i..i + padded_len].copy_from_slice(&src);
            i -= plain_size % block_len;

            self.xts_crypt_block(&mut gamma, &two, &mut plain_data[i..i + block_len], true)?;

            let saved = plain_data[i - block_len..i].to_vec();
            let curr = plain_data[i..i + block_len].to_vec();
            plain_data[i - block_len..i].copy_from_slice(&curr);
            plain_data[i..i + block_len - padded_len]
                .copy_from_slice(&saved[..block_len - padded_len]);
        }

        plain_data.truncate(plain_size);
        Ok(plain_data)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let plain_size = input.len();
        let padded_len = block_len - plain_size % block_len;
        let mut plain_data = input.to_vec();
        plain_data.resize(plain_size + padded_len, 0);

        let mut gamma = vec![0u8; block_len];
        crypt_basic_transform(&self.core, &self.iv, &mut gamma)?;

        let mut two = vec![0u8; block_len];
        two[0] = 2;

        let loop_num = if padded_len == block_len {
            plain_size
        } else {
            plain_size.saturating_sub(2 * block_len)
        };

        let mut i = 0usize;
        while i < loop_num {
            self.xts_crypt_block(&mut gamma, &two, &mut plain_data[i..i + block_len], false)?;
            i += block_len;
        }

        if padded_len != block_len {
            gamma = {
                let mut out = vec![0u8; block_len];
                gf2m_mul_bytes(&self.gf2m, block_len, &gamma, &two, &mut out)?;
                out
            };
            two = {
                let mut out = vec![0u8; block_len];
                gf2m_mul_bytes(&self.gf2m, block_len, &gamma, &two, &mut out)?;
                out
            };
            self.xts_crypt_block_with_tweak(&two, &mut plain_data[i..i + block_len], false)?;

            i += block_len;
            i += plain_size % block_len;
            let src = plain_data[i - block_len..i - block_len + padded_len].to_vec();
            plain_data[i..i + padded_len].copy_from_slice(&src);
            i -= plain_size % block_len;

            self.xts_crypt_block_with_tweak(&gamma, &mut plain_data[i..i + block_len], false)?;

            let saved = plain_data[i - block_len..i].to_vec();
            let curr = plain_data[i..i + block_len].to_vec();
            plain_data[i - block_len..i].copy_from_slice(&curr);
            plain_data[i..i + block_len - padded_len]
                .copy_from_slice(&saved[..block_len - padded_len]);
        }

        plain_data.truncate(plain_size);
        Ok(plain_data)
    }

    fn xts_crypt_block(
        &self,
        gamma: &mut [u8],
        two: &[u8],
        block: &mut [u8],
        encrypt: bool,
    ) -> Result<()> {
        let bl = block.len();
        let next_gamma = {
            let mut out = vec![0u8; bl];
            gf2m_mul_bytes(&self.gf2m, bl, gamma, two, &mut out)?;
            out
        };
        gamma.copy_from_slice(&next_gamma);
        self.xts_crypt_block_with_tweak(gamma, block, encrypt)
    }

    fn xts_crypt_block_with_tweak(
        &self,
        tweak: &[u8],
        block: &mut [u8],
        encrypt: bool,
    ) -> Result<()> {
        let bl = block.len();
        let mut tmp = kalyna_xor_to(block, tweak, bl);
        if encrypt {
            crypt_basic_transform_in_place(&self.core, &mut tmp)?;
        } else {
            let dec = {
                let mut out = vec![0u8; bl];
                self.core.decrypt_block(&tmp, &mut out)?;
                out
            };
            tmp.copy_from_slice(&dec);
        }
        block.copy_from_slice(&kalyna_xor_to(&tmp, tweak, bl));
        Ok(())
    }
}
