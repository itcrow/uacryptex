//! GCM mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::{crypt_basic_transform_in_place, KalynaCore};
use super::modutil::{
    bytes_to_u64_words, gf2m_ctx_for_block_len, gf2m_mul_to, kalyna_padding, kalyna_xor_to,
    u64_words_to_bytes,
};

/// GCM cipher context (S-box 1).
pub struct Dstu7624Gcm {
    core: KalynaCore,
    gf2m: crate::math::Gf2mCtx,
    iv: [u64; 8],
    q: usize,
}

impl Dstu7624Gcm {
    pub fn init(key: &[u8], iv: &[u8], q: usize) -> Result<Self> {
        if !(8..=iv.len()).contains(&q) {
            return Err(Error::InvalidParam("q".into()));
        }
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;

        let w = block_len / 8;
        let mut iv_words = [0u64; 8];
        bytes_to_u64_words(iv, &mut iv_words[..w]);

        Ok(Self {
            core,
            gf2m: gf2m_ctx_for_block_len(block_len),
            iv: iv_words,
            q,
        })
    }

    pub fn encrypt(&self, plain: &[u8], auth: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut plain_buf = plain.to_vec();
        let plain_len_orig = plain_buf.len();
        let auth_len_orig = auth.len();

        let mut gamma_old = self.iv;
        let mut gamma = [0u64; 8];
        let mut enc_state = gamma_old;
        self.encrypt_u64_state(&mut enc_state)?;
        gamma_old = enc_state;

        for i in (0..plain_len_orig).step_by(block_len) {
            gamma_old[0] = gamma_old[0].wrapping_add(1);
            gamma.copy_from_slice(&gamma_old);
            self.encrypt_u64_state(&mut gamma)?;
            let mut gamma8 = vec![0u8; block_len];
            u64_words_to_bytes(&gamma[..w], &mut gamma8);
            let take = (plain_len_orig - i).min(block_len);
            let x = kalyna_xor_to(&plain_buf[i..i + take], &gamma8[..take], take);
            plain_buf[i..i + take].copy_from_slice(&x);
        }

        let cipher_text = plain_buf.clone();

        let mut plain_len = plain_len_orig;
        kalyna_padding(&mut plain_buf, &mut plain_len, block_len);

        let mut h = [0u64; 8];
        self.encrypt_u64_state(&mut h)?;
        let mut h8 = vec![0u8; block_len];
        u64_words_to_bytes(&h[..w], &mut h8);

        let mut b8 = vec![0u8; block_len];

        for i in (0..auth_len_orig).step_by(block_len) {
            let take = (auth_len_orig - i).min(block_len);
            b8 = kalyna_xor_to(&auth[i..i + take], &b8, take);
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
        }

        for i in (0..plain_len).step_by(block_len) {
            b8 = kalyna_xor_to(&plain_buf[i..i + block_len], &b8, block_len);
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
        }

        let tag = self.finalize_tag(&b8, auth_len_orig, plain_len, block_len)?;
        Ok((cipher_text, tag))
    }

    pub fn decrypt(&self, cipher: &[u8], tag: &[u8], auth: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let plain_len_orig = cipher.len();
        let auth_len_orig = auth.len();

        let mut plain_buf = cipher.to_vec();
        let mut plain_len = plain_len_orig;
        kalyna_padding(&mut plain_buf, &mut plain_len, block_len);

        let mut b8 = vec![0u8; block_len];
        let mut h8 = vec![0u8; block_len];
        let mut h = [0u64; 8];
        self.encrypt_u64_state(&mut h)?;
        u64_words_to_bytes(&h, &mut h8);

        for i in (0..auth_len_orig).step_by(block_len) {
            let take = (auth_len_orig - i).min(block_len);
            b8 = kalyna_xor_to(&auth[i..i + take], &b8, take);
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
        }

        for i in (0..plain_len).step_by(block_len) {
            b8 = kalyna_xor_to(&plain_buf[i..i + block_len], &b8, block_len);
            b8 = gf2m_mul_to(&self.gf2m, block_len, &b8, &h8)?;
        }

        let computed = self.finalize_tag(&b8, auth_len_orig, plain_len, block_len)?;
        if tag.len() != self.q || computed[..self.q] != tag[..] {
            return Err(Error::VerifyFailed);
        }

        let w = block_len / 8;
        let mut gamma_old = self.iv;
        let mut gamma = [0u64; 8];
        let mut enc_state = gamma_old;
        self.encrypt_u64_state(&mut enc_state)?;
        gamma_old = enc_state;

        let mut out = cipher.to_vec();
        for i in (0..plain_len_orig).step_by(block_len) {
            gamma_old[0] = gamma_old[0].wrapping_add(1);
            gamma.copy_from_slice(&gamma_old);
            self.encrypt_u64_state(&mut gamma)?;
            let mut gamma8 = vec![0u8; block_len];
            u64_words_to_bytes(&gamma[..w], &mut gamma8);
            let take = (plain_len_orig - i).min(block_len);
            let x = kalyna_xor_to(&out[i..i + take], &gamma8[..take], take);
            out[i..i + take].copy_from_slice(&x);
        }

        Ok(out)
    }

    fn finalize_tag(
        &self,
        b8: &[u8],
        auth_len_orig: usize,
        plain_len: usize,
        block_len: usize,
    ) -> Result<Vec<u8>> {
        let w = block_len / 8;
        let mut len_h = [0u64; 8];
        let mut auth_bits = auth_len_orig * 8;
        let mut plain_bits = plain_len * 8;
        let mut idx = 0usize;
        while auth_bits != 0 {
            len_h[0] ^= ((auth_bits & 255) as u64) << (idx << 3);
            auth_bits >>= 8;
            idx += 1;
        }
        idx = 0;
        while plain_bits != 0 {
            len_h[(block_len / 2) >> 3] ^= ((plain_bits & 255) as u64) << (idx << 3);
            plain_bits >>= 8;
            idx += 1;
        }

        let mut h8 = vec![0u8; block_len];
        u64_words_to_bytes(&len_h[..w], &mut h8);
        h8 = kalyna_xor_to(&h8, b8, block_len);

        let mut h = [0u64; 8];
        bytes_to_u64_words(&h8, &mut h[..w]);
        self.encrypt_u64_state(&mut h)?;
        u64_words_to_bytes(&h[..w], &mut h8);
        Ok(h8[..self.q].to_vec())
    }

    fn encrypt_u64_state(&self, state: &mut [u64; 8]) -> Result<()> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let mut bytes = vec![0u8; block_len];
        u64_words_to_bytes(&state[..w], &mut bytes);
        crypt_basic_transform_in_place(&self.core, &mut bytes)?;
        bytes_to_u64_words(&bytes, &mut state[..w]);
        Ok(())
    }
}
