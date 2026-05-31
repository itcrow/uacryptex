//! CCM mode for DSTU 7624 (Kalyna).

use crate::error::{Error, Result};

use super::core::KalynaCore;
use super::ctr::Dstu7624Ctr;
use super::modutil::{bytes_to_u64_words, kalyna_padding, kalyna_xor_to, u64_words_to_bytes};

/// CCM cipher context (S-box 1).
pub struct Dstu7624Ccm {
    core: KalynaCore,
    key: Vec<u8>,
    iv: Vec<u8>,
    iv_ctr: Vec<u8>,
    q: usize,
    nb: usize,
}

impl Dstu7624Ccm {
    pub fn init(key: &[u8], iv: &[u8], q: usize, n_max: u64) -> Result<Self> {
        if q == 0 || n_max < 8 {
            return Err(Error::InvalidParam("q or n_max".into()));
        }
        let block_len = iv.len();
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_len)?;
        if q > block_len {
            return Err(Error::InvalidParam("q".into()));
        }
        let nb = ((n_max - 3) >> 3) as usize + 1;
        if block_len < nb + 1 {
            return Err(Error::InvalidParam("block_len vs nb".into()));
        }

        Ok(Self {
            core,
            key: key.to_vec(),
            iv: iv.to_vec(),
            iv_ctr: iv.to_vec(),
            q,
            nb,
        })
    }

    fn ccm_padd(&self, auth: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let w = block_len / 8;
        let tmp = block_len - self.nb - 1;

        let mut g1 = [0u8; 64];
        g1[..tmp].copy_from_slice(&self.iv[..tmp]);

        let a_data_len = auth.len();
        let mut a_data_buf = auth.to_vec();
        a_data_buf.resize(a_data_len + block_len, 0);

        let mut p_data_buf = plain.to_vec();
        let mut p_data_len = p_data_buf.len();
        p_data_buf.resize(p_data_len + block_len, 0);

        g1[tmp] = p_data_len as u8;
        if plain.is_empty() {
            g1[block_len - 1] = 0;
        } else {
            g1[block_len - 1] = 1 << 7;
        }
        g1[block_len - 1] |= match self.q {
            8 => 2 << 4,
            16 => 3 << 4,
            32 => 4 << 4,
            48 => 5 << 4,
            64 => 6 << 4,
            _ => 0,
        };
        g1[block_len - 1] |= (self.nb - 1) as u8;

        let mut g2 = [0u8; 64];
        g2[0] = a_data_len as u8;

        let rem = a_data_len % block_len;
        let mut h = vec![0u8; block_len * 2 + a_data_len + block_len];
        h[..block_len].copy_from_slice(&g1[..block_len]);
        h[block_len..block_len + block_len - rem].copy_from_slice(&g2[..block_len - rem]);
        h[block_len + block_len - rem..block_len + block_len - rem + a_data_len]
            .copy_from_slice(&a_data_buf[..a_data_len]);

        let auth_total = a_data_len + block_len + (block_len - rem);
        let mut b = [0u8; 64];
        let mut b64 = [0u64; 8];

        for i in (0..auth_total).step_by(block_len) {
            let x = kalyna_xor_to(&h[i..i + block_len], &b, block_len);
            b[..block_len].copy_from_slice(&x);
            ccm_transform_block(&self.core, &mut b, &mut b64[..w])?;
        }

        kalyna_padding(&mut p_data_buf, &mut p_data_len, block_len);
        for i in (0..p_data_len).step_by(block_len) {
            let x = kalyna_xor_to(&p_data_buf[i..i + block_len], &b, block_len);
            b[..block_len].copy_from_slice(&x);
            ccm_transform_block(&self.core, &mut b, &mut b64[..w])?;
        }

        Ok(b[..self.q].to_vec())
    }

    pub fn encrypt(&self, auth: &[u8], plain: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let tag = self.ccm_padd(auth, plain)?;
        let mut ctr = Dstu7624Ctr::init(&self.key, &self.iv_ctr)?;
        let cipher_plain = ctr.encrypt(plain)?;
        let cipher_tag = ctr.encrypt(&tag)?;
        let mut cipher = cipher_plain;
        cipher.extend_from_slice(&cipher_tag);
        Ok((cipher, tag))
    }

    pub fn decrypt(&self, auth: &[u8], cipher: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        if tag.len() != self.q {
            return Err(Error::InvalidParam("tag length".into()));
        }
        let mut ctr = Dstu7624Ctr::init(&self.key, &self.iv_ctr)?;
        let decrypted = ctr.decrypt(cipher)?;
        if decrypted.len() < self.q {
            return Err(Error::InvalidParam("cipher too short".into()));
        }
        let plain_len = decrypted.len() - self.q;
        let plain = decrypted[..plain_len].to_vec();
        let check_h = self.ccm_padd(auth, &plain)?;
        if check_h != tag {
            return Err(Error::VerifyFailed);
        }
        Ok(plain)
    }
}

fn ccm_transform_block(core: &KalynaCore, b: &mut [u8; 64], state: &mut [u64]) -> Result<()> {
    let block_len = core.block_len();
    let w = block_len / 8;
    bytes_to_u64_words(b, &mut state[..w]);
    core.basic_transform_state(&mut state[..w]);
    u64_words_to_bytes(state, &mut b[..block_len]);
    Ok(())
}
