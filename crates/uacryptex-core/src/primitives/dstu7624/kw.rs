//! KW (key wrap) mode for DSTU 7624 (Kalyna).

use crate::error::Result;

use super::core::{crypt_basic_transform_in_place, KalynaCore};
use super::modutil::{kalyna_padding, kalyna_unpadding};

/// KW cipher context (S-box 1).
pub struct Dstu7624Kw {
    core: KalynaCore,
}

impl Dstu7624Kw {
    pub fn init(key: &[u8], block_size: usize) -> Result<Self> {
        let mut core = KalynaCore::new_sbox1();
        core.init(key, block_size)?;
        Ok(Self { core })
    }

    pub fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let block_size_kw_byte = block_len / 2;
        let mut plain_data_size_byte = input.len();
        let mut cipher_data = vec![0u8; plain_data_size_byte + (block_len << 2)];
        cipher_data[..plain_data_size_byte].copy_from_slice(input);

        if plain_data_size_byte % block_len != 0 {
            let mut plain_data_size_bit = plain_data_size_byte * 8;
            let mut i = 0usize;
            while plain_data_size_bit != 0 {
                cipher_data[plain_data_size_byte + i] = (plain_data_size_bit & 255) as u8;
                i += 1;
                plain_data_size_bit >>= 8;
            }
            plain_data_size_byte += block_size_kw_byte;
            kalyna_padding(&mut cipher_data, &mut plain_data_size_byte, block_len);
        }

        let r = plain_data_size_byte / block_len;
        let n = 2 * (r + 1);
        let v = (n - 1) * 6;

        let b_el_count = (n - 1) * block_size_kw_byte;
        let b_last_el = (n - 2) * block_size_kw_byte;

        let mut b = vec![0u8; n * block_size_kw_byte];
        let mut shift = vec![0u8; n * block_size_kw_byte];
        let mut b_val = [0u8; 32];
        b_val[..block_size_kw_byte].copy_from_slice(&cipher_data[..block_size_kw_byte]);
        b[..b_el_count]
            .copy_from_slice(&cipher_data[block_size_kw_byte..block_size_kw_byte + b_el_count]);

        for i in 1..=v {
            let mut swap = [0u8; 64];
            swap[..block_size_kw_byte].copy_from_slice(&b_val[..block_size_kw_byte]);
            swap[block_size_kw_byte..block_len].copy_from_slice(&b[..block_size_kw_byte]);
            crypt_basic_transform_in_place(&self.core, &mut swap[..block_len])?;
            swap[block_size_kw_byte] ^= i as u8;
            b_val[..block_size_kw_byte].copy_from_slice(&swap[block_size_kw_byte..block_len]);
            shift[..b_el_count]
                .copy_from_slice(&b[block_size_kw_byte..block_size_kw_byte + b_el_count]);
            b[..b_el_count - block_size_kw_byte]
                .copy_from_slice(&shift[..b_el_count - block_size_kw_byte]);
            b[b_last_el..b_last_el + block_size_kw_byte]
                .copy_from_slice(&swap[..block_size_kw_byte]);
        }

        cipher_data[..block_size_kw_byte].copy_from_slice(&b_val[..block_size_kw_byte]);
        cipher_data[block_size_kw_byte..block_size_kw_byte + b_el_count]
            .copy_from_slice(&b[..b_el_count]);
        cipher_data.truncate(block_size_kw_byte + b_el_count);
        Ok(cipher_data)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        let block_len = self.core.block_len();
        let block_size_kw_byte = block_len / 2;
        let mut cipher_data = input.to_vec();
        let mut cipher_data_size_byte = cipher_data.len();

        let r = cipher_data_size_byte / block_len - 1;
        let n = 2 * (r + 1);
        let v = (n - 1) * 6;

        let mut b_val = [0u8; 32];
        b_val[..block_size_kw_byte].copy_from_slice(&cipher_data[..block_size_kw_byte]);

        let b_el_count = (n - 1) * block_size_kw_byte;
        let b_last_el = (n - 2) * block_size_kw_byte;
        let mut b = vec![0u8; cipher_data_size_byte];
        b[..b_el_count]
            .copy_from_slice(&cipher_data[block_size_kw_byte..block_size_kw_byte + b_el_count]);

        let mut shift = vec![0u8; cipher_data_size_byte];
        for i in (1..=v).rev() {
            let mut swap = [0u8; 64];
            swap[..block_size_kw_byte]
                .copy_from_slice(&b[b_last_el..b_last_el + block_size_kw_byte]);
            b_val[0] ^= i as u8;
            swap[block_size_kw_byte..block_len].copy_from_slice(&b_val[..block_size_kw_byte]);
            let mut dec_out = [0u8; 64];
            self.core
                .decrypt_block(&swap[..block_len], &mut dec_out[..block_len])?;
            swap[..block_len].copy_from_slice(&dec_out[..block_len]);
            b_val[..block_size_kw_byte].copy_from_slice(&swap[..block_size_kw_byte]);
            shift[..cipher_data_size_byte - block_size_kw_byte]
                .copy_from_slice(&b[..cipher_data_size_byte - block_size_kw_byte]);
            b[block_size_kw_byte..block_size_kw_byte + b_el_count]
                .copy_from_slice(&shift[..b_el_count]);
            b[..block_size_kw_byte].copy_from_slice(&swap[block_size_kw_byte..block_len]);
        }

        cipher_data[..block_size_kw_byte].copy_from_slice(&b_val[..block_size_kw_byte]);
        cipher_data[block_size_kw_byte..block_size_kw_byte + b_el_count]
            .copy_from_slice(&b[..b_el_count]);

        if kalyna_unpadding(&cipher_data, &mut cipher_data_size_byte).is_none() {
            // C leaves length unchanged when unpadding fails.
        }
        if cipher_data_size_byte % block_len != 0 {
            cipher_data_size_byte -= block_size_kw_byte + 1;
        }
        cipher_data.truncate(cipher_data_size_byte);
        Ok(cipher_data)
    }
}
