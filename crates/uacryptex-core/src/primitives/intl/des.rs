//! DES / 3DES-EDE ECB via the `des` crate (no padding; block-aligned lengths).

use crate::error::{Error, Result};
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::{Des, TdesEde3};

const BLOCK: usize = 8;

fn check_block_aligned(len: usize) -> Result<()> {
    if len % BLOCK != 0 {
        return Err(Error::InvalidParam(format!(
            "DES data length {len} is not a multiple of {BLOCK}"
        )));
    }
    Ok(())
}

fn des_key(key: &[u8]) -> Result<GenericArray<u8, cipher::consts::U8>> {
    if key.len() != BLOCK {
        return Err(Error::InvalidParam(format!(
            "DES key length {} (expected 8)",
            key.len()
        )));
    }
    Ok(*GenericArray::from_slice(key))
}

fn expand_tdes_key(key: &[u8]) -> Result<GenericArray<u8, cipher::consts::U24>> {
    match key.len() {
        16 => {
            let mut k = [0u8; 24];
            k[..8].copy_from_slice(&key[..8]);
            k[8..16].copy_from_slice(&key[8..16]);
            k[16..24].copy_from_slice(&key[..8]);
            Ok(*GenericArray::from_slice(&k))
        }
        24 => Ok(*GenericArray::from_slice(key)),
        n => Err(Error::InvalidParam(format!(
            "TDES key length {n} (expected 16 or 24)"
        ))),
    }
}

/// Single-DES ECB encrypt (8-byte key).
pub fn des_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    check_block_aligned(plaintext.len())?;
    let cipher = Des::new(&des_key(key)?);
    let mut out = plaintext.to_vec();
    for chunk in out.chunks_mut(BLOCK) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}

/// Single-DES ECB decrypt.
pub fn des_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    check_block_aligned(ciphertext.len())?;
    let cipher = Des::new(&des_key(key)?);
    let mut out = ciphertext.to_vec();
    for chunk in out.chunks_mut(BLOCK) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}

/// 3DES-EDE ECB encrypt (16- or 24-byte key per Cryptonite `des3`).
pub fn tdes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    check_block_aligned(plaintext.len())?;
    let cipher = TdesEde3::new(&expand_tdes_key(key)?);
    let mut out = plaintext.to_vec();
    for chunk in out.chunks_mut(BLOCK) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}

/// 3DES-EDE ECB decrypt.
pub fn tdes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    check_block_aligned(ciphertext.len())?;
    let cipher = TdesEde3::new(&expand_tdes_key(key)?);
    let mut out = ciphertext.to_vec();
    for chunk in out.chunks_mut(BLOCK) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Ok(out)
}
