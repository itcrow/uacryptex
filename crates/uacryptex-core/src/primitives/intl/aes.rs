//! AES-ECB/CBC/CTR/CFB/OFB via `aes` + `cbc` (no padding; ECB/CBC require block-aligned lengths).

use crate::error::{Error, Result};
use aes::{Aes128, Aes192, Aes256};
use block_padding::NoPadding;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;
type Aes192CbcEnc = Encryptor<Aes192>;
type Aes192CbcDec = Decryptor<Aes192>;
type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const BLOCK: usize = 16;

struct StreamState {
    gamma: [u8; BLOCK],
    feed: [u8; BLOCK],
    offset: usize,
}

impl StreamState {
    fn new(iv: &[u8]) -> Self {
        let mut gamma = [0u8; BLOCK];
        let mut feed = [0u8; BLOCK];
        gamma.copy_from_slice(iv);
        feed.copy_from_slice(iv);
        Self {
            gamma,
            feed,
            offset: BLOCK,
        }
    }
}

fn check_block_aligned(len: usize) -> Result<()> {
    if len % BLOCK != 0 {
        return Err(Error::InvalidParam(format!(
            "AES data length {len} is not a multiple of {BLOCK}"
        )));
    }
    Ok(())
}

fn check_key_len(key: &[u8]) -> Result<()> {
    match key.len() {
        16 | 24 | 32 => Ok(()),
        n => Err(Error::InvalidParam(format!(
            "AES key length {n} (expected 16, 24, or 32)"
        ))),
    }
}

fn check_iv_len(iv: &[u8]) -> Result<()> {
    if iv.len() != BLOCK {
        return Err(Error::InvalidParam(format!(
            "AES IV length {} (expected 16)",
            iv.len()
        )));
    }
    Ok(())
}

fn block_encrypt(key: &[u8], input: &[u8], output: &mut [u8]) {
    let mut block = aes::Block::clone_from_slice(input);
    match key.len() {
        16 => Aes128::new(key.into()).encrypt_block(&mut block),
        24 => Aes192::new(key.into()).encrypt_block(&mut block),
        32 => Aes256::new(key.into()).encrypt_block(&mut block),
        _ => unreachable!(),
    }
    output.copy_from_slice(block.as_slice());
}

fn xor_block(src: &[u8], mask: &[u8], out: &mut [u8]) {
    for i in 0..BLOCK {
        out[i] = src[i] ^ mask[i];
    }
}

fn gamma_gen(counter: &mut [u8; BLOCK]) {
    let mut i = BLOCK;
    loop {
        i -= 1;
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
        if i == 0 {
            break;
        }
    }
}

/// CTR encrypt/decrypt (Cryptonite `encrypt_ctr`; arbitrary length).
pub fn aes_ctr_crypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    check_iv_len(iv)?;
    let mut st = StreamState::new(iv);
    let mut out = vec![0u8; data.len()];
    let mut data_off = 0usize;

    if st.offset != 0 {
        while st.offset < BLOCK && data_off < data.len() {
            out[data_off] = data[data_off] ^ st.gamma[st.offset];
            data_off += 1;
            st.offset += 1;
        }
        if st.offset == BLOCK {
            block_encrypt(key, &st.feed, &mut st.gamma);
            gamma_gen(&mut st.feed);
            st.offset = 0;
        }
    }

    while data_off + BLOCK <= data.len() {
        xor_block(&data[data_off..], &st.gamma, &mut out[data_off..]);
        block_encrypt(key, &st.feed, &mut st.gamma);
        gamma_gen(&mut st.feed);
        data_off += BLOCK;
    }

    while data_off < data.len() {
        out[data_off] = data[data_off] ^ st.gamma[st.offset];
        st.offset += 1;
        data_off += 1;
    }

    Ok(out)
}

/// OFB encrypt/decrypt (Cryptonite `encrypt_ofb`).
pub fn aes_ofb_crypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    check_iv_len(iv)?;
    let mut st = StreamState::new(iv);
    let mut out = vec![0u8; data.len()];
    let mut data_off = 0usize;

    if st.offset != 0 {
        while st.offset < BLOCK && data_off < data.len() {
            out[data_off] = data[data_off] ^ st.gamma[st.offset];
            st.offset += 1;
            data_off += 1;
        }
        if st.offset == BLOCK {
            let input = st.gamma;
            let mut next = [0u8; BLOCK];
            block_encrypt(key, &input, &mut next);
            st.gamma = next;
            st.offset = 0;
        }
    }

    while data_off + BLOCK <= data.len() {
        xor_block(&data[data_off..], &st.gamma, &mut out[data_off..]);
        let input = st.gamma;
        let mut next = [0u8; BLOCK];
        block_encrypt(key, &input, &mut next);
        st.gamma = next;
        data_off += BLOCK;
    }

    while data_off < data.len() {
        out[data_off] = data[data_off] ^ st.gamma[st.offset];
        st.offset += 1;
        data_off += 1;
    }

    Ok(out)
}

/// CFB encrypt (Cryptonite `encrypt_cfb`).
pub fn aes_cfb_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    check_iv_len(iv)?;
    let mut st = StreamState::new(iv);
    let mut out = vec![0u8; plaintext.len()];
    let mut data_off = 0usize;

    if st.offset != 0 {
        while st.offset < BLOCK && data_off < plaintext.len() {
            out[data_off] = plaintext[data_off] ^ st.gamma[st.offset];
            st.feed[st.offset] = out[data_off];
            st.offset += 1;
            data_off += 1;
        }
        if st.offset == BLOCK {
            block_encrypt(key, &st.feed, &mut st.gamma);
            st.offset = 0;
        }
    }

    while data_off + BLOCK <= plaintext.len() {
        xor_block(&plaintext[data_off..], &st.gamma, &mut out[data_off..]);
        st.feed.copy_from_slice(&out[data_off..data_off + BLOCK]);
        block_encrypt(key, &st.feed, &mut st.gamma);
        data_off += BLOCK;
    }

    while data_off < plaintext.len() {
        out[data_off] = plaintext[data_off] ^ st.gamma[st.offset];
        st.feed[st.offset] = out[data_off];
        st.offset += 1;
        data_off += 1;
    }

    Ok(out)
}

/// CFB decrypt (Cryptonite `decrypt_cfb`).
pub fn aes_cfb_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    check_iv_len(iv)?;
    let mut st = StreamState::new(iv);
    let mut out = vec![0u8; ciphertext.len()];
    let mut data_off = 0usize;

    if st.offset != 0 {
        while st.offset < BLOCK && data_off < ciphertext.len() {
            st.feed[st.offset] = ciphertext[data_off];
            out[data_off] = ciphertext[data_off] ^ st.gamma[st.offset];
            st.offset += 1;
            data_off += 1;
        }
        if st.offset == BLOCK {
            block_encrypt(key, &st.feed, &mut st.gamma);
            st.offset = 0;
        }
    }

    while data_off + BLOCK <= ciphertext.len() {
        st.feed
            .copy_from_slice(&ciphertext[data_off..data_off + BLOCK]);
        xor_block(&ciphertext[data_off..], &st.gamma, &mut out[data_off..]);
        block_encrypt(key, &st.feed, &mut st.gamma);
        data_off += BLOCK;
    }

    while data_off < ciphertext.len() {
        st.feed[st.offset] = ciphertext[data_off];
        out[data_off] = ciphertext[data_off] ^ st.gamma[st.offset];
        st.offset += 1;
        data_off += 1;
    }

    Ok(out)
}

/// ECB encrypt (output length equals input).
pub fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    check_block_aligned(plaintext.len())?;
    let mut out = plaintext.to_vec();
    ecb_process(key, &mut out, true)?;
    Ok(out)
}

/// ECB decrypt.
pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    check_block_aligned(ciphertext.len())?;
    let mut out = ciphertext.to_vec();
    ecb_process(key, &mut out, false)?;
    Ok(out)
}

fn ecb_process(key: &[u8], buf: &mut [u8], encrypt: bool) -> Result<()> {
    match key.len() {
        16 if encrypt => {
            let cipher = Aes128::new(key.into());
            for chunk in buf.chunks_mut(BLOCK) {
                cipher.encrypt_block(aes::Block::from_mut_slice(chunk));
            }
        }
        16 => {
            let cipher = Aes128::new(key.into());
            for chunk in buf.chunks_mut(BLOCK) {
                cipher.decrypt_block(aes::Block::from_mut_slice(chunk));
            }
        }
        24 if encrypt => {
            let cipher = Aes192::new(key.into());
            for chunk in buf.chunks_mut(BLOCK) {
                cipher.encrypt_block(aes::Block::from_mut_slice(chunk));
            }
        }
        24 => {
            let cipher = Aes192::new(key.into());
            for chunk in buf.chunks_mut(BLOCK) {
                cipher.decrypt_block(aes::Block::from_mut_slice(chunk));
            }
        }
        32 if encrypt => {
            let cipher = Aes256::new(key.into());
            for chunk in buf.chunks_mut(BLOCK) {
                cipher.encrypt_block(aes::Block::from_mut_slice(chunk));
            }
        }
        32 => {
            let cipher = Aes256::new(key.into());
            for chunk in buf.chunks_mut(BLOCK) {
                cipher.decrypt_block(aes::Block::from_mut_slice(chunk));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// CBC encrypt with explicit IV (fresh context; Cryptonite `aes_init_cbc` per direction).
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    if iv.len() != BLOCK {
        return Err(Error::InvalidParam(format!(
            "AES IV length {} (expected 16)",
            iv.len()
        )));
    }
    check_block_aligned(plaintext.len())?;
    let mut buf = plaintext.to_vec();
    cbc_process(key, iv, &mut buf, true)?;
    Ok(buf)
}

/// CBC decrypt with explicit IV.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    check_key_len(key)?;
    if iv.len() != BLOCK {
        return Err(Error::InvalidParam(format!(
            "AES IV length {} (expected 16)",
            iv.len()
        )));
    }
    check_block_aligned(ciphertext.len())?;
    let mut buf = ciphertext.to_vec();
    cbc_process(key, iv, &mut buf, false)?;
    Ok(buf)
}

fn cbc_process(key: &[u8], iv: &[u8], buf: &mut [u8], encrypt: bool) -> Result<()> {
    match key.len() {
        16 if encrypt => {
            let enc = Aes128CbcEnc::new(key.into(), iv.into());
            enc.encrypt_padded_mut::<NoPadding>(buf, buf.len())
                .map_err(|e| Error::Internal(format!("AES-CBC encrypt: {e}")))?;
        }
        16 => {
            let dec = Aes128CbcDec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(buf)
                .map_err(|e| Error::Internal(format!("AES-CBC decrypt: {e}")))?;
        }
        24 if encrypt => {
            let enc = Aes192CbcEnc::new(key.into(), iv.into());
            enc.encrypt_padded_mut::<NoPadding>(buf, buf.len())
                .map_err(|e| Error::Internal(format!("AES-CBC encrypt: {e}")))?;
        }
        24 => {
            let dec = Aes192CbcDec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(buf)
                .map_err(|e| Error::Internal(format!("AES-CBC decrypt: {e}")))?;
        }
        32 if encrypt => {
            let enc = Aes256CbcEnc::new(key.into(), iv.into());
            enc.encrypt_padded_mut::<NoPadding>(buf, buf.len())
                .map_err(|e| Error::Internal(format!("AES-CBC encrypt: {e}")))?;
        }
        32 => {
            let dec = Aes256CbcDec::new(key.into(), iv.into());
            dec.decrypt_padded_mut::<NoPadding>(buf)
                .map_err(|e| Error::Internal(format!("AES-CBC decrypt: {e}")))?;
        }
        _ => unreachable!(),
    }
    Ok(())
}
