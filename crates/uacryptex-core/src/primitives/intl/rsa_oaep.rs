//! RSA PKCS#1 OAEP encrypt/decrypt (Cryptonite `rsa_encrypt_oaep` / `rsa_decrypt_oaep`).

use crate::error::{Error, Result};
use num_bigint_dig::BigUint;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Sha256, Sha384, Sha512};

use super::rsa::{
    bigint_from_cryptonite_bytes, bigint_to_cryptonite_bytes, em_int_to_be_bytes, pad_to_modulus,
};

/// OAEP hash function (Cryptonite `RsaHashType`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaOaepHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl RsaOaepHash {
    pub const fn hlen(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

const LHASH_SHA1: [u8; 20] = [
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
];
const LHASH_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];
const LHASH_SHA384: [u8; 48] = [
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
];
const LHASH_SHA512: [u8; 64] = [
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
];

fn hash_bytes(hash: RsaOaepHash, data: &[u8]) -> Vec<u8> {
    match hash {
        RsaOaepHash::Sha1 => Sha1::digest(data).to_vec(),
        RsaOaepHash::Sha256 => Sha256::digest(data).to_vec(),
        RsaOaepHash::Sha384 => Sha384::digest(data).to_vec(),
        RsaOaepHash::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn lhash(hash: RsaOaepHash, label: Option<&[u8]>) -> Vec<u8> {
    match label {
        None => match hash {
            RsaOaepHash::Sha1 => LHASH_SHA1.to_vec(),
            RsaOaepHash::Sha256 => LHASH_SHA256.to_vec(),
            RsaOaepHash::Sha384 => LHASH_SHA384.to_vec(),
            RsaOaepHash::Sha512 => LHASH_SHA512.to_vec(),
        },
        Some(label) => hash_bytes(hash, label),
    }
}

/// Cryptonite `mgf` (MGF1 with hash `htype`; counter increments byte 3 only).
fn mgf(hash: RsaOaepHash, seed: &[u8], mask_len: usize) -> Vec<u8> {
    let hlen = hash.hlen();
    let iter = 1 + (mask_len - 1) / hlen;
    let mut mask = vec![0u8; mask_len];
    let mut offset = 0usize;
    let mut count = [0u8; 4];
    for _ in 0..iter {
        let mut input = seed.to_vec();
        input.extend_from_slice(&count);
        let digest = hash_bytes(hash, &input);
        let take = hlen.min(mask_len - offset);
        mask[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        count[3] = count[3].wrapping_add(1);
    }
    mask
}

/// `rsa_init_encrypt_oaep` modulus check: `len >= 2 * hlen + 2`.
pub fn rsa_oaep_modulus_valid(hash: RsaOaepHash, n: &[u8]) -> bool {
    n.len() >= 2 * hash.hlen() + 2
}

fn check_oaep_params(hash: RsaOaepHash, n: &[u8], msg: &[u8]) -> Result<usize> {
    let mod_len = n.len();
    if !rsa_oaep_modulus_valid(hash, n) {
        return Err(Error::InvalidParam("RSA modulus too short for OAEP".into()));
    }
    let hlen = hash.hlen();
    if msg.len() > mod_len - 2 * hlen - 2 {
        return Err(Error::InvalidParam("OAEP message too long".into()));
    }
    Ok(mod_len)
}

/// OAEP encrypt (`seed` = `hlen` random bytes from PRNG in Cryptonite).
pub fn rsa_oaep_encrypt(
    hash: RsaOaepHash,
    n: &[u8],
    e: &[u8],
    msg: &[u8],
    label: Option<&[u8]>,
    seed: &[u8],
) -> Result<Vec<u8>> {
    let mod_len = check_oaep_params(hash, n, msg)?;
    let hlen = hash.hlen();
    if seed.len() != hlen {
        return Err(Error::InvalidParam(format!(
            "OAEP seed length {} (expected {hlen})",
            seed.len()
        )));
    }

    let dblen = mod_len - hlen - 1;
    let lhash = lhash(hash, label);

    let mut em = vec![0u8; mod_len];
    em[0] = 0;
    let (seed_db, masked_db) = em[1..].split_at_mut(hlen);
    let masked_seed = seed_db;

    masked_db.copy_from_slice(&mgf(hash, seed, dblen));

    let sep = mod_len - msg.len() - hlen - 2;
    for i in 0..dblen {
        if i < hlen {
            masked_db[i] ^= lhash[i];
        } else if i == sep {
            masked_db[i] ^= 1;
        } else if i > sep {
            masked_db[i] ^= msg[i - sep - 1];
        }
    }

    masked_seed.copy_from_slice(&mgf(hash, masked_db, hlen));
    for i in 0..hlen {
        masked_seed[i] ^= seed[i];
    }

    let n_int = bigint_from_cryptonite_bytes(n);
    let e_int = bigint_from_cryptonite_bytes(&pad_to_modulus(e, mod_len));
    let m_int = BigUint::from_bytes_be(&em);
    let c_int = m_int.modpow(&e_int, &n_int);
    Ok(bigint_to_cryptonite_bytes(&c_int, mod_len))
}

/// OAEP decrypt.
pub fn rsa_oaep_decrypt(
    hash: RsaOaepHash,
    n: &[u8],
    d: &[u8],
    ciphertext: &[u8],
    label: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mod_len = n.len();
    if !rsa_oaep_modulus_valid(hash, n) {
        return Err(Error::VerifyFailed);
    }
    if ciphertext.len() != mod_len {
        return Err(Error::InvalidParam(format!(
            "ciphertext length {} (expected {mod_len})",
            ciphertext.len()
        )));
    }

    let hlen = hash.hlen();
    let dblen = mod_len - hlen - 1;
    let lhash = lhash(hash, label);

    let n_int = bigint_from_cryptonite_bytes(n);
    let d_int = bigint_from_cryptonite_bytes(&pad_to_modulus(d, mod_len));
    let c_int = bigint_from_cryptonite_bytes(ciphertext);
    let em_int = c_int.modpow(&d_int, &n_int);
    let em = em_int_to_be_bytes(&em_int, mod_len);

    if em[0] != 0 {
        return Err(Error::VerifyFailed);
    }

    let masked_seed = &em[1..1 + hlen];
    let masked_db = &em[1 + hlen..];

    let mut seed = mgf(hash, masked_db, hlen);
    for i in 0..hlen {
        seed[i] ^= masked_seed[i];
    }

    let mut db = mgf(hash, &seed, dblen);
    for i in 0..dblen {
        db[i] ^= masked_db[i];
    }

    if db[..hlen] != lhash[..] {
        return Err(Error::VerifyFailed);
    }

    let mut moff = hlen;
    while moff < dblen && db[moff] != 0x01 {
        moff += 1;
    }
    if moff >= dblen {
        return Err(Error::VerifyFailed);
    }
    moff += 1;
    Ok(db[moff..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mgf_sha1_matches_rfc_test_vector_length() {
        let seed = [0u8; 20];
        let mask = mgf(RsaOaepHash::Sha1, &seed, 50);
        assert_eq!(mask.len(), 50);
    }
}
