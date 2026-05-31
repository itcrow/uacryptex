//! RSA PKCS#1 v1.5 sign/verify (pre-hashed message), Cryptonite-compatible EMSA encoding.

use crate::error::{Error, Result};
use num_bigint_dig::BigUint;

/// Cryptonite stores RSA integers as little-endian bytes (`wa_alloc_from_ba`).
pub(crate) fn bigint_from_cryptonite_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

/// Pad LE integer to modulus width (Cryptonite `wa_change_len`: extend/truncate LSB side).
pub(crate) fn pad_to_modulus(value: &[u8], mod_len: usize) -> Vec<u8> {
    if value.len() >= mod_len {
        value[..mod_len].to_vec()
    } else {
        let mut out = value.to_vec();
        out.resize(mod_len, 0);
        out
    }
}

pub(crate) fn bigint_to_cryptonite_bytes(val: &BigUint, mod_len: usize) -> Vec<u8> {
    let mut le = val.to_bytes_le();
    if le.len() > mod_len {
        le.truncate(mod_len);
    } else if le.len() < mod_len {
        le.resize(mod_len, 0);
    }
    le
}

/// Cryptonite `AID_SHA*` from `rsa.c` (EM = 0x00 || 0x01 || PS || 0x00 || AID || hash).
const AID_SHA1: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const AID_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const AID_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const AID_SHA512: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Build EMSA-PKCS1-v1_5 message (`rsa_sign_pkcs1_v1_5` in Cryptonite `rsa.c`).
fn build_em(mod_len: usize, aid: &[u8], hash: &[u8]) -> Result<Vec<u8>> {
    let tlen = aid.len();
    let hlen = hash.len();
    if tlen + hlen + 11 > mod_len {
        return Err(Error::InvalidParam("RSA modulus too short for EMSA".into()));
    }
    let mut em = vec![0u8; mod_len];
    em[0] = 0;
    em[1] = 1;
    em[2..mod_len - hlen - tlen - 1].fill(0xff);
    em[mod_len - hlen - tlen - 1] = 0;
    em[mod_len - hlen - tlen..mod_len - hlen].copy_from_slice(aid);
    em[mod_len - hlen..].copy_from_slice(hash);
    Ok(em)
}

pub(crate) fn em_int_to_be_bytes(em: &BigUint, mod_len: usize) -> Vec<u8> {
    let be = em.to_bytes_be();
    let mut out = vec![0u8; mod_len];
    let start = mod_len.saturating_sub(be.len());
    out[start..].copy_from_slice(&be);
    out
}

/// Sign: `m^d mod n` on EMSA block (Cryptonite `rsaedp` + `wa_to_ba`).
fn sign_raw(n: &[u8], d: &[u8], aid: &[u8], hash: &[u8]) -> Result<Vec<u8>> {
    let mod_len = n.len();
    let n_int = bigint_from_cryptonite_bytes(n);
    let d_int = bigint_from_cryptonite_bytes(&pad_to_modulus(d, mod_len));
    let em = build_em(mod_len, aid, hash)?;
    let em_int = BigUint::from_bytes_be(&em);
    let sig = em_int.modpow(&d_int, &n_int);
    Ok(bigint_to_cryptonite_bytes(&sig, mod_len))
}

/// Verify: `m = s^e mod n` and EMSA check (`rsa_verify_pkcs1_v1_5`).
fn verify_raw(n: &[u8], e: &[u8], aid: &[u8], hash: &[u8], signature: &[u8]) -> Result<()> {
    let mod_len = n.len();
    let n_int = bigint_from_cryptonite_bytes(n);
    let e_int = bigint_from_cryptonite_bytes(&pad_to_modulus(e, mod_len));
    let sig_int = bigint_from_cryptonite_bytes(&pad_to_modulus(signature, mod_len));
    let em_int = sig_int.modpow(&e_int, &n_int);
    let em = em_int_to_be_bytes(&em_int, mod_len);

    let tlen = aid.len();
    let hlen = hash.len();
    if em[0] != 0 || em[1] != 1 {
        return Err(Error::VerifyFailed);
    }
    if em[mod_len - hlen - tlen - 1] != 0 {
        return Err(Error::VerifyFailed);
    }
    if !em[2..mod_len - hlen - tlen - 1].iter().all(|&b| b == 0xff) {
        return Err(Error::VerifyFailed);
    }
    if &em[mod_len - hlen - tlen..mod_len - hlen] != aid {
        return Err(Error::VerifyFailed);
    }
    if &em[mod_len - hlen..] != hash {
        return Err(Error::VerifyFailed);
    }
    Ok(())
}

fn check_hash_len(hash: &[u8], expected: usize) -> Result<()> {
    if hash.len() != expected {
        return Err(Error::InvalidParam(format!(
            "hash length {} (expected {expected})",
            hash.len()
        )));
    }
    Ok(())
}

macro_rules! impl_rsa_pkcs1 {
    ($sign:ident, $verify:ident, $aid:expr, $hash_len:expr) => {
        pub fn $sign(n: &[u8], _e: &[u8], d: &[u8], hash: &[u8]) -> Result<Vec<u8>> {
            check_hash_len(hash, $hash_len)?;
            sign_raw(n, d, $aid, hash)
        }

        pub fn $verify(n: &[u8], e: &[u8], hash: &[u8], signature: &[u8]) -> Result<()> {
            check_hash_len(hash, $hash_len)?;
            verify_raw(n, e, $aid, hash, signature)
        }
    };
}

impl_rsa_pkcs1!(
    rsa_pkcs1_v15_sign_sha1,
    rsa_pkcs1_v15_verify_sha1,
    &AID_SHA1,
    20
);
impl_rsa_pkcs1!(
    rsa_pkcs1_v15_sign_sha256,
    rsa_pkcs1_v15_verify_sha256,
    &AID_SHA256,
    32
);
impl_rsa_pkcs1!(
    rsa_pkcs1_v15_sign_sha384,
    rsa_pkcs1_v15_verify_sha384,
    &AID_SHA384,
    48
);
impl_rsa_pkcs1!(
    rsa_pkcs1_v15_sign_sha512,
    rsa_pkcs1_v15_verify_sha512,
    &AID_SHA512,
    64
);
