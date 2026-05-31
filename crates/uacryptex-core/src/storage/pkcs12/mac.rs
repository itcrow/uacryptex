//! PKCS#12 MAC (`pfx_calc_mac`, `pkcs12_key_gen_for_hmac`).

use der::asn1::Uint;

use crate::pki::oid::{oid_matches_str, OidId};
use crate::primitives::gost34_311::{hmac_gost3411, Gost34311};
use crate::primitives::intl::{hmac_sha1, hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512};
use crate::primitives::intl::{sha1_digest, sha224_digest, sha256_digest, sha384_digest, sha512_digest};
use crate::storage::pkcs12::types::{DigestInfo, MacData, Pfx};
use crate::{Error, Result};

fn uint_to_u32(value: &Uint) -> u32 {
    let mut out = 0u32;
    for byte in value.as_bytes() {
        out = (out << 8) | u32::from(*byte);
    }
    out
}

/// UTF-8 password to UTF-16BE with null terminator (Cryptonite `utf8_to_utf16be`).
pub fn utf8_to_utf16be_null(pass: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(pass.len() * 2 + 2);
    for ch in pass.encode_utf16() {
        out.extend_from_slice(&ch.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

fn expand_repeated(src: &[u8], dst: &mut [u8]) {
    if src.is_empty() {
        return;
    }
    let mut off = 0;
    while off + src.len() <= dst.len() {
        dst[off..off + src.len()].copy_from_slice(src);
        off += src.len();
    }
    if off < dst.len() {
        let rem = dst.len() - off;
        dst[off..off + rem].copy_from_slice(&src[..rem]);
    }
}

struct MacDigest {
    block_len: usize,
}

fn mac_digest_info(digest: &DigestInfo) -> Result<MacDigest> {
    let oid = digest.digest_algorithm.oid.to_string();
    let block_len = if oid_matches_str(OidId::PkiGost3411, &oid) {
        32
    } else if oid_matches_str(OidId::PkiSha1, &oid)
        || oid_matches_str(OidId::PkiSha224, &oid)
        || oid_matches_str(OidId::PkiSha256, &oid)
    {
        64
    } else if oid_matches_str(OidId::PkiSha384, &oid) || oid_matches_str(OidId::PkiSha512, &oid) {
        128
    } else {
        return Err(Error::Unsupported(format!(
            "unsupported PKCS#12 MAC digest OID: {oid}"
        )));
    };
    Ok(MacDigest { block_len })
}

fn hash_iteration(digest: &DigestInfo, msg: &[u8]) -> Result<Vec<u8>> {
    let oid = digest.digest_algorithm.oid.to_string();
    if oid_matches_str(OidId::PkiGost3411, &oid) {
        let sync = [0u8; 32];
        let mut h = Gost34311::new(&sync)?;
        h.update(msg)?;
        Ok(h.final_hash()?.to_vec())
    } else if oid_matches_str(OidId::PkiSha1, &oid) {
        Ok(sha1_digest(msg).to_vec())
    } else if oid_matches_str(OidId::PkiSha224, &oid) {
        Ok(sha224_digest(msg).to_vec())
    } else if oid_matches_str(OidId::PkiSha256, &oid) {
        Ok(sha256_digest(msg).to_vec())
    } else if oid_matches_str(OidId::PkiSha384, &oid) {
        Ok(sha384_digest(msg).to_vec())
    } else if oid_matches_str(OidId::PkiSha512, &oid) {
        Ok(sha512_digest(msg).to_vec())
    } else {
        Err(Error::Unsupported(format!("unsupported PKCS#12 MAC digest OID: {oid}")))
    }
}

/// RFC 7292 appendix B key derivation used by Cryptonite `pkcs12_key_gen_for_hmac`.
pub fn pkcs12_key_gen_for_hmac(
    digest: &DigestInfo,
    pass_utf16be: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>> {
    let cfg = mac_digest_info(digest)?;
    let d = vec![3u8; cfg.block_len];

    let slen = cfg.block_len * salt.len().div_ceil(cfg.block_len);
    let plen = if pass_utf16be.is_empty() {
        0
    } else {
        cfg.block_len * pass_utf16be.len().div_ceil(cfg.block_len)
    };

    let mut i_buf = vec![0u8; slen + plen];
    expand_repeated(salt, &mut i_buf[..slen]);
    if plen > 0 {
        expand_repeated(pass_utf16be, &mut i_buf[slen..]);
    }

    let mut msg = Vec::with_capacity(d.len() + i_buf.len());
    msg.extend_from_slice(&d);
    msg.extend_from_slice(&i_buf);
    let mut ai = hash_iteration(digest, &msg)?;

    for _ in 1..iterations {
        ai = hash_iteration(digest, &ai)?;
    }

    Ok(ai)
}

fn hmac_with_digest(digest: &DigestInfo, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let oid = digest.digest_algorithm.oid.to_string();
    if oid_matches_str(OidId::PkiGost3411, &oid) {
        let sync = [0u8; 32];
        Ok(hmac_gost3411(&sync, key, &[data])?.to_vec())
    } else if oid_matches_str(OidId::PkiSha1, &oid) {
        Ok(hmac_sha1(key, data).to_vec())
    } else if oid_matches_str(OidId::PkiSha224, &oid) {
        Ok(hmac_sha224(key, data).to_vec())
    } else if oid_matches_str(OidId::PkiSha256, &oid) {
        Ok(hmac_sha256(key, data).to_vec())
    } else if oid_matches_str(OidId::PkiSha384, &oid) {
        Ok(hmac_sha384(key, data).to_vec())
    } else if oid_matches_str(OidId::PkiSha512, &oid) {
        Ok(hmac_sha512(key, data).to_vec())
    } else {
        Err(Error::Unsupported(format!("unsupported PKCS#12 MAC digest OID: {oid}")))
    }
}

/// `pfx_calc_mac`.
pub fn pfx_calc_mac(pfx: &Pfx, password: &str, auth_safe_data: &[u8]) -> Result<Vec<u8>> {
    let mac_data = pfx
        .mac_data
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("PFX macData missing".into()))?;
    pfx_calc_mac_with_data(mac_data, password, auth_safe_data)
}

pub fn pfx_calc_mac_with_data(mac_data: &MacData, password: &str, auth_safe_data: &[u8]) -> Result<Vec<u8>> {
    let iterations = mac_data
        .iterations
        .as_ref()
        .map(uint_to_u32)
        .unwrap_or(1);
    let pass_utf16 = utf8_to_utf16be_null(password);
    let dk = pkcs12_key_gen_for_hmac(
        &mac_data.mac,
        &pass_utf16,
        mac_data.mac_salt.as_bytes(),
        iterations,
    )?;
    hmac_with_digest(&mac_data.mac, &dk, auth_safe_data)
}

/// `pfx_check_mac`.
pub fn pfx_check_mac(pfx: &Pfx, password: &str, auth_safe_data: &[u8]) -> Result<()> {
    let Some(mac_data) = &pfx.mac_data else {
        return Ok(());
    };
    let calculated = pfx_calc_mac_with_data(mac_data, password, auth_safe_data)?;
    if calculated.as_slice() != mac_data.mac.digest.as_bytes() {
        return Err(Error::VerifyFailed);
    }
    Ok(())
}
