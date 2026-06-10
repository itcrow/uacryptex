//! Session key wrap/unwrap (`wrap_session_key`, `unwrap_session_key`).

use crate::pki::crypto::aid::sbox_from_algorithm_der;
use crate::pki::crypto::DhAdapter;
use crate::primitives::dstu4145::{Dstu4145Prng, RandomBytes, SystemRandom};
use crate::primitives::gost28147::{unwrap_key, wrap_key, WRAP_KEY_LEN};
use crate::primitives::gost34_311::Gost34311;
use crate::{Error, Result};

/// DER OID bytes for GOST28147 wrap (`CFB_WRAP_OID` in Cryptonite).
const CFB_WRAP_OID: [u8; 13] = [
    0x06, 0x0b, 0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x05,
];

const KEY_LENGTH_BITS: i32 = 256;
const WRAP_KEY_LEN_DOUBLE: usize = WRAP_KEY_LEN * 2;

/// `wrap_session_key`.
pub fn wrap_session_key(
    dha: &DhAdapter,
    recipient_pub_key: &[u8],
    session_key: &[u8],
    rnd_bytes: &[u8],
) -> Result<Vec<u8>> {
    if rnd_bytes.len() != 64 {
        return Err(Error::InvalidParam("UKM must be 64 bytes".into()));
    }

    let (zx, _zy) = dha.dh(recipient_pub_key)?;
    let kek = iso15946_generate_secretc(&zx, Some(rnd_bytes))?;
    let sbox = sbox_from_algorithm_der(dha.algorithm_der())?;
    let mut seed = [0u8; 40];
    SystemRandom.fill(&mut seed)?;
    let mut prng = Dstu4145Prng::new(&seed)?;

    match session_key.len() {
        32 => {
            let session_key: [u8; 32] = session_key
                .try_into()
                .map_err(|_| Error::InvalidParam("session key must be 32 bytes".into()))?;
            Ok(wrap_key(&sbox, &kek, &session_key, &mut prng)?.to_vec())
        }
        64 => {
            let first: [u8; 32] = session_key[..32]
                .try_into()
                .map_err(|_| Error::InvalidParam("invalid session key".into()))?;
            let second: [u8; 32] = session_key[32..]
                .try_into()
                .map_err(|_| Error::InvalidParam("invalid session key".into()))?;
            let w1 = wrap_key(&sbox, &kek, &first, &mut prng)?;
            let w2 = wrap_key(&sbox, &kek, &second, &mut prng)?;
            let mut out = Vec::with_capacity(WRAP_KEY_LEN_DOUBLE);
            out.extend_from_slice(&w1);
            out.extend_from_slice(&w2);
            Ok(out)
        }
        n => Err(Error::InvalidParam(format!(
            "session key must be 32 or 64 bytes, got {n}"
        ))),
    }
}

/// `unwrap_session_key`.
pub fn unwrap_session_key(
    dha: &DhAdapter,
    wrapped_key: &[u8],
    rnd_bytes: Option<&[u8]>,
    originator_pub_key: &[u8],
) -> Result<Vec<u8>> {
    if let Some(ukm) = rnd_bytes {
        if ukm.len() != 64 {
            return Err(Error::InvalidParam("UKM must be 64 bytes".into()));
        }
    }

    let (zx, _zy) = dha.dh(originator_pub_key)?;
    let kek = iso15946_generate_secretc(&zx, rnd_bytes)?;
    let sbox = sbox_from_algorithm_der(dha.algorithm_der())?;

    match wrapped_key.len() {
        WRAP_KEY_LEN => {
            let wrapped_arr: [u8; WRAP_KEY_LEN] = wrapped_key
                .try_into()
                .map_err(|_| Error::InvalidParam("invalid wrapped key length".into()))?;
            Ok(unwrap_key(&sbox, &kek, &wrapped_arr)?.to_vec())
        }
        WRAP_KEY_LEN_DOUBLE => {
            let w1: [u8; WRAP_KEY_LEN] = wrapped_key[..WRAP_KEY_LEN]
                .try_into()
                .map_err(|_| Error::InvalidParam("invalid wrapped key length".into()))?;
            let w2: [u8; WRAP_KEY_LEN] = wrapped_key[WRAP_KEY_LEN..]
                .try_into()
                .map_err(|_| Error::InvalidParam("invalid wrapped key length".into()))?;
            let k1 = unwrap_key(&sbox, &kek, &w1)?;
            let k2 = unwrap_key(&sbox, &kek, &w2)?;
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&k1);
            out.extend_from_slice(&k2);
            Ok(out)
        }
        n => Err(Error::InvalidParam(format!(
            "wrapped key must be {WRAP_KEY_LEN} or {} bytes, got {n}",
            WRAP_KEY_LEN * 2
        ))),
    }
}

fn iso15946_generate_secretc(zx: &[u8], entity_info: Option<&[u8]>) -> Result<[u8; 32]> {
    let shared_info = build_shared_info(entity_info)?;
    let sync = [0u8; 32];
    let mut ctx = Gost34311::new(&sync)?;

    let hash_data = strip_trailing_zero(zx);
    let mut swapped = hash_data.clone();
    crate::primitives::gost28147::byte_swap(&mut swapped);
    ctx.update(&swapped)?;

    let counter = [0u8, 0, 0, 1];
    ctx.update(&counter)?;
    ctx.update(&shared_info)?;

    let digest = ctx.final_hash()?;
    Ok(digest)
}

fn build_shared_info(entity_info: Option<&[u8]>) -> Result<Vec<u8>> {
    let supp_pub_info_len = 8usize;
    let alg_id_len = 4 + CFB_WRAP_OID.len();
    let mut shared_info_len = 14 + CFB_WRAP_OID.len();
    if entity_info.is_some() {
        shared_info_len += 68;
    }

    let mut encode = vec![0u8; shared_info_len];
    encode[0] = 0x30;
    encode[1] = (shared_info_len - 2) as u8;
    encode[2] = 0x30;
    encode[3] = (alg_id_len - 2) as u8;
    encode[4..4 + CFB_WRAP_OID.len()].copy_from_slice(&CFB_WRAP_OID);
    encode[alg_id_len] = 0x05;
    encode[alg_id_len + 1] = 0x00;

    if let Some(entity_info) = entity_info {
        let entity_info_len = entity_info.len();
        if entity_info_len > 255 {
            return Err(Error::InvalidParam("entity_info too long".into()));
        }
        let off = alg_id_len + 2;
        encode[off] = 0xa0;
        encode[off + 1] = (entity_info_len + 2) as u8;
        encode[off + 2] = 0x04;
        encode[off + 3] = entity_info_len as u8;
        encode[off + 4..off + 4 + entity_info_len].copy_from_slice(entity_info);
    }

    let tail = shared_info_len - supp_pub_info_len;
    encode[tail] = 0xa2;
    encode[tail + 1] = 6;
    encode[tail + 2] = 0x04;
    encode[tail + 3] = 0x04;
    int2be(KEY_LENGTH_BITS, &mut encode[tail + 4..tail + 8]);
    Ok(encode)
}

fn int2be(src: i32, dst: &mut [u8]) {
    for (i, b) in dst.iter_mut().enumerate() {
        *b = (src >> (24 - i * 8)) as u8;
    }
}

fn strip_trailing_zero(zx: &[u8]) -> Vec<u8> {
    let mut len = zx.len();
    while len > 0 && zx[len - 1] == 0 {
        len -= 1;
    }
    if len == 0 {
        vec![0]
    } else {
        zx[..len].to_vec()
    }
}

/// `gost28147_generate_key`.
pub fn gost28147_generate_session_key(rng: &mut dyn RandomBytes) -> Result<Vec<u8>> {
    generate_session_key(32, rng)
}

/// Generate a random content-encryption key of `len` bytes.
pub fn generate_session_key(len: usize, rng: &mut dyn RandomBytes) -> Result<Vec<u8>> {
    if len == 0 {
        return Err(Error::InvalidParam("session key length is zero".into()));
    }
    let mut key = vec![0u8; len];
    rng.fill(&mut key)?;
    Ok(key)
}
