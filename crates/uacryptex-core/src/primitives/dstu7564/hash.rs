//! Kupyna (DSTU 7564) one-shot hash via the `kupyna` crate.

use kupyna::digest::{
    typenum::{U32, U38, U48, U6, U64},
    Digest,
};
use kupyna::{KupynaLong, KupynaShort};

use crate::{Error, Result};

/// Compute Kupyna digest with output length 1..=64 bytes (Cryptonite `dstu7564_init` + update + final).
pub fn hash(data: &[u8], output_len: usize) -> Result<Vec<u8>> {
    if output_len == 0 || output_len > 64 {
        return Err(Error::InvalidParam(format!(
            "Kupyna output length must be 1..=64, got {output_len}"
        )));
    }

    let mut out = vec![0u8; output_len];
    match output_len {
        6 => {
            let mut h = KupynaShort::<U6>::default();
            h.update(data);
            out.copy_from_slice(h.finalize().as_slice());
        }
        n if n <= 32 => {
            let mut h = KupynaShort::<U32>::default();
            h.update(data);
            out.copy_from_slice(&h.finalize()[..n]);
        }
        38 => {
            let mut h = KupynaLong::<U38>::default();
            h.update(data);
            out.copy_from_slice(h.finalize().as_slice());
        }
        48 => {
            let mut h = KupynaLong::<U48>::default();
            h.update(data);
            out.copy_from_slice(h.finalize().as_slice());
        }
        64 => {
            let mut h = KupynaLong::<U64>::default();
            h.update(data);
            out.copy_from_slice(h.finalize().as_slice());
        }
        n => {
            let mut h = KupynaLong::<U64>::default();
            h.update(data);
            out.copy_from_slice(&h.finalize()[..n]);
        }
    }
    Ok(out)
}
