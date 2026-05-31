//! Random bytes for DSTU 4145 signing.
//!
//! Production DSTU PRNG uses GOST 28147 ECB + GOST 34.311 (Cryptonite port).

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroize;

use crate::primitives::byte_utils::{uint64_to_uint8, uint8_swap};
use crate::primitives::gost28147::Gost28147;
use crate::primitives::gost34_311::Gost34311;
use crate::{Error, Result};

pub trait RandomBytes {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// OS CSPRNG (`getrandom`).
pub struct SystemRandom;

impl RandomBytes for SystemRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|e| Error::Internal(format!("random: {e}")))
    }
}

/// Deterministic byte stream for tests.
pub struct SliceRandom {
    data: Vec<u8>,
    pos: usize,
}

impl SliceRandom {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            pos: 0,
        }
    }
}

impl RandomBytes for SliceRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        for b in buf.iter_mut() {
            *b = self.data[self.pos % self.data.len()];
            self.pos += 1;
        }
        Ok(())
    }
}

fn current_time_le() -> [u8; 8] {
    let tm = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut time = [0u8; 8];
    uint64_to_uint8(tm, &mut time);
    uint8_swap(&mut time);
    time
}

/// DSTU 4145 PRNG (`dstu4145_prng_internal.c`).
pub struct Dstu4145Prng {
    time: [u32; 2],
    state: [u32; 2],
    old_state: [u32; 2],
    ecb: Gost28147,
    hash: Gost34311,
}

impl Drop for Dstu4145Prng {
    fn drop(&mut self) {
        self.time.zeroize();
        self.state.zeroize();
        self.old_state.zeroize();
    }
}

impl Dstu4145Prng {
    /// `dstu4145_prng_alloc`: `seed` is 32-byte key + 8-byte initial state (>= 40 bytes total).
    pub fn new(seed: &[u8]) -> Result<Self> {
        if seed.len() < 40 {
            return Err(Error::InvalidParam(
                "dstu4145 prng seed must be at least 40 bytes".into(),
            ));
        }

        let sync = [0u8; 32];
        let mut prng = Self {
            time: [0; 2],
            state: [0; 2],
            old_state: [0; 2],
            ecb: Gost28147::new(),
            hash: Gost34311::new(&sync)?,
        };

        prng.state = bytes_to_state(&seed[32..40]);
        prng.old_state = prng.state;

        prng.ecb.init_ecb(&seed[..32])?;
        let time = current_time_le();
        let mut encrypted = time;
        prng.ecb.ecb_encrypt(&time, &mut encrypted)?;
        prng.time = bytes_to_state(&encrypted);

        Ok(prng)
    }

    /// `dstu4145_prng_seed`.
    pub fn seed(&mut self, buf: &[u8]) -> Result<()> {
        self.hash.update(buf)?;
        self.hash.update(&state_bytes(self.state))?;
        self.hash.update(&state_bytes(self.time))?;
        let hash1 = self.hash.final_hash()?;

        self.hash.update(&hash1)?;
        self.hash.update(buf)?;
        self.hash.update(&state_bytes(self.state))?;
        self.hash.update(&state_bytes(self.time))?;
        let hash2 = self.hash.final_hash()?;

        self.state = bytes_to_state(&hash2[..8]);
        self.old_state = self.state;

        let time = current_time_le();
        self.ecb.init_ecb(&hash1)?;
        let mut encrypted = time;
        self.ecb.ecb_encrypt(&time, &mut encrypted)?;
        self.time = bytes_to_state(&encrypted);
        Ok(())
    }

    fn next_byte(&mut self) -> Result<u8> {
        let mut rnd = 0u8;
        for i in 0..8 {
            self.state[0] ^= self.time[0];
            self.state[1] ^= self.time[1];

            let mut block = state_bytes(self.state);
            self.ecb.ecb_encrypt_block8(&mut block)?;
            self.state = bytes_to_state(&block);

            let bit = block[0] & 1;
            rnd |= bit << i;

            self.state[0] ^= self.time[0];
            self.state[1] ^= self.time[1];
            let mut block = state_bytes(self.state);
            self.ecb.ecb_encrypt_block8(&mut block)?;
            self.state = bytes_to_state(&block);

            if self.state == self.old_state {
                return Err(Error::DstuPrngLooped);
            }
        }
        Ok(rnd)
    }

    /// `dstu4145_prng_next_bytes`.
    pub fn next_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        for b in buf.iter_mut() {
            *b = self.next_byte()?;
        }
        Ok(())
    }
}

impl RandomBytes for Dstu4145Prng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        self.next_bytes(buf)
    }
}

fn state_bytes(state: [u32; 2]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&state[0].to_le_bytes());
    out[4..].copy_from_slice(&state[1].to_le_bytes());
    out
}

fn bytes_to_state(bytes: &[u8]) -> [u32; 2] {
    [
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_fill_produces_bytes() {
        let mut seed = vec![0u8; 40];
        seed[0..32].fill(0x11);
        seed[32..40].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut prng = Dstu4145Prng::new(&seed).unwrap();
        let mut out = [0u8; 16];
        prng.fill(&mut out).unwrap();
        assert_ne!(out, [0u8; 16]);
    }

    #[test]
    fn rejects_seed_shorter_than_40_bytes() {
        assert!(Dstu4145Prng::new(&[0u8; 39]).is_err());
    }

    #[test]
    fn next_bytes_are_deterministic_for_same_instance() {
        let mut seed = vec![0u8; 40];
        seed[0..32].fill(0xaa);
        seed[32..40].copy_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);

        let mut prng = Dstu4145Prng::new(&seed).unwrap();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        prng.next_bytes(&mut first).unwrap();
        prng.next_bytes(&mut second).unwrap();

        let mut replay_first = [0u8; 32];
        prng.next_bytes(&mut replay_first).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, replay_first);
    }

    #[test]
    fn seed_changes_output_stream() {
        let mut seed = vec![0u8; 40];
        seed[0..32].fill(0x55);
        seed[32..40].copy_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);

        let mut prng = Dstu4145Prng::new(&seed).unwrap();
        let mut before = [0u8; 16];
        prng.next_bytes(&mut before).unwrap();

        prng.seed(b"reseed-input").unwrap();

        let mut after = [0u8; 16];
        prng.next_bytes(&mut after).unwrap();
        assert_ne!(before, after);
    }
}
