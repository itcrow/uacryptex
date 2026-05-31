//! Adapter master PRNG (`cryptonite_manager.c` / `rs_std_next_bytes` + `prng_alloc`).

use std::sync::{Arc, Mutex};

use crate::primitives::dstu4145::{Dstu4145Prng, RandomBytes, SystemRandom};
use crate::{Error, Result};

/// Cryptonite `SignAdapter` master PRNG (`PRNG_MODE_DEFAULT` over DSTU PRNG).
#[derive(Clone)]
pub struct MasterPrng {
    inner: Arc<Mutex<Dstu4145Prng>>,
}

impl MasterPrng {
    pub fn new() -> Result<Self> {
        let mut seed = [0u8; 40];
        SystemRandom.fill(&mut seed)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Dstu4145Prng::new(&seed)?)),
        })
    }

    pub fn next_bytes(&self, out: &mut [u8]) -> Result<()> {
        let mut master = self
            .inner
            .lock()
            .map_err(|_| Error::Internal("master prng lock poisoned".into()))?;
        master.next_bytes(out)
    }

    /// DSTU PRNG for enveloped-data engine (`PRNG_MODE_DSTU`).
    pub fn dstu_prng(&self) -> Result<Dstu4145Prng> {
        let mut seed = [0u8; 40];
        self.next_bytes(&mut seed)?;
        Dstu4145Prng::new(&seed)
    }

    /// `prng_next_bytes` + `dstu4145_init_sign` inner seeding for one signature.
    pub fn dstu_sign_prng(&self) -> Result<Dstu4145Prng> {
        let mut master = self
            .inner
            .lock()
            .map_err(|_| Error::Internal("master prng lock poisoned".into()))?;
        let mut sign_seed = [0u8; 40];
        master.next_bytes(&mut sign_seed)?;
        let mut sign_prng = Dstu4145Prng::new(&sign_seed)?;
        let mut inner_seed = [0u8; 40];
        sign_prng.next_bytes(&mut inner_seed)?;
        Dstu4145Prng::new(&inner_seed)
    }
}
