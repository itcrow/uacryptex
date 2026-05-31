//! DSTU 4145 signing context (Cryptonite `Dstu4145Ctx` subset).

use super::params::{CurveParams, PublicKey};
use super::prng::RandomBytes;
use super::{sign, verify, Signature};
use crate::{Error, Result};

/// Operational mode for a DSTU 4145 context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMode {
    Sign,
    Verify,
}

/// Signing / verification context.
#[derive(Debug, Clone)]
pub struct Context {
    pub params: CurveParams,
    mode: Option<ContextMode>,
    private_key: Option<Vec<u8>>,
    public_key: Option<PublicKey>,
}

impl Context {
    pub fn new(params: CurveParams) -> Result<Self> {
        params.validate()?;
        Ok(Self {
            params,
            mode: None,
            private_key: None,
            public_key: None,
        })
    }

    pub fn mode(&self) -> Option<ContextMode> {
        self.mode
    }

    pub fn init_sign(&mut self, private_key: impl Into<Vec<u8>>) -> Result<()> {
        self.params.validate()?;
        self.private_key = Some(private_key.into());
        self.public_key = None;
        self.mode = Some(ContextMode::Sign);
        Ok(())
    }

    pub fn init_verify(&mut self, public_key: PublicKey) -> Result<()> {
        self.params.validate()?;
        if public_key.x.is_empty() || public_key.y.is_empty() {
            return Err(Error::InvalidParam("empty public key".into()));
        }
        self.public_key = Some(public_key);
        self.private_key = None;
        self.mode = Some(ContextMode::Verify);
        Ok(())
    }

    pub fn sign(&self, hash: &[u8], rng: &mut dyn RandomBytes) -> Result<Signature> {
        if self.mode != Some(ContextMode::Sign) {
            return Err(Error::InvalidParam("context not in sign mode".into()));
        }
        let key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::InvalidParam("missing private key".into()))?;
        sign::sign(&self.params, key, hash, rng)
    }

    pub fn verify(&self, hash: &[u8], signature: &Signature) -> Result<()> {
        if self.mode != Some(ContextMode::Verify) {
            return Err(Error::InvalidParam("context not in verify mode".into()));
        }
        let pk = self
            .public_key
            .as_ref()
            .ok_or_else(|| Error::InvalidParam("missing public key".into()))?;
        verify(&self.params, pk, hash, signature)
    }
}
