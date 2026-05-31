//! DSTU 7564:2014 Kupyna hash function and KMAC.
//!
//! Hash: `kupyna` crate (RustCrypto). KMAC: Cryptonite-compatible streaming (`kmac.rs`).

mod hash;
mod kmac;
mod kupyna_engine;

pub use hash::hash;
pub use kmac::{kmac, Kmac};
