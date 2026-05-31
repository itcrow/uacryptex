//! Pure Rust core for uacryptex — Ukrainian crypto, PKI, and storage.
//!
//! Cryptonite C sources are used only as a KAT oracle during migration.

pub mod error;
pub mod math;
pub mod pki;
pub mod primitives;
pub mod storage;

pub use error::{Error, Result};
pub use error::{
    RET_INVALID_PARAM, RET_MEMORY_ALLOC_ERROR, RET_OK, RET_PKIX_OBJ_NOT_FOUND, RET_VERIFY_FAILED,
};

/// Library version (semver).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
