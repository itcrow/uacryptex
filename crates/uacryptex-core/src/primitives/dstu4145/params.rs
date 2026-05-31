//! Curve and field parameters for DSTU 4145.

use crate::{Error, Result};

/// Irreducible polynomial f(t) defining GF(2^m) in polynomial basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldPolynomial {
    /// Exponents of nonzero terms, highest degree first (e.g. `[163, 7, 6, 3, 0]`).
    pub f: Vec<u32>,
    /// Coefficient `a` in the curve equation (0 or 1).
    pub a: i32,
}

/// Elliptic curve parameters in polynomial basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurveParams {
    pub field: FieldPolynomial,
    /// True when coordinates are stored in optimal normal basis (ONB).
    pub is_onb: bool,
    /// Coefficient b (Cryptonite `ByteArray` octets).
    pub b: Vec<u8>,
    /// Order n of the base point subgroup (Cryptonite `ByteArray` octets).
    pub n: Vec<u8>,
    /// Base point coordinates (Cryptonite `ByteArray` octets).
    pub base_x: Vec<u8>,
    pub base_y: Vec<u8>,
}

/// Public key (affine coordinates, big-endian).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// Signature components. For DSTU 4145 over GF(2^m), r and s are often stored
/// little-endian in Cryptonite test vectors — see `Signature::from_le`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl Signature {
    pub fn from_be(r: impl Into<Vec<u8>>, s: impl Into<Vec<u8>>) -> Self {
        Self {
            r: r.into(),
            s: s.into(),
        }
    }

    pub fn from_le(r: impl Into<Vec<u8>>, s: impl Into<Vec<u8>>) -> Self {
        Self {
            r: r.into(),
            s: s.into(),
        }
    }
}

impl CurveParams {
    pub fn validate(&self) -> Result<()> {
        if self.field.f.is_empty() {
            return Err(Error::InvalidParam("empty field polynomial".into()));
        }
        if self.b.is_empty() || self.n.is_empty() {
            return Err(Error::InvalidParam("missing curve parameters".into()));
        }
        Ok(())
    }

    pub fn field_degree(&self) -> u32 {
        self.field.f[0]
    }
}
