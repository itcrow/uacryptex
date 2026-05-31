//! Elliptic-curve points in projective coordinates (Cryptonite `math_ec_point_internal`).

use super::word::WordArray;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcPoint {
    pub x: WordArray,
    pub y: WordArray,
    pub z: WordArray,
}

impl EcPoint {
    pub fn with_len(len: usize) -> Self {
        Self {
            x: WordArray::with_zero(len),
            y: WordArray::with_zero(len),
            z: WordArray::with_zero(len),
        }
    }

    pub fn from_affine(px: &WordArray, py: &WordArray) -> Self {
        Self {
            x: px.clone(),
            y: py.clone(),
            z: WordArray::with_one(px.buf.len()),
        }
    }

    pub fn zero(len: usize) -> Self {
        let mut p = Self::with_len(len);
        p.set_infinity();
        p
    }

    pub fn set_infinity(&mut self) {
        self.x.zero();
        self.y.zero();
        self.z.set_one();
    }

    pub fn copy_from(&mut self, other: &EcPoint) {
        self.x.copy_from_slice(&other.x);
        self.y.copy_from_slice(&other.y);
        self.z.copy_from_slice(&other.z);
    }
}
