//! Standard DSTU 4145 curve parameter sets (Cryptonite `dstu4145_params_internal.c`).

#[path = "curves_data.rs"]
mod curves_data;

use super::params::{CurveParams, FieldPolynomial};
use crate::{Error, Result};

pub use curves_data::DefaultParams;

/// Standard parameter set identifiers (`dstu4145.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ParamsId {
    M163Pb = 1,
    M167Pb = 2,
    M173Pb = 3,
    M179Pb = 4,
    M191Pb = 5,
    M233Pb = 6,
    M257Pb = 7,
    M307Pb = 8,
    M367Pb = 9,
    M431Pb = 10,
    M173Onb = 11,
    M179Onb = 12,
    M191Onb = 13,
    M233Onb = 14,
    M431Onb = 15,
}

impl ParamsId {
    pub fn default_params(self) -> &'static DefaultParams {
        use curves_data::*;
        match self {
            Self::M163Pb => &PARAMS_M163_PB,
            Self::M167Pb => &PARAMS_M167_PB,
            Self::M173Pb => &PARAMS_M173_PB,
            Self::M179Pb => &PARAMS_M179_PB,
            Self::M191Pb => &PARAMS_M191_PB,
            Self::M233Pb => &PARAMS_M233_PB,
            Self::M257Pb => &PARAMS_M257_PB,
            Self::M307Pb => &PARAMS_M307_PB,
            Self::M367Pb => &PARAMS_M367_PB,
            Self::M431Pb => &PARAMS_M431_PB,
            Self::M173Onb => &PARAMS_M173_ONB,
            Self::M179Onb => &PARAMS_M179_ONB,
            Self::M191Onb => &PARAMS_M191_ONB,
            Self::M233Onb => &PARAMS_M233_ONB,
            Self::M431Onb => &PARAMS_M431_ONB,
        }
    }

    pub fn curve_params(self) -> Result<CurveParams> {
        self.default_params().to_curve_params()
    }

    pub fn is_onb(self) -> bool {
        self.default_params().is_onb
    }
}

impl DefaultParams {
    pub fn to_curve_params(&self) -> Result<CurveParams> {
        if self.is_onb {
            CurveParams::normal_basis(self.f, self.a, self.b, self.n, self.px, self.py)
        } else {
            CurveParams::polynomial_basis(self.f, self.a, self.b, self.n, self.px, self.py)
        }
    }
}

fn trim_ba(bytes: &[u8]) -> Vec<u8> {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(1);
    bytes[..end].to_vec()
}

impl CurveParams {
    /// Build curve parameters in polynomial basis from Cryptonite `ByteArray` octets.
    pub fn polynomial_basis(
        f: &[i32],
        a: i32,
        b: &[u8],
        n: &[u8],
        base_x: &[u8],
        base_y: &[u8],
    ) -> Result<Self> {
        Self::from_field(f, a, false, b, n, base_x, base_y)
    }

    /// Build curve parameters in normal (ONB) basis.
    pub fn normal_basis(
        f: &[i32],
        a: i32,
        b: &[u8],
        n: &[u8],
        base_x: &[u8],
        base_y: &[u8],
    ) -> Result<Self> {
        Self::from_field(f, a, true, b, n, base_x, base_y)
    }

    fn from_field(
        f: &[i32],
        a: i32,
        is_onb: bool,
        b: &[u8],
        n: &[u8],
        base_x: &[u8],
        base_y: &[u8],
    ) -> Result<Self> {
        if f.len() != 3 && f.len() != 5 {
            return Err(Error::InvalidParam(
                "field polynomial f must have 3 or 5 terms".into(),
            ));
        }
        Ok(Self {
            field: FieldPolynomial {
                f: f.iter().map(|&e| e as u32).collect(),
                a,
            },
            is_onb,
            b: trim_ba(b),
            n: trim_ba(n),
            base_x: trim_ba(base_x),
            base_y: trim_ba(base_y),
        })
    }

    /// Cryptonite `dstu4145_equals_params` for parameter blocks.
    pub fn equals(&self, other: &Self) -> bool {
        if self.is_onb != other.is_onb {
            return false;
        }
        if self.field.f.len() != other.field.f.len() {
            return false;
        }
        if self.field.f != other.field.f || self.field.a != other.field.a {
            return false;
        }
        self.b == other.b
            && self.n == other.n
            && self.base_x == other.base_x
            && self.base_y == other.base_y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m163_default_matches_verify_pn_kat_hex() {
        let params = ParamsId::M163Pb.curve_params().unwrap();
        let s = "5ff6108462a2dc8210ab403925e638a19c1455d21";
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        let mut b = hex::decode(s).unwrap();
        b.reverse();
        assert_eq!(params.b, b);
        assert!(!params.is_onb);
    }

    #[test]
    fn equals_params_same_id() {
        let a = ParamsId::M163Pb.curve_params().unwrap();
        let b = ParamsId::M163Pb.curve_params().unwrap();
        assert!(a.equals(&b));
    }

    #[test]
    fn equals_params_different_curves() {
        let a = ParamsId::M163Pb.curve_params().unwrap();
        let b = ParamsId::M173Onb.curve_params().unwrap();
        assert!(!a.equals(&b));
    }
}
