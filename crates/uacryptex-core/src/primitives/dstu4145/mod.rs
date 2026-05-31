//! DSTU 4145-2002 elliptic curve digital signature over GF(2^m).
//!
//! Port target: `cryptonite/src/cryptonite/c/dstu4145*.c`

mod dh;
mod context;
mod curves;
mod onb;
#[path = "onb_data.rs"]
mod onb_data;
mod params;
mod prng;
mod pubkey;
mod sign;
mod verify;

pub use dh::dstu4145_dh;
pub use onb::OnbTables;

pub use context::{Context, ContextMode};
pub use curves::{DefaultParams, ParamsId};
pub use params::{CurveParams, FieldPolynomial, PublicKey, Signature};
pub use prng::{Dstu4145Prng, RandomBytes, SliceRandom, SystemRandom};
pub use pubkey::{
    compress_public_key, compressed_key_from_spki_bitstring, decompress_public_key,
    public_key_from_private_key,
};
pub use sign::{generate_private_key, public_key_from_private, sign};
pub use verify::verify;
