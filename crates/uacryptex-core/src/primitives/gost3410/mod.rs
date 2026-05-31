//! GOST R 34.10-94 digital signature over GF(p) (legacy).
//!
//! Deprecated: use DSTU 4145 for new Ukrainian PKI. Enable with `--features legacy-gost3410`.

mod params;
mod util;
mod pubkey;
mod sign;
mod verify;

pub use params::{CurveParams, ParamsId, MODULE_BYTES};
pub use pubkey::{
    compress_pubkey, decompress_pubkey, get_pubkey, pubkey_be_from_spki_bitstring,
    pubkey_from_spki_bitstring,
};
pub use sign::{generate_private_key, sign, split_signature_be, Signature};
pub use verify::verify;
