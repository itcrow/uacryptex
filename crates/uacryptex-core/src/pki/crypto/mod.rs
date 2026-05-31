//! PKI crypto adapters (`cryptonite_manager.h`).

mod aid;
mod cipher;
mod dh;
mod digest;
mod prng;
mod session_key;
mod signature_encoding;
mod sign;
mod verify;

pub use aid::{
    algorithm_identifier_der, curve_params_from_spki_algorithm, digest_algorithm_from_certificate,
    digest_aid_from_signature_oid, ecdsa_curve_from_spki_algorithm,
    ecdsa_signature_oid_for_digest_oid, gost3411_algorithm_der, is_dstu4145_signature_oid,
    is_ecdsa_signature_oid, oid_str_under, sbox_from_algorithm_der, spki_algorithm_der,
};
pub use cipher::{create_gost28147_wrap_aid, get_gost28147_aid, CipherAdapter};
pub use digest::DigestAdapter;
pub use dh::DhAdapter;
pub use prng::MasterPrng;
pub use session_key::{gost28147_generate_session_key, unwrap_session_key, wrap_session_key};
pub use sign::SignAdapter;
pub use verify::VerifyAdapter;

pub(crate) use sign::build_dstu_spki_der;
#[cfg(feature = "legacy-gost3410")]
pub(crate) use sign::build_gost3410_spki_der;
pub(crate) use signature_encoding::{sign_bitstring_to_raw, sign_raw_to_bitstring};

/// Cryptonite `OptLevelId` (stored; precomp tuning deferred).
pub type OptLevelId = u32;
