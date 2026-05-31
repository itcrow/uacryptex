//! Key storage: PKCS#8, PKCS#12, cert store.
//!
//! Port target: `cryptonite/src/storage/`

pub mod pkcs5;
pub mod pkcs12;
pub mod pkcs8;

pub use pkcs12::{
    pkcs12_change_password, pkcs12_create, pkcs12_decode, pkcs12_encode, pkcs12_enum_keys,
    pkcs12_generate_key, pkcs12_get_certificates, pkcs12_get_dh_adapter, pkcs12_get_sign_adapter,
    pkcs12_get_storage_name, pkcs12_get_verify_adapter, pkcs12_is_key_generated,
    pkcs12_select_key, pkcs12_set_certificates, pkcs12_store_key, Pkcs12, Pkcs12AuthType,
    Pkcs12Keypair, Pkcs12MacType,
};
pub use pkcs8::{
    pkcs8_decode, pkcs8_encode, pkcs8_generate, pkcs8_get_dh_adapter, pkcs8_get_privatekey,
    pkcs8_get_sign_adapter, pkcs8_get_spki_der, pkcs8_get_verify_adapter, pkcs8_type,
    Pkcs8PrivateKeyType, PrivateKeyInfo,
};
