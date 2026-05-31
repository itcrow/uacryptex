//! PKCS#12 keystores (Cryptonite `storage/c/file/pkcs12.c`).

mod builder;
mod content;
mod mac;
mod types;

pub use builder::{
    pkcs12_change_password, pkcs12_create, pkcs12_encode, pkcs12_generate_key,
    pkcs12_get_dh_adapter, pkcs12_is_key_generated, pkcs12_store_key,
};
pub use content::{
    cert_bag_x509_der, cinfo_get_data, cinfo_type, encode_authenticated_safe,
    encode_content_info_data, encode_content_info_encrypted, pfx_get_contents, safebag_alias,
    safebag_type, CertBag, CinfoType, ContentsEntry, SafeBagType,
};
pub use mac::{pfx_calc_mac, pfx_check_mac, pkcs12_key_gen_for_hmac, utf8_to_utf16be_null};
pub use types::{
    decode_pfx, AuthenticatedSafe, DigestInfo, EncryptedContentInfo, EncryptedData, MacData, Pfx,
    SafeBag, SafeContents,
};

use crate::pki::cert::Cert;
use crate::pki::crypto::{SignAdapter, VerifyAdapter};
use crate::pki::oid::{oid_matches_str, OidId};
use crate::storage::pkcs12::content::auth_safe_octets;
use crate::storage::pkcs5::{pkcs5_decrypt_dstu, EncryptedPrivateKeyInfo};
use crate::storage::pkcs8::{
    is_private_key_info, pkcs8_decode, pkcs8_get_sign_adapter, pkcs8_get_verify_adapter,
    PrivateKeyInfo,
};
use crate::{Error, Result};

/// Cryptonite `Pkcs12MacType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs12MacType {
    Gost34311,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// Cryptonite `Pkcs12AuthType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pkcs12AuthType {
    KeyPass,
    NoPass,
    StoragePass,
}

/// Cryptonite `Pkcs12Keypair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs12Keypair {
    pub alias: String,
    pub auth: Pkcs12AuthType,
    pub int_id: i32,
}

/// Opened PKCS#12 store.
#[derive(Debug)]
pub struct Pkcs12 {
    name: Option<String>,
    password: String,
    mac_data: MacData,
    mac_type: Pkcs12MacType,
    modified: bool,
    entries: Vec<ContentsEntry>,
    keypairs: Vec<Pkcs12Keypair>,
    curr_key: Option<PrivateKeyInfo>,
    extra_certs: Vec<Vec<u8>>,
    genkey: Option<PrivateKeyInfo>,
}

impl Pkcs12 {
    pub fn storage_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn keypairs(&self) -> &[Pkcs12Keypair] {
        &self.keypairs
    }

    pub fn entries(&self) -> &[ContentsEntry] {
        &self.entries
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn mac_type(&self) -> Pkcs12MacType {
        self.mac_type
    }

    pub(crate) fn rebuild_keypairs(&mut self) -> Result<()> {
        let mut keypairs = Vec::new();
        let mut count = 0usize;
        for entry in &self.entries {
            for bag in &entry.bags {
                match safebag_type(bag) {
                    SafeBagType::KeyBag => {
                        keypairs.push(Pkcs12Keypair {
                            alias: safebag_alias(bag, count)?,
                            auth: Pkcs12AuthType::NoPass,
                            int_id: count as i32,
                        });
                        count += 1;
                    }
                    SafeBagType::Pkcs8ShroudedKeyBag => {
                        let epki = bag
                            .bag_value
                            .decode_as::<crate::storage::pkcs5::EncryptedPrivateKeyInfo>()
                            .map_err(|e| {
                                Error::Internal(format!("EncryptedPrivateKeyInfo decode: {e}"))
                            })?;
                        let auth = match pkcs5_decrypt_dstu(&epki, &self.password) {
                            Ok(plain) if is_private_key_info(&plain) => Pkcs12AuthType::StoragePass,
                            Ok(_) => Pkcs12AuthType::KeyPass,
                            Err(_) => Pkcs12AuthType::KeyPass,
                        };
                        keypairs.push(Pkcs12Keypair {
                            alias: safebag_alias(bag, count)?,
                            auth,
                            int_id: count as i32,
                        });
                        count += 1;
                    }
                    _ => {}
                }
            }
        }
        self.keypairs = keypairs;
        Ok(())
    }
}

fn cert_matches_key(cert_der: &[u8], key: &PrivateKeyInfo) -> Result<bool> {
    let cert = Cert::decode(cert_der)?;
    let private_key = crate::storage::pkcs8::pkcs8_get_privatekey(key)?;
    Ok(crate::pki::crypto::SignAdapter::init_by_cert(&private_key, &cert).is_ok())
}

/// `pkcs12_decode`.
pub fn pkcs12_decode(
    storage_name: Option<&str>,
    storage_body: &[u8],
    password: &str,
) -> Result<Pkcs12> {
    let pfx = types::decode_pfx(storage_body)?;
    let auth_data = auth_safe_octets(&pfx)?;
    mac::pfx_check_mac(&pfx, password, &auth_data)?;
    let entries = pfx_get_contents(&pfx, password)?;
    let mac_data = pfx
        .mac_data
        .clone()
        .ok_or_else(|| Error::InvalidParam("PFX macData missing".into()))?;
    let mac_type = mac_type_from_digest(&mac_data.mac)?;
    let mut store = Pkcs12 {
        name: storage_name.map(str::to_owned),
        password: password.to_owned(),
        mac_data,
        mac_type,
        modified: false,
        entries,
        keypairs: Vec::new(),
        curr_key: None,
        extra_certs: Vec::new(),
        genkey: None,
    };
    store.rebuild_keypairs()?;
    Ok(store)
}

/// `pkcs12_get_storage_name`.
pub fn pkcs12_get_storage_name(store: &Pkcs12) -> Option<&str> {
    store.storage_name()
}

/// `pkcs12_enum_keys`.
pub fn pkcs12_enum_keys(store: &mut Pkcs12) -> Result<&[Pkcs12Keypair]> {
    store.rebuild_keypairs()?;
    Ok(&store.keypairs)
}

/// `pkcs12_select_key`.
pub fn pkcs12_select_key(store: &mut Pkcs12, alias: Option<&str>, pwd: Option<&str>) -> Result<()> {
    if store.keypairs.is_empty() {
        store.rebuild_keypairs()?;
    }

    let keypair = if let Some(alias) = alias {
        store.keypairs.iter().find(|k| k.alias == alias)
    } else if !store.keypairs.is_empty() {
        Some(&store.keypairs[0])
    } else {
        None
    };

    let keypair = keypair.ok_or(Error::StorageNoKey)?;

    let mut count = 0usize;
    for entry in &store.entries {
        for bag in &entry.bags {
            match safebag_type(bag) {
                SafeBagType::KeyBag => {
                    if count == keypair.int_id as usize {
                        let pki = bag
                            .bag_value
                            .decode_as::<PrivateKeyInfo>()
                            .map_err(|e| Error::Internal(format!("PrivateKeyInfo decode: {e}")))?;
                        store.curr_key = Some(pki);
                        return Ok(());
                    }
                    count += 1;
                }
                SafeBagType::Pkcs8ShroudedKeyBag => {
                    if count == keypair.int_id as usize {
                        let epki = bag
                            .bag_value
                            .decode_as::<EncryptedPrivateKeyInfo>()
                            .map_err(|e| {
                                Error::Internal(format!("EncryptedPrivateKeyInfo decode: {e}"))
                            })?;
                        let pass = pwd.unwrap_or(&store.password);
                        let plain = pkcs5_decrypt_dstu(&epki, pass)?;
                        store.curr_key = Some(
                            pkcs8_decode(&plain).map_err(|_| Error::StorageInvalidKeyPassword)?,
                        );
                        return Ok(());
                    }
                    count += 1;
                }
                _ => {}
            }
        }
    }

    store.curr_key = None;
    Err(Error::StorageNoKey)
}

/// Attach external certificates (Cryptonite `pkcs12_set_certificates`).
pub fn pkcs12_set_certificates(store: &mut Pkcs12, certs: &[&[u8]]) -> Result<()> {
    for cert in certs {
        store.extra_certs.push(cert.to_vec());
    }
    builder::pkcs12_set_certificates_encrypted(store, certs)
}

/// `pkcs12_get_certificates`.
pub fn pkcs12_get_certificates(store: &Pkcs12) -> Result<Vec<Vec<u8>>> {
    let mut certs = store.extra_certs.clone();
    for entry in &store.entries {
        for bag in &entry.bags {
            if safebag_type(bag) == SafeBagType::CertBag {
                certs.push(cert_bag_x509_der(&bag.bag_value)?);
            }
        }
    }
    Ok(certs)
}

/// `pkcs12_get_certificate` — returns `None` when no matching cert (not an error).
pub fn pkcs12_get_certificate(store: &Pkcs12, _key_usage: i32) -> Result<Option<Vec<u8>>> {
    let key = store
        .curr_key
        .as_ref()
        .ok_or(Error::StorageKeyNotSelected)?;

    for cert_der in pkcs12_get_certificates(store)? {
        if cert_matches_key(&cert_der, key)? {
            return Ok(Some(cert_der));
        }
    }
    Ok(None)
}

/// `pkcs12_get_sign_adapter`.
pub fn pkcs12_get_sign_adapter(store: &Pkcs12) -> Result<SignAdapter> {
    let key = store
        .curr_key
        .as_ref()
        .ok_or(Error::StorageKeyNotSelected)?;
    let cert = match pkcs12_get_certificate(store, 0)? {
        Some(der) => Some(Cert::decode(&der)?),
        None => None,
    };
    pkcs8_get_sign_adapter(key, cert.as_ref())
}

/// `pkcs12_get_verify_adapter`.
pub fn pkcs12_get_verify_adapter(store: &Pkcs12) -> Result<VerifyAdapter> {
    let key = store
        .curr_key
        .as_ref()
        .ok_or(Error::StorageKeyNotSelected)?;
    pkcs8_get_verify_adapter(key)
}

fn mac_type_from_digest(digest: &types::DigestInfo) -> Result<Pkcs12MacType> {
    let oid = digest.digest_algorithm.oid.to_string();
    if oid_matches_str(OidId::PkiGost3411, &oid) {
        Ok(Pkcs12MacType::Gost34311)
    } else if oid_matches_str(OidId::PkiSha1, &oid) {
        Ok(Pkcs12MacType::Sha1)
    } else if oid_matches_str(OidId::PkiSha224, &oid) {
        Ok(Pkcs12MacType::Sha224)
    } else if oid_matches_str(OidId::PkiSha256, &oid) {
        Ok(Pkcs12MacType::Sha256)
    } else if oid_matches_str(OidId::PkiSha384, &oid) {
        Ok(Pkcs12MacType::Sha384)
    } else if oid_matches_str(OidId::PkiSha512, &oid) {
        Ok(Pkcs12MacType::Sha512)
    } else {
        Err(Error::Unsupported(format!(
            "unsupported PKCS#12 MAC digest OID: {oid}"
        )))
    }
}
