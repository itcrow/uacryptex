//! PKCS#12 create / encode (`pkcs12_create`, `pkcs12_encode`, …).

use der::asn1::{Any, BmpString, ObjectIdentifier, OctetString, SetOfVec, Uint};
use der::{Decode, Encode};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::cms::ContentInfo;
use crate::pki::crypto::{algorithm_identifier_der, DhAdapter};
use crate::pki::ext::pkix_key_id_from_spki_der;
use crate::pki::oid::{oid_matches_str, OidId};
use crate::storage::pkcs5::{
    aes256_cbc_encryption_aid, gost28147_cfb_encryption_aid, pkcs12_random_salt,
    pkcs5_encrypt_dstu, pkcs5_reencrypt_pbes2, random_aes_iv, random_gost28147_iv,
};
use crate::storage::pkcs8::{pkcs8_encode, pkcs8_generate, pkcs8_get_spki_der, PrivateKeyInfo};
use crate::storage::pkcs12::content::{
    encode_authenticated_safe, encode_content_info_data, encode_content_info_encrypted,
    CertBag, ContentsEntry,
};
use crate::storage::pkcs12::mac::pfx_calc_mac_with_data;
use crate::storage::pkcs12::types::{DigestInfo, MacData, Pfx, SafeBag, SafeContents};
use crate::storage::pkcs12::{Pkcs12, Pkcs12MacType};
use crate::{Error, Result};

const KEY_BAG_OID: &str = "1.2.840.113549.1.12.10.1.1";
const PKCS8_SHROUDED_KEY_BAG_OID: &str = "1.2.840.113549.1.12.10.1.2";
const CERT_BAG_OID: &str = "1.2.840.113549.1.12.10.1.3";
const FRIENDLY_NAME_OID: &str = "1.2.840.113549.1.9.20";
const LOCAL_KEY_ID_OID: &str = "1.2.840.113549.1.9.21";
const X509_CERTIFICATE_OID: &str = "1.2.840.113549.1.9.22.1";
const DEFAULT_KEY_SALT_LEN: usize = 32;

pub(crate) fn u32_to_uint(value: u32) -> Result<Uint> {
    if value == 0 {
        return Uint::new(&[0u8]).map_err(|e| Error::Internal(format!("uint: {e}")));
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(7);
    Uint::new(&be[start..]).map_err(|e| Error::Internal(format!("uint: {e}")))
}

pub(crate) fn create_empty_mac_data(mac_type: Pkcs12MacType, rounds: u32) -> Result<MacData> {
    let (salt_len, digest_len, digest_oid) = match mac_type {
        Pkcs12MacType::Gost34311 => (32, 32, OidId::PkiGost3411),
        Pkcs12MacType::Sha1 => (8, 20, OidId::PkiSha1),
        Pkcs12MacType::Sha224 => (8, 28, OidId::PkiSha224),
        Pkcs12MacType::Sha256 => (8, 32, OidId::PkiSha256),
        Pkcs12MacType::Sha384 => (8, 48, OidId::PkiSha384),
        Pkcs12MacType::Sha512 => (8, 64, OidId::PkiSha512),
    };
    let salt = pkcs12_random_salt(salt_len)?;
    let digest_alg = algorithm_identifier_der(digest_oid, Some(&Any::null()))?;
    let digest_algorithm: AlgorithmIdentifier<Any> =
        AlgorithmIdentifier::from_der(&digest_alg)
            .map_err(|e| Error::Internal(format!("digest aid decode: {e}")))?;
    Ok(MacData {
        mac: DigestInfo {
            digest_algorithm,
            digest: OctetString::new(vec![0u8; digest_len])
                .map_err(|e| Error::Internal(format!("mac digest: {e}")))?,
        },
        mac_salt: OctetString::new(salt).map_err(|e| Error::Internal(format!("mac salt: {e}")))?,
        iterations: Some(u32_to_uint(rounds)?),
    })
}

/// `pkcs12_create`.
pub fn pkcs12_create(
    mac_type: Pkcs12MacType,
    password: &str,
    rounds: u32,
) -> Result<Pkcs12> {
    Ok(Pkcs12 {
        name: None,
        password: password.to_owned(),
        mac_data: create_empty_mac_data(mac_type, rounds)?,
        mac_type,
        modified: true,
        entries: Vec::new(),
        keypairs: Vec::new(),
        curr_key: None,
        extra_certs: Vec::new(),
        genkey: None,
    })
}

/// `pkcs12_is_key_generated`.
pub fn pkcs12_is_key_generated(store: &Pkcs12) -> bool {
    store.genkey.is_some()
}

/// `pkcs12_generate_key`.
pub fn pkcs12_generate_key(store: &mut Pkcs12, aid: Option<&[u8]>) -> Result<()> {
    store.genkey = Some(pkcs8_generate(aid)?);
    Ok(())
}

fn bag_oid_from_str(oid: &str) -> Result<ObjectIdentifier> {
    ObjectIdentifier::new(oid).map_err(|e| Error::Internal(format!("bag oid: {e}")))
}

fn mac_iterations(store: &Pkcs12) -> u32 {
    store
        .mac_data
        .iterations
        .as_ref()
        .map(|v| {
            let bytes = v.as_bytes();
            bytes.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b))
        })
        .unwrap_or(1)
}

fn encryption_aid_for_store(store: &Pkcs12) -> Result<AlgorithmIdentifier<Any>> {
    if oid_matches_str(
        OidId::PkiGost3411,
        &store.mac_data.mac.digest_algorithm.oid.to_string(),
    ) {
        gost28147_cfb_encryption_aid(&random_gost28147_iv()?)
    } else {
        aes256_cbc_encryption_aid(&random_aes_iv()?)
    }
}

fn build_key_safebag(
    alias: Option<&str>,
    key: &PrivateKeyInfo,
    key_pass: Option<&str>,
    rounds: u32,
) -> Result<SafeBag> {
    let (bag_id, bag_value) = if let Some(pass) = key_pass {
        let encoded = pkcs8_encode(key)?;
        let salt = pkcs12_random_salt(DEFAULT_KEY_SALT_LEN)?;
        let iv = random_gost28147_iv()?;
        let encrypt_aid = gost28147_cfb_encryption_aid(&iv)?;
        let epki = pkcs5_encrypt_dstu(&encoded, pass, &salt, rounds, &encrypt_aid)?;
        (
            bag_oid_from_str(PKCS8_SHROUDED_KEY_BAG_OID)?,
            Any::encode_from(&epki)
                .map_err(|e| Error::Internal(format!("EPKI encode: {e}")))?,
        )
    } else {
        (
            bag_oid_from_str(KEY_BAG_OID)?,
            Any::encode_from(key).map_err(|e| Error::Internal(format!("PKI encode: {e}")))?,
        )
    };

    let spki = pkcs8_get_spki_der(key)?;
    let key_id = pkix_key_id_from_spki_der(&spki)?;
    let mut attr_vec = vec![Attribute {
        oid: bag_oid_from_str(LOCAL_KEY_ID_OID)?,
        values: SetOfVec::try_from(vec![Any::encode_from(
            &OctetString::new(key_id).map_err(|e| Error::Internal(format!("key id: {e}")))?,
        )
        .map_err(|e| Error::Internal(format!("key id attr: {e}")))?])
        .map_err(|e| Error::Internal(format!("key id set: {e}")))?,
    }];

    if let Some(alias) = alias {
        let bmp = BmpString::from_utf8(alias)
            .map_err(|e| Error::Internal(format!("friendlyName: {e}")))?;
        attr_vec.push(Attribute {
            oid: bag_oid_from_str(FRIENDLY_NAME_OID)?,
            values: SetOfVec::try_from(vec![
                Any::encode_from(&bmp)
                    .map_err(|e| Error::Internal(format!("friendlyName attr: {e}")))?,
            ])
            .map_err(|e| Error::Internal(format!("friendlyName set: {e}")))?,
        });
    }

    let attrs = Attributes::try_from(attr_vec)
        .map_err(|e| Error::Internal(format!("bag attributes: {e}")))?;

    Ok(SafeBag {
        bag_id,
        bag_value,
        bag_attributes: Some(attrs),
    })
}

/// `pkcs12_store_key`.
pub fn pkcs12_store_key(
    store: &mut Pkcs12,
    alias: Option<&str>,
    pwd: Option<&str>,
    rounds: u32,
) -> Result<()> {
    let key = store.genkey.take().ok_or(Error::StorageNoKey)?;
    let bag = build_key_safebag(alias, &key, pwd, rounds)?;
    store.entries.push(ContentsEntry {
        bags: vec![bag],
        needs_encrypted_envelope: false,
        encrypted_template: None,
    });
    store.modified = true;
    store.rebuild_keypairs()?;
    Ok(())
}

fn cert_safebag(cert_der: &[u8]) -> Result<SafeBag> {
    let cert_value = OctetString::new(cert_der).map_err(|e| Error::Internal(format!("cert: {e}")))?;
    let cert_bag = CertBag {
        cert_id: bag_oid_from_str(X509_CERTIFICATE_OID)?,
        cert_value: Any::encode_from(&cert_value)
            .map_err(|e| Error::Internal(format!("cert bag value: {e}")))?,
    };
    Ok(SafeBag {
        bag_id: bag_oid_from_str(CERT_BAG_OID)?,
        bag_value: Any::encode_from(&cert_bag)
            .map_err(|e| Error::Internal(format!("cert bag: {e}")))?,
        bag_attributes: None,
    })
}

/// Replace external cert list with encrypted cert bags entry.
pub fn pkcs12_set_certificates_encrypted(store: &mut Pkcs12, certs: &[&[u8]]) -> Result<()> {
    let mut bags = SafeContents::new();
    for cert in certs {
        bags.push(cert_safebag(cert)?);
    }
    store.entries.push(ContentsEntry {
        bags,
        needs_encrypted_envelope: true,
        encrypted_template: None,
    });
    store.modified = true;
    Ok(())
}

/// `pkcs12_change_password`.
pub fn pkcs12_change_password(store: &mut Pkcs12, old_pass: &str, new_pass: &str) -> Result<()> {
    if store.password != old_pass {
        return Ok(());
    }
    store.password = new_pass.to_owned();
    store.modified = true;
    Ok(())
}

/// `pkcs12_encode`.
pub fn pkcs12_encode(store: &Pkcs12) -> Result<Vec<u8>> {
    let mut auth_safe = Vec::<ContentInfo>::new();
    for entry in &store.entries {
        let bags_der = entry
            .bags
            .to_der()
            .map_err(|e| Error::Internal(format!("SafeContents encode: {e}")))?;
        let cinfo = if entry.needs_encrypted_envelope {
            let epki = if let Some(template) = &entry.encrypted_template {
                pkcs5_reencrypt_pbes2(template, &store.password, &bags_der)?
            } else {
                let encrypt_aid = encryption_aid_for_store(store)?;
                pkcs5_encrypt_dstu(
                    &bags_der,
                    &store.password,
                    store.mac_data.mac_salt.as_bytes(),
                    mac_iterations(store),
                    &encrypt_aid,
                )?
            };
            encode_content_info_encrypted(&epki)?
        } else {
            encode_content_info_data(&bags_der)?
        };
        auth_safe.push(cinfo);
    }
    let auth_der = encode_authenticated_safe(&auth_safe)?;
    let auth_cinfo = encode_content_info_data(&auth_der)?;

    let mut mac_data = store.mac_data.clone();
    if store.modified {
        let auth_octets = auth_cinfo
            .content
            .as_ref()
            .and_then(|any| any.decode_as::<OctetString>().ok())
            .map(|os| os.as_bytes().to_vec())
            .ok_or_else(|| Error::Internal("authSafe encode".into()))?;
        let mac = pfx_calc_mac_with_data(&mac_data, &store.password, &auth_octets)?;
        mac_data.mac.digest = OctetString::new(mac)
            .map_err(|e| Error::Internal(format!("mac digest: {e}")))?;
    }

    let pfx = Pfx {
        version: u32_to_uint(3)?,
        auth_safe: auth_cinfo,
        mac_data: Some(mac_data),
    };
    pfx.to_der()
        .map_err(|e| Error::Internal(format!("PFX encode: {e}")))
}

/// `pkcs12_get_dh_adapter`.
pub fn pkcs12_get_dh_adapter(store: &Pkcs12) -> Result<DhAdapter> {
    let key = store
        .curr_key
        .as_ref()
        .ok_or(Error::StorageKeyNotSelected)?;
    DhAdapter::init_from_private_key_info(key)
}
