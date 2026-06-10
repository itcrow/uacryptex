//! Extensions collection helpers (`exts.c`).

use x509_cert::ext::Extension;

use super::{ext_get_value, object_identifier};
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// Cryptonite `Extensions_t` — a growable extension list.
pub type Extensions = Vec<Extension>;

/// `exts_add_extension`.
pub fn exts_add_extension(extensions: &mut Extensions, ext: &Extension) {
    extensions.push(ext.clone());
}

/// `exts_get_ext_by_oid`.
pub fn exts_get_ext_by_oid(extensions: &[Extension], oid: OidId) -> Result<Extension> {
    let target = object_identifier(oid)?;
    extensions
        .iter()
        .find(|ext| ext.extn_id == target)
        .cloned()
        .ok_or_else(|| Error::Unsupported(format!("extension {oid:?} not found")))
}

/// `exts_get_ext_value_by_oid`.
pub fn exts_get_ext_value_by_oid(extensions: &[Extension], oid: OidId) -> Result<Vec<u8>> {
    Ok(ext_get_value(&exts_get_ext_by_oid(extensions, oid)?))
}
