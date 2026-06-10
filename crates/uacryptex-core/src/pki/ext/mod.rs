//! X.509 extension encode/decode (`cryptonite/src/pkix/c/api/ext.c`).

mod builders;
mod exts;
mod san;

pub(crate) use builders::pkix_key_id_from_spki_der;

pub use builders::{
    ext_create_any, ext_create_auth_info_access, ext_create_auth_key_id_from_cert,
    ext_create_auth_key_id_from_spki, ext_create_basic_constraints, ext_create_cert_policies,
    ext_create_crl_distr_points, ext_create_crl_id, ext_create_crl_number, ext_create_crl_reason,
    ext_create_delta_crl_indicator, ext_create_ext_key_usage, ext_create_freshest_crl,
    ext_create_invalidity_date, ext_create_key_usage, ext_create_nonce,
    ext_create_private_key_usage, ext_create_private_key_usage_from_cert,
    ext_create_qc_statements, ext_create_subj_dir_attr_directly, ext_create_subj_info_access,
    ext_create_subj_key_id, qc_statement_compliance, qc_statement_limit_value, CrlReasonCode,
    KeyUsageBits, QcStatement,
};
pub use exts::{
    exts_add_extension, exts_get_ext_by_oid, exts_get_ext_value_by_oid, Extensions,
};
pub use san::{
    ext_create_subj_alt_name_directly, ext_create_subj_alt_name_dns_email, GeneralNameKind,
};

use der::Decode;
use der::Encode;
use x509_cert::ext::Extension;

use crate::pki::oid::{oid_to_str, OidId};
use crate::{Error, Result};

/// Parsed X.509 extension (RFC 5280 §4.1.2.9).
pub type ExtensionValue = Extension;

/// Extension value bytes (`ext_get_value`).
pub fn ext_get_value(ext: &Extension) -> Vec<u8> {
    ext.extn_value.as_bytes().to_vec()
}

/// Encode extension to DER.
pub fn ext_to_der(ext: &Extension) -> Result<Vec<u8>> {
    ext.to_der()
        .map_err(|e| Error::Internal(format!("extension encode: {e}")))
}

/// Decode extension from DER.
pub fn ext_from_der(bytes: &[u8]) -> Result<Extension> {
    Extension::from_der(bytes).map_err(|e| Error::Internal(format!("extension decode: {e}")))
}

pub(crate) fn object_identifier(id: OidId) -> Result<der::asn1::ObjectIdentifier> {
    let dot =
        oid_to_str(id).ok_or_else(|| Error::InvalidParam(format!("unknown OID id {id:?}")))?;
    der::asn1::ObjectIdentifier::new(&dot)
        .map_err(|e| Error::Internal(format!("object identifier: {e}")))
}

pub(crate) fn encode_as_ext_value<T: Encode>(value: &T) -> Result<Vec<u8>> {
    value
        .to_der()
        .map_err(|e| Error::Internal(format!("extension value encode: {e}")))
}

pub(crate) fn build_extension(
    id: OidId,
    critical: bool,
    extn_value: impl AsRef<[u8]>,
) -> Result<Extension> {
    Ok(Extension {
        extn_id: object_identifier(id)?,
        critical,
        extn_value: der::asn1::OctetString::new(extn_value.as_ref())
            .map_err(|e| Error::Internal(format!("octet string: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::oid::OidId;

    #[test]
    fn extension_der_roundtrip() {
        let ext = build_extension(
            OidId::QcStatementsExtension,
            true,
            hex::decode("300D300B06092A8624020101010201").unwrap(),
        )
        .unwrap();
        let der = ext_to_der(&ext).unwrap();
        let decoded = ext_from_der(&der).unwrap();
        assert_eq!(ext_get_value(&decoded), ext_get_value(&ext));
        assert_eq!(decoded.extn_id, ext.extn_id);
        assert_eq!(decoded.critical, ext.critical);
    }
}
