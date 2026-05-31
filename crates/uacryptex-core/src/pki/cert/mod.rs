//! X.509 certificate API (`cryptonite/src/pkix/c/api/cert.c`).

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::constraints::BasicConstraints;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, ExtendedKeyUsage, SubjectInfoAccessSyntax, SubjectKeyIdentifier,
};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::pki::ext::object_identifier;
use crate::pki::oid::{oid_from_str, OidId};
use crate::{Error, Result};

/// Parsed X.509 certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    inner: Certificate,
}

impl Cert {
    /// `cert_decode`.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let inner = Certificate::from_der(der)
            .map_err(|e| Error::Internal(format!("certificate decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `cert_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("certificate encode: {e}")))
    }

    /// `cert_init_by_adapter`.
    pub fn init_by_adapter(tbs: TbsCertificate, adapter: &crate::pki::crypto::SignAdapter) -> Result<Self> {
        let tbs_der = tbs
            .to_der()
            .map_err(|e| Error::Internal(format!("tbs certificate encode: {e}")))?;
        let signature_raw = adapter.sign_data(&tbs_der)?;
        let sign_aid = adapter.signature_algorithm_der();
        let signature_algorithm = AlgorithmIdentifierOwned::from_der(sign_aid)
            .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;
        let signature = crate::pki::crypto::sign_raw_to_bitstring(sign_aid, &signature_raw)?;
        Ok(Self {
            inner: Certificate {
                tbs_certificate: tbs,
                signature_algorithm,
                signature,
            },
        })
    }

    /// Subject distinguished name.
    pub fn subject(&self) -> &x509_cert::name::Name {
        &self.inner.tbs_certificate.subject
    }

    /// Issuer distinguished name.
    pub fn issuer(&self) -> &x509_cert::name::Name {
        &self.inner.tbs_certificate.issuer
    }

    /// `cert_get_version` (0 = v1, 1 = v2, 2 = v3).
    pub fn version(&self) -> u8 {
        self.inner.tbs_certificate.version as u8
    }

    /// `cert_get_sn` — serial number bytes (big-endian INTEGER encoding).
    pub fn serial_number(&self) -> Vec<u8> {
        self.inner.tbs_certificate.serial_number.as_bytes().to_vec()
    }

    /// Copy with a different serial number (CRL KAT / revoked-entry checks).
    pub fn with_serial_number(&self, serial: &[u8]) -> Result<Self> {
        let mut clone = self.clone();
        clone.inner.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(serial).map_err(|e| {
                Error::Internal(format!("serial number: {e}"))
            })?;
        Ok(clone)
    }

    /// `cert_verify`.
    pub fn verify(&self, adapter: &crate::pki::crypto::VerifyAdapter) -> Result<()> {
        let tbs_der = self.tbs_der()?;
        let sign_aid = self.signature_algorithm_der()?;
        let signature_raw =
            crate::pki::crypto::sign_bitstring_to_raw(&sign_aid, &self.inner.signature)?;
        adapter.verify_data(&tbs_der, &signature_raw)
    }

    /// TBS issuer Name DER.
    pub fn issuer_der(&self) -> Result<Vec<u8>> {
        self.inner
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|e| Error::Internal(format!("issuer encode: {e}")))
    }

    /// Underlying certificate (for CMS embedding).
    pub fn inner_certificate(&self) -> &Certificate {
        &self.inner
    }

    /// `cert_get_not_before` as Unix seconds.
    pub fn not_before_unix(&self) -> i64 {
        self.inner
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs() as i64
    }

    /// `cert_get_not_after` as Unix seconds.
    pub fn not_after_unix(&self) -> i64 {
        self.inner
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64
    }

    /// `cert_get_tbs_info`.
    pub fn tbs_der(&self) -> Result<Vec<u8>> {
        self.inner
            .tbs_certificate
            .to_der()
            .map_err(|e| Error::Internal(format!("tbs encode: {e}")))
    }

    /// `cert_get_aid` (signature algorithm DER).
    pub fn signature_algorithm_der(&self) -> Result<Vec<u8>> {
        self.inner
            .signature_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))
    }

    /// `cert_get_sign` (BIT STRING DER).
    pub fn signature_der(&self) -> Result<Vec<u8>> {
        self.inner
            .signature
            .to_der()
            .map_err(|e| Error::Internal(format!("signature encode: {e}")))
    }

    /// `cert_get_spki` (SubjectPublicKeyInfo DER).
    pub fn spki_der(&self) -> Result<Vec<u8>> {
        self.inner
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| Error::Internal(format!("spki encode: {e}")))
    }

    /// Compressed DSTU public key from SPKI (`spki_get_pub_key`).
    pub fn spki_public_key_bytes(&self) -> Result<Vec<u8>> {
        Ok(crate::primitives::dstu4145::compressed_key_from_spki_bitstring(
            self.inner
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )?)
    }

    /// Compare issuer + serial to this certificate.
    pub fn matches_issuer_and_serial(&self, issuer: &x509_cert::name::Name, serial: &[u8]) -> bool {
        self.inner.tbs_certificate.issuer == *issuer
            && self.inner.tbs_certificate.serial_number.as_bytes() == serial
    }

    /// `cert_check_pubkey_and_usage` with key_usage=0 (pubkey only).
    pub fn check_public_key_matches(&self, pub_key: &[u8]) -> bool {
        self.spki_public_key_bytes()
            .map(|cert_key| cert_key == pub_key)
            .unwrap_or(false)
    }

    /// SPKI AlgorithmIdentifier DER.
    pub fn spki_algorithm_der(&self) -> Result<Vec<u8>> {
        self.inner
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("spki algorithm encode: {e}")))
    }

    /// `cert_get_ext_value`.
    pub fn extension_value(&self, id: OidId) -> Result<Vec<u8>> {
        let target = object_identifier(id)?;
        let extensions = self
            .inner
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or_else(|| Error::Unsupported("certificate has no extensions".into()))?;

        for ext in extensions {
            if ext.extn_id == target {
                return Ok(ext.extn_value.as_bytes().to_vec());
            }
        }
        Err(Error::Unsupported(format!("extension {id:?} not found")))
    }

    /// `cert_get_critical_ext_oids`.
    pub fn critical_extension_ids(&self) -> Vec<OidId> {
        extension_ids(self, true)
    }

    /// `cert_get_non_critical_ext_oids`.
    pub fn non_critical_extension_ids(&self) -> Vec<OidId> {
        extension_ids(self, false)
    }

    /// `cert_get_subj_key_id`.
    pub fn subject_key_id(&self) -> Result<Vec<u8>> {
        let value = self.extension_value(OidId::SubjectKeyIdentifierExtension)?;
        let ski = SubjectKeyIdentifier::from_der(&value)
            .map_err(|e| Error::Internal(format!("subject key id: {e}")))?;
        Ok(ski.0.as_bytes().to_vec())
    }

    /// `cert_get_auth_key_id`.
    pub fn authority_key_id(&self) -> Result<Vec<u8>> {
        let value = self.extension_value(OidId::AuthorityKeyIdentifierExtension)?;
        let aki = AuthorityKeyIdentifier::from_der(&value)
            .map_err(|e| Error::Internal(format!("authority key id: {e}")))?;
        let key_id = aki
            .key_identifier
            .ok_or_else(|| Error::Internal("authority key id missing keyIdentifier".into()))?;
        Ok(key_id.as_bytes().to_vec())
    }

    /// `cert_get_basic_constrains` — `-1` when extension absent or `pathLen` not set.
    pub fn basic_constraints_path_len(&self) -> Result<i32> {
        let Some((_, bc)) = self
            .inner
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|e| Error::Internal(format!("basic constraints: {e}")))?
        else {
            return Ok(-1);
        };

        Ok(bc
            .path_len_constraint
            .map(i32::from)
            .unwrap_or(-1))
    }

    /// `cert_is_ocsp_cert`.
    pub fn is_ocsp_responder(&self) -> Result<bool> {
        let value = match self.extension_value(OidId::ExtKeyUsageExtension) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        let eku = ExtendedKeyUsage::from_der(&value)
            .map_err(|e| Error::Internal(format!("extended key usage: {e}")))?;
        let ocsp = object_identifier(OidId::OcspKeyPurpose)?;
        Ok(eku.0.len() == 1 && eku.0[0] == ocsp)
    }

    /// `cert_check_validity_with_date`.
    pub fn check_validity_at(&self, unix_secs: i64) -> Result<()> {
        if unix_secs < self.not_before_unix() {
            return Err(Error::InvalidParam("certificate not yet valid".into()));
        }
        if unix_secs > self.not_after_unix() {
            return Err(Error::InvalidParam("certificate expired".into()));
        }
        Ok(())
    }

    /// `cert_get_tsp_url` — first TSP access URI from Subject Information Access.
    pub fn tsp_url(&self) -> Result<String> {
        let value = self.extension_value(OidId::SubjectInfoAccessExtension)?;
        let sia = SubjectInfoAccessSyntax::from_der(&value)
            .map_err(|e| Error::Internal(format!("subject info access: {e}")))?;
        let tsp_method = object_identifier(OidId::TspOid)?;
        for ad in sia.0 {
            if ad.access_method == tsp_method {
                if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) =
                    ad.access_location
                {
                    return Ok(uri.as_str().to_string());
                }
            }
        }
        Err(Error::Unsupported("TSP URL not found in certificate".into()))
    }
}

fn extension_ids(cert: &Cert, critical: bool) -> Vec<OidId> {
    let Some(extensions) = &cert.inner.tbs_certificate.extensions else {
        return Vec::new();
    };
    extensions
        .iter()
        .filter(|ext| ext.critical == critical)
        .filter_map(|ext| oid_id_from_object_identifier(&ext.extn_id))
        .collect()
}

fn oid_id_from_object_identifier(oid: &ObjectIdentifier) -> Option<OidId> {
    oid_from_str(&oid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_encode_roundtrip_tov_test_cert() {
        let der = include_bytes!("../../../../../testdata/pki/tov_test.der");
        let cert = Cert::decode(der).expect("decode");
        assert_eq!(cert.encode().unwrap(), der.as_slice());
    }
}
