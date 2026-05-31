//! Certificate Revocation List API (`cryptonite/src/pkix/c/api/crl.c`).

use der::asn1::BitString;
use der::{Decode, Encode};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::crl::{CrlDistributionPoints, CrlNumber};
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::Extension;
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::pki::cert::Cert;
use crate::pki::crypto::{sign_bitstring_to_raw, sign_raw_to_bitstring, SignAdapter, VerifyAdapter};
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::{Error, Result};

/// Parsed X.509 CRL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crl {
    inner: CertificateList,
}

impl Crl {
    /// `crl_alloc` — empty revoked list and extensions (Cryptonite uninitialized object).
    pub fn new() -> Self {
        let mut crl = Self::decode(include_bytes!("../../../../testdata/pki/crl.dat"))
            .expect("crl.dat fixture");
        crl.inner.tbs_cert_list.revoked_certificates = None;
        crl.inner.tbs_cert_list.crl_extensions = None;
        crl
    }

    /// `crl_decode`.
    pub fn decode(der: &[u8]) -> Result<Self> {
        let inner = CertificateList::from_der(der)
            .map_err(|e| Error::Internal(format!("crl decode: {e}")))?;
        Ok(Self { inner })
    }

    /// `crl_encode`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| Error::Internal(format!("crl encode: {e}")))
    }

    /// `crl_init_by_sign`.
    pub fn init_by_sign(
        tbs: TbsCertList,
        signature_algorithm: AlgorithmIdentifierOwned,
        signature: BitString,
    ) -> Result<Self> {
        Ok(Self {
            inner: CertificateList {
                tbs_cert_list: tbs,
                signature_algorithm,
                signature,
            },
        })
    }

    /// `crl_init_by_adapter`.
    pub fn init_by_adapter(tbs: TbsCertList, adapter: &SignAdapter) -> Result<Self> {
        let tbs_der = tbs
            .to_der()
            .map_err(|e| Error::Internal(format!("tbs crl encode: {e}")))?;
        let signature_raw = adapter.sign_data(&tbs_der)?;
        let sign_aid = adapter.signature_algorithm_der();
        let signature_algorithm = AlgorithmIdentifierOwned::from_der(sign_aid)
            .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;
        let signature = sign_raw_to_bitstring(sign_aid, &signature_raw)?;
        Ok(Self {
            inner: CertificateList {
                tbs_cert_list: tbs,
                signature_algorithm,
                signature,
            },
        })
    }

    /// `crl_get_tbs`.
    pub fn tbs(&self) -> &TbsCertList {
        &self.inner.tbs_cert_list
    }

    /// Mutable TBS access (for tests that inject extensions).
    pub fn tbs_mut(&mut self) -> &mut TbsCertList {
        &mut self.inner.tbs_cert_list
    }

    /// `crl_set_tbs`.
    pub fn set_tbs(&mut self, tbs: TbsCertList) {
        self.inner.tbs_cert_list = tbs;
    }

    /// `crl_get_sign_aid`.
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifierOwned {
        &self.inner.signature_algorithm
    }

    /// `crl_get_sign_aid` as DER.
    pub fn signature_algorithm_der(&self) -> Result<Vec<u8>> {
        self.inner
            .signature_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("signature algorithm encode: {e}")))
    }

    /// `crl_set_sign_aid`.
    pub fn set_signature_algorithm(&mut self, aid: AlgorithmIdentifierOwned) {
        self.inner.signature_algorithm = aid;
    }

    /// `crl_get_sign`.
    pub fn signature(&self) -> &BitString {
        &self.inner.signature
    }

    /// `crl_set_sign`.
    pub fn set_signature(&mut self, signature: BitString) {
        self.inner.signature = signature;
    }

    /// Underlying CRL (for CMS embedding).
    pub fn inner_certificate_list(&self) -> &CertificateList {
        &self.inner
    }

    /// `crl_check_cert`.
    pub fn check_cert(&self, cert: &Cert) -> Result<bool> {
        let Some(revoked) = &self.inner.tbs_cert_list.revoked_certificates else {
            return Ok(false);
        };
        if revoked.is_empty() {
            return Ok(false);
        }
        let sn = cert.serial_number();
        Ok(revoked
            .iter()
            .any(|entry| entry.serial_number.as_bytes() == sn.as_slice()))
    }

    /// `crl_get_cert_info`.
    pub fn revoked_cert_for_cert(&self, cert: &Cert) -> Result<RevokedCert> {
        self.revoked_cert_by_serial(&cert.serial_number())
    }

    /// `crl_get_cert_info_by_sn`.
    pub fn revoked_cert_by_serial(&self, serial: &[u8]) -> Result<RevokedCert> {
        let Some(revoked) = &self.inner.tbs_cert_list.revoked_certificates else {
            return Err(Error::NotFound);
        };
        if revoked.is_empty() {
            return Err(Error::NotFound);
        }
        revoked
            .iter()
            .find(|entry| entry.serial_number.as_bytes() == serial)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// `crl_is_full` — true when Freshest CRL extension is present.
    pub fn is_full(&self) -> bool {
        has_extension(&self.inner.tbs_cert_list.crl_extensions, OidId::FreshestCrlExtension)
    }

    /// `crl_is_delta` — true when Delta CRL Indicator extension is present.
    pub fn is_delta(&self) -> bool {
        has_extension(
            &self.inner.tbs_cert_list.crl_extensions,
            OidId::DeltaCrlIndicatorExtension,
        )
    }

    /// `crl_verify`.
    pub fn verify(&self, adapter: &VerifyAdapter) -> Result<()> {
        let tbs_der = self
            .inner
            .tbs_cert_list
            .to_der()
            .map_err(|e| Error::Internal(format!("tbs crl encode: {e}")))?;
        let sign_aid = self.signature_algorithm_der()?;
        let signature_raw = sign_bitstring_to_raw(&sign_aid, &self.inner.signature)?;
        adapter.verify_data(&tbs_der, &signature_raw)
    }

    /// `crl_get_crl_number`.
    pub fn crl_number(&self) -> Result<Vec<u8>> {
        let value = extension_value(
            self.inner.tbs_cert_list.crl_extensions.as_ref(),
            OidId::CrlNumberExtension,
        )?;
        let number = CrlNumber::from_der(&value)
            .map_err(|e| Error::Internal(format!("crl number decode: {e}")))?;
        Ok(number.0.as_bytes().to_vec())
    }

    /// `crl_get_distribution_points`.
    pub fn distribution_point_urls(&self) -> Result<Vec<String>> {
        let value = extension_value(
            self.inner.tbs_cert_list.crl_extensions.as_ref(),
            OidId::CrlDistributionPointsExtension,
        )?;
        let dps = CrlDistributionPoints::from_der(&value)
            .map_err(|e| Error::Internal(format!("crl distribution points decode: {e}")))?;

        let mut urls = Vec::new();
        for dp in &dps.0 {
            let Some(DistributionPointName::FullName(names)) = &dp.distribution_point else {
                continue;
            };
            for name in names {
                if let GeneralName::UniformResourceIdentifier(uri) = name {
                    urls.push(uri.as_str().to_string());
                }
            }
        }
        Ok(urls)
    }

    /// `crl_get_this_update` as Unix seconds.
    pub fn this_update_unix(&self) -> i64 {
        self.inner
            .tbs_cert_list
            .this_update
            .to_unix_duration()
            .as_secs() as i64
    }

    /// Add a CRL extension (used by distribution-point KAT).
    pub fn add_crl_extension(&mut self, ext: Extension) {
        match &mut self.inner.tbs_cert_list.crl_extensions {
            Some(extensions) => extensions.push(ext),
            None => self.inner.tbs_cert_list.crl_extensions = Some(vec![ext]),
        }
    }
}

impl Default for Crl {
    fn default() -> Self {
        Self::new()
    }
}

fn has_extension(extensions: &Option<Vec<Extension>>, id: OidId) -> bool {
    let Some(extensions) = extensions else {
        return false;
    };
    let Ok(target) = object_identifier(id) else {
        return false;
    };
    extensions.iter().any(|ext| ext.extn_id == target)
}

fn extension_value(extensions: Option<&Vec<Extension>>, id: OidId) -> Result<Vec<u8>> {
    let extensions = extensions.ok_or(Error::NotFound)?;
    let target = object_identifier(id)?;
    for ext in extensions {
        if ext.extn_id == target {
            return Ok(ext.extn_value.as_bytes().to_vec());
        }
    }
    Err(Error::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_crl_dat_roundtrip() {
        let der = include_bytes!("../../../../testdata/pki/crl.dat");
        let crl = Crl::decode(der).expect("decode");
        assert_eq!(crl.encode().unwrap(), der.as_slice());
    }
}
