//! CRL issuance engine (`crl_engine.c`).

use der::Decode;
use std::time::{SystemTime, UNIX_EPOCH};

use x509_cert::crl::{RevokedCert, TbsCertList};
use x509_cert::ext::Extension;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Version;

use crate::pki::cert::Cert;
use crate::pki::crl::Crl;
use crate::pki::crypto::{SignAdapter, VerifyAdapter};
use crate::pki::ext::{ext_create_crl_reason, ext_create_invalidity_date, CrlReasonCode};
use crate::{Error, Result};

/// Cryptonite `CRLType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrlType {
    Delta = 0,
    Full = 1,
}

/// Cryptonite `CrlEngine`.
pub struct CrlEngine<'a> {
    sign_adapter: &'a SignAdapter,
    verify_adapter: &'a VerifyAdapter,
    previous: Option<Crl>,
    revoked: Vec<RevokedCert>,
    crl_extensions: Option<Vec<Extension>>,
    template_name: String,
    crl_type: CrlType,
    description: String,
}

/// `ecrl_alloc`.
pub fn ecrl_alloc<'a>(
    previous: Option<&Crl>,
    sign_adapter: &'a SignAdapter,
    verify_adapter: &'a VerifyAdapter,
    crl_extensions: Option<Vec<Extension>>,
    template_name: &str,
    crl_type: CrlType,
    description: &str,
) -> Result<CrlEngine<'a>> {
    if !sign_adapter.has_cert() {
        return Err(Error::NoCertificate);
    }

    let mut previous_crl = None;
    let mut revoked = Vec::new();

    if let Some(crl) = previous {
        crl.verify(verify_adapter)?;
        previous_crl = Some(crl.clone());
        if crl.is_delta() && crl_type == CrlType::Delta {
            if let Some(entries) = &crl.tbs().revoked_certificates {
                revoked.extend(entries.clone());
            }
        }
    }

    Ok(CrlEngine {
        sign_adapter,
        verify_adapter,
        previous: previous_crl,
        revoked,
        crl_extensions,
        template_name: template_name.to_string(),
        crl_type,
        description: description.to_string(),
    })
}

/// `ecrl_get_template_name`.
pub fn ecrl_get_template_name<'a>(engine: &'a CrlEngine<'_>) -> &'a str {
    &engine.template_name
}

/// `ecrl_get_type`.
pub fn ecrl_get_type(engine: &CrlEngine<'_>) -> CrlType {
    engine.crl_type
}

/// `ecrl_get_description`.
pub fn ecrl_get_description<'a>(engine: &'a CrlEngine<'_>) -> &'a str {
    &engine.description
}

/// `ecrl_add_revoked_cert`.
pub fn ecrl_add_revoked_cert(
    engine: &mut CrlEngine<'_>,
    cert: &Cert,
    reason: Option<CrlReasonCode>,
    invalidity_date: Option<i64>,
) -> Result<()> {
    cert.verify(engine.verify_adapter)?;
    ecrl_add_revoked_cert_by_sn(engine, &cert.serial_number(), reason, invalidity_date)
}

/// `ecrl_add_revoked_cert_by_sn`.
pub fn ecrl_add_revoked_cert_by_sn(
    engine: &mut CrlEngine<'_>,
    serial_number: &[u8],
    reason: Option<CrlReasonCode>,
    invalidity_date: Option<i64>,
) -> Result<()> {
    use der::asn1::GeneralizedTime;
    use std::time::Duration;
    use x509_cert::time::Time;

    let mut entry_extensions = Vec::new();
    if let Some(reason) = reason {
        entry_extensions.push(ext_create_crl_reason(false, reason)?);
    }
    if let Some(unix_secs) = invalidity_date {
        let gt = GeneralizedTime::from_unix_duration(Duration::from_secs(unix_secs as u64))
            .map_err(|e| Error::Internal(format!("invalidity date: {e}")))?;
        entry_extensions.push(ext_create_invalidity_date(false, gt)?);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Internal(format!("system time: {e}")))?;
    let revocation_date = Time::UtcTime(
        der::asn1::UtcTime::from_unix_duration(now)
            .map_err(|e| Error::Internal(format!("revocation date: {e}")))?,
    );

    let serial = x509_cert::serial_number::SerialNumber::new(serial_number)
        .map_err(|e| Error::Internal(format!("serial number: {e}")))?;

    engine.revoked.push(RevokedCert {
        serial_number: serial,
        revocation_date,
        crl_entry_extensions: if entry_extensions.is_empty() {
            None
        } else {
            Some(entry_extensions)
        },
    });
    Ok(())
}

/// `ecrl_merge_delta`.
pub fn ecrl_merge_delta(engine: &mut CrlEngine<'_>, delta: &Crl) -> Result<()> {
    if engine.crl_type != CrlType::Full {
        return Err(Error::InvalidParam("CRL engine is not full type".into()));
    }
    delta.verify(engine.verify_adapter)?;

    let Some(delta_entries) = &delta.tbs().revoked_certificates else {
        return Ok(());
    };
    let Some(base_entries) = engine
        .previous
        .as_ref()
        .and_then(|crl| crl.tbs().revoked_certificates.clone())
    else {
        engine.revoked.extend(delta_entries.clone());
        return Ok(());
    };

    let mut merged = base_entries;
    merged.extend(delta_entries.clone());
    engine.revoked = merged;
    Ok(())
}

fn ecrl_generate_core(engine: &CrlEngine<'_>, this_update: i64, next_update: i64) -> Result<Crl> {
    use der::asn1::UtcTime;
    use std::time::Duration;
    use x509_cert::time::Time;

    let issuer_cert = engine.sign_adapter.cert()?;
    let signature =
        AlgorithmIdentifierOwned::from_der(engine.sign_adapter.signature_algorithm_der())
            .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;

    let this = Time::UtcTime(
        UtcTime::from_unix_duration(Duration::from_secs(this_update as u64))
            .map_err(|e| Error::Internal(format!("thisUpdate: {e}")))?,
    );
    let next = Time::UtcTime(
        UtcTime::from_unix_duration(Duration::from_secs(next_update as u64))
            .map_err(|e| Error::Internal(format!("nextUpdate: {e}")))?,
    );

    let tbs = TbsCertList {
        version: Version::V2,
        signature,
        issuer: issuer_cert.subject().clone(),
        this_update: this,
        next_update: Some(next),
        revoked_certificates: if engine.revoked.is_empty() {
            None
        } else {
            Some(engine.revoked.clone())
        },
        crl_extensions: engine.crl_extensions.clone(),
    };

    Crl::init_by_adapter(tbs, engine.sign_adapter)
}

/// `ecrl_generate`.
pub fn ecrl_generate(engine: &CrlEngine<'_>, out: &mut Option<Crl>) -> Result<()> {
    let previous = engine
        .previous
        .as_ref()
        .ok_or_else(|| Error::InvalidParam("CRL engine has no previous CRL".into()))?;
    let next_update = crl_next_update_unix(previous)?;
    let this_update = unix_now()?;
    *out = Some(ecrl_generate_core(engine, this_update, next_update)?);
    Ok(())
}

/// `ecrl_generate_next_update`.
pub fn ecrl_generate_next_update(
    engine: &CrlEngine<'_>,
    next_update: i64,
    out: &mut Option<Crl>,
) -> Result<()> {
    let this_update = unix_now()?;
    *out = Some(ecrl_generate_core(engine, this_update, next_update)?);
    Ok(())
}

/// `ecrl_generate_diff_next_update`.
pub fn ecrl_generate_diff_next_update(
    engine: &CrlEngine<'_>,
    diff_next_update_secs: i64,
    out: &mut Option<Crl>,
) -> Result<()> {
    if diff_next_update_secs <= 0 {
        return Err(Error::InvalidParam(
            "diff_next_update must be positive".into(),
        ));
    }
    let this_update = unix_now()?;
    let next_update = this_update + diff_next_update_secs;
    *out = Some(ecrl_generate_core(engine, this_update, next_update)?);
    Ok(())
}

fn unix_now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| Error::Internal(format!("system time: {e}")))
}

fn crl_next_update_unix(crl: &Crl) -> Result<i64> {
    let next = crl
        .tbs()
        .next_update
        .ok_or_else(|| Error::InvalidParam("CRL has no nextUpdate".into()))?;
    Ok(next.to_unix_duration().as_secs() as i64)
}
