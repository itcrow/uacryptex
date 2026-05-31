//! `env_decrypt_data` (`cryptonite/src/pkix/c/api/enveloped_data.c`).

use der::Encode;

use super::enveloped_types::{
    EnvelopedData, KeyAgreeRecipientIdentifier, OriginatorIdentifierOrKey, RecipientInfo,
};
use crate::pki::cert::Cert;
use crate::pki::crypto::{unwrap_session_key, CipherAdapter, DhAdapter};
use crate::pki::ext::pkix_key_id_from_spki_der;
use crate::{Error, Result};

pub fn decrypt_data(
    env_data: &EnvelopedData,
    external_ciphertext: Option<&[u8]>,
    originator_cert_opt: Option<&Cert>,
    recipient_dh: &DhAdapter,
    recipient_cert: &Cert,
) -> Result<Vec<u8>> {
    let ciphertext = encrypted_content_bytes(env_data, external_ciphertext)?;
    let cipher = CipherAdapter::init(
        &env_data
            .encrypted_content_info
            .content_encryption_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("content encryption aid encode: {e}")))?,
    )?;

    let (wrapped_key, rnd_bytes, originator_pub_key) =
        unwrap_info(env_data, originator_cert_opt, recipient_cert)?;

    let session_key = unwrap_session_key(
        recipient_dh,
        &wrapped_key,
        rnd_bytes.as_deref(),
        &originator_pub_key,
    )?;
    cipher.decrypt(&session_key, &ciphertext)
}

fn encrypted_content_bytes(env_data: &EnvelopedData, external: Option<&[u8]>) -> Result<Vec<u8>> {
    if let Some(content) = env_data
        .encrypted_content_info
        .encrypted_content
        .as_ref()
        .filter(|os| !os.as_bytes().is_empty())
    {
        let data = content.as_bytes().to_vec();
        if let Some(ext) = external {
            if !ext.is_empty() && ext != data.as_slice() {
                return Err(Error::InvalidParam(
                    "external ciphertext does not match enveloped content".into(),
                ));
            }
        }
        return Ok(data);
    }

    if let Some(ext) = external.filter(|b| !b.is_empty()) {
        return Ok(ext.to_vec());
    }

    Err(Error::InvalidParam(
        "enveloped data has no encrypted content".into(),
    ))
}

type UnwrapInfo = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);

fn unwrap_info(
    env_data: &EnvelopedData,
    originator_cert_opt: Option<&Cert>,
    recipient_cert: &Cert,
) -> Result<UnwrapInfo> {
    for recipient in env_data.recipient_infos.0.iter() {
        let RecipientInfo::Kari(kari) = recipient else {
            continue;
        };

        for rekey in kari.recipient_encrypted_keys.0.iter() {
            if !recipient_matches(&rekey.rid, recipient_cert)? {
                continue;
            }

            let wrapped_key = rekey.encrypted_key.as_bytes().to_vec();
            let rnd_bytes = kari.ukm.as_ref().map(|os| os.as_bytes().to_vec());
            let originator_pub_key =
                resolve_originator_public_key(&kari.originator, originator_cert_opt, env_data)?;
            return Ok((wrapped_key, rnd_bytes, originator_pub_key));
        }
    }

    Err(Error::NotFound)
}

fn recipient_matches(rid: &KeyAgreeRecipientIdentifier, recipient_cert: &Cert) -> Result<bool> {
    match rid {
        KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(isn) => {
            Ok(recipient_cert.matches_issuer_and_serial(&isn.issuer, isn.serial_number.as_bytes()))
        }
        KeyAgreeRecipientIdentifier::RKeyId(rkey_id) => {
            let ski = pkix_key_id_from_spki_der(&recipient_cert.spki_der()?)?;
            Ok(ski == rkey_id.subject_key_identifier.0.as_bytes())
        }
    }
}

fn resolve_originator_public_key(
    originator: &OriginatorIdentifierOrKey,
    originator_cert_opt: Option<&Cert>,
    env_data: &EnvelopedData,
) -> Result<Vec<u8>> {
    match try_originator_public_key(originator, originator_cert_opt) {
        Ok(key) => return Ok(key),
        Err(Error::NoCertificate) | Err(Error::InvalidParam(_)) => {}
        Err(e) => return Err(e),
    }

    if let Some(originator_info) = &env_data.originator_info {
        if let Some(certs) = &originator_info.certs {
            for choice in certs.0.iter() {
                let super::types::CertificateChoices::Certificate(cert) = choice;
                let cert_der = cert
                    .to_der()
                    .map_err(|e| Error::Internal(format!("cert encode: {e}")))?;
                let wrapped = Cert::decode(&cert_der)?;
                if let Ok(key) = try_originator_public_key(originator, Some(&wrapped)) {
                    return Ok(key);
                }
            }
        }
    }

    if originator_cert_opt.is_some() {
        Err(Error::InvalidParam("wrong originator certificate".into()))
    } else {
        Err(Error::NoCertificate)
    }
}

fn try_originator_public_key(
    originator: &OriginatorIdentifierOrKey,
    originator_cert_opt: Option<&Cert>,
) -> Result<Vec<u8>> {
    match originator {
        OriginatorIdentifierOrKey::OriginatorKey(originator_key) => Ok(
            crate::primitives::dstu4145::compressed_key_from_spki_bitstring(
                originator_key.public_key.raw_bytes(),
            )?,
        ),
        OriginatorIdentifierOrKey::IssuerAndSerialNumber(isn) => {
            let cert = originator_cert_opt.ok_or(Error::NoCertificate)?;
            if !cert.matches_issuer_and_serial(&isn.issuer, isn.serial_number.as_bytes()) {
                return Err(Error::InvalidParam("wrong originator certificate".into()));
            }
            cert.spki_public_key_bytes()
        }
        OriginatorIdentifierOrKey::SubjectKeyIdentifier(ski) => {
            let cert = originator_cert_opt.ok_or(Error::NoCertificate)?;
            let cert_ski = pkix_key_id_from_spki_der(&cert.spki_der()?)?;
            if cert_ski != ski.0.as_bytes() {
                return Err(Error::InvalidParam("wrong originator certificate".into()));
            }
            cert.spki_public_key_bytes()
        }
    }
}
