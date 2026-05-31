//! CMS EnvelopedData encrypt/decrypt (`uacryptex_cms_envelop_*`).

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::cms::{
    encode_enveloped_content_info, EnvelopedDataContainer, EnvelopedDataEngine,
};
use uacryptex_core::pki::crypto::MasterPrng;
use uacryptex_core::pki::oid::OidId;
use uacryptex_core::{Error, RET_OK};

use crate::buf::UacryptexBuf;
use crate::error::{bytes_from_ptr, check_out, write_error, UacryptexError};
use crate::UacryptexHandle;

/// Build CMS EnvelopedData (PKCS#7 ContentInfo) for `recipient_cert`.
///
/// `originator_key` must be a DSTU4145 (or ECDSA) private key handle with a matching certificate
/// (via `uacryptex_sign_open` or PKCS#12 with bound cert).
#[no_mangle]
pub extern "C" fn uacryptex_cms_envelop_encrypt(
    data: *const u8,
    data_len: usize,
    originator_key: *mut UacryptexHandle,
    recipient_cert: *const u8,
    recipient_cert_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let payload = bytes_from_ptr(data, data_len)
            .map_err(|code| Error::InvalidParam(format!("invalid data: code {code}")))?;
        let recipient_der = bytes_from_ptr(recipient_cert, recipient_cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid recipient cert: code {code}")))?;
        if originator_key.is_null() {
            return Err(Error::InvalidParam("originator key handle is null".into()));
        }
        let handle = unsafe { &mut *originator_key };
        let originator = handle.matching_cert()?;
        let recipient = Cert::decode(recipient_der)?;
        let originator_dh = handle.dh_adapter()?;
        let prng = MasterPrng::new()?;

        let mut engine = EnvelopedDataEngine::new(&originator_dh);
        engine.set_originator_cert(&originator)?;
        engine.set_data(OidId::Data, payload)?;
        engine.set_encryption_oid(OidId::Gost28147Cfb);
        engine.set_save_cert(true);
        engine.set_save_data(true);
        engine.set_prng(prng);
        engine.add_recipient(&recipient);

        let (container, external) = engine.generate()?;
        if external.is_some() {
            return Err(Error::Internal(
                "unexpected external ciphertext with save_data=true".into(),
            ));
        }
        Ok(UacryptexBuf::from_vec(encode_enveloped_content_info(
            &container,
        )?))
    };

    match run() {
        Ok(buf) => {
            unsafe {
                *out = buf;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

/// Decrypt CMS EnvelopedData.
///
/// Pass `originator_cert_len == 0` when the originator certificate is embedded in the CMS.
/// Pass `external_len == 0` when ciphertext is embedded in the structure.
#[no_mangle]
pub extern "C" fn uacryptex_cms_envelop_decrypt(
    cms: *const u8,
    cms_len: usize,
    external: *const u8,
    external_len: usize,
    originator_cert: *const u8,
    originator_cert_len: usize,
    recipient_key: *mut UacryptexHandle,
    recipient_cert: *const u8,
    recipient_cert_len: usize,
    out: *mut UacryptexBuf,
    err: *mut UacryptexError,
) -> i32 {
    let run = || -> Result<UacryptexBuf, Error> {
        check_out(out as *mut _)
            .map_err(|code| Error::InvalidParam(format!("invalid out pointer: code {code}")))?;
        let cms_der = bytes_from_ptr(cms, cms_len)
            .map_err(|code| Error::InvalidParam(format!("invalid cms: code {code}")))?;
        let external_ct = if external.is_null() || external_len == 0 {
            None
        } else {
            Some(bytes_from_ptr(external, external_len).map_err(|code| {
                Error::InvalidParam(format!("invalid external ciphertext: code {code}"))
            })?)
        };
        let originator = if originator_cert.is_null() || originator_cert_len == 0 {
            None
        } else {
            Some(Cert::decode(
                bytes_from_ptr(originator_cert, originator_cert_len).map_err(|code| {
                    Error::InvalidParam(format!("invalid originator cert: code {code}"))
                })?,
            )?)
        };
        let recipient_der = bytes_from_ptr(recipient_cert, recipient_cert_len)
            .map_err(|code| Error::InvalidParam(format!("invalid recipient cert: code {code}")))?;
        if recipient_key.is_null() {
            return Err(Error::InvalidParam("recipient key handle is null".into()));
        }
        let handle = unsafe { &mut *recipient_key };
        let recipient = Cert::decode(recipient_der)?;
        let recipient_dh = handle.dh_adapter()?;

        let container = EnvelopedDataContainer::decode(cms_der)?;
        let originator = match originator {
            Some(cert) => Some(cert),
            None if container.has_originator_cert() => Some(container.originator_cert()?),
            None => None,
        };
        let plaintext =
            container.decrypt_data(external_ct, originator.as_ref(), &recipient_dh, &recipient)?;
        Ok(UacryptexBuf::from_vec(plaintext))
    };

    match run() {
        Ok(buf) => {
            unsafe {
                *out = buf;
            }
            RET_OK
        }
        Err(e) => write_error(err, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::uacryptex_sign_open;
    use crate::{uacryptex_buf_free, uacryptex_handle_free};
    use uacryptex_core::RET_OK;

    const USERFIZ_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/userfiz_certificate.cer");
    const USERFIZ_KEY: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/userfiz_private_key_ba.dat");
    const USERUR_CERT: &[u8] =
        include_bytes!("../../../testdata/pki/pki_example/userur_certificate.cer");
    const USERUR_KEY: &[u8] = include_bytes!("../../../testdata/pki/userur_private_key.dat");

    #[test]
    fn cms_envelop_roundtrip_via_ffi() {
        let plaintext = b"Status message for enveloped data test";

        let mut originator: *mut UacryptexHandle = std::ptr::null_mut();
        let mut recipient: *mut UacryptexHandle = std::ptr::null_mut();
        let mut err = UacryptexError::default();

        assert_eq!(
            uacryptex_sign_open(
                USERFIZ_KEY.as_ptr(),
                USERFIZ_KEY.len(),
                USERFIZ_CERT.as_ptr(),
                USERFIZ_CERT.len(),
                &mut originator,
                &mut err,
            ),
            RET_OK
        );
        assert_eq!(
            uacryptex_sign_open(
                USERUR_KEY.as_ptr(),
                USERUR_KEY.len(),
                USERUR_CERT.as_ptr(),
                USERUR_CERT.len(),
                &mut recipient,
                &mut err,
            ),
            RET_OK
        );

        let mut cms = UacryptexBuf::empty();
        let rc = uacryptex_cms_envelop_encrypt(
            plaintext.as_ptr(),
            plaintext.len(),
            originator,
            USERUR_CERT.as_ptr(),
            USERUR_CERT.len(),
            &mut cms,
            &mut err,
        );
        assert_eq!(rc, RET_OK, "encrypt err={err:?}");

        let mut out = UacryptexBuf::empty();
        let rc = uacryptex_cms_envelop_decrypt(
            cms.ptr,
            cms.len,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            recipient,
            USERUR_CERT.as_ptr(),
            USERUR_CERT.len(),
            &mut out,
            &mut err,
        );
        assert_eq!(rc, RET_OK, "decrypt err={err:?}");
        assert_eq!(
            unsafe { std::slice::from_raw_parts(out.ptr, out.len) },
            plaintext
        );

        uacryptex_buf_free(out);
        uacryptex_buf_free(cms);
        uacryptex_handle_free(originator);
        uacryptex_handle_free(recipient);
    }
}
