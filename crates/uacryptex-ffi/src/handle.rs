//! Opaque handles for PKCS#12 stores and signing keys.

use uacryptex_core::pki::cert::Cert;
use uacryptex_core::pki::crypto::{DhAdapter, SignAdapter};
use uacryptex_core::storage::pkcs12::Pkcs12;

/// Inner state behind [`super::UacryptexHandle`].
pub enum HandleInner {
    Pkcs12(Pkcs12),
    Sign(SignAdapter),
}

pub struct Handle {
    pub inner: HandleInner,
}

impl Handle {
    pub fn into_raw(self) -> *mut super::UacryptexHandle {
        Box::into_raw(Box::new(super::UacryptexHandle {
            inner: Some(self),
        }))
    }
}

impl super::UacryptexHandle {
    pub(crate) fn as_handle_mut(&mut self) -> Result<&mut Handle, uacryptex_core::Error> {
        self.inner
            .as_mut()
            .ok_or_else(|| uacryptex_core::Error::InvalidParam("handle is freed".into()))
    }

    pub(crate) fn pkcs12_mut(&mut self) -> Result<&mut Pkcs12, uacryptex_core::Error> {
        match &mut self.as_handle_mut()?.inner {
            HandleInner::Pkcs12(store) => Ok(store),
            HandleInner::Sign(_) => Err(uacryptex_core::Error::InvalidParam(
                "handle is not a PKCS#12 store".into(),
            )),
        }
    }

    pub(crate) fn pkcs12_ref(&self) -> Result<&Pkcs12, uacryptex_core::Error> {
        match &self.inner.as_ref().ok_or_else(|| {
            uacryptex_core::Error::InvalidParam("handle is freed".into())
        })?.inner {
            HandleInner::Pkcs12(store) => Ok(store),
            HandleInner::Sign(_) => Err(uacryptex_core::Error::InvalidParam(
                "handle is not a PKCS#12 store".into(),
            )),
        }
    }

    pub(crate) fn sign_adapter(&mut self) -> Result<SignAdapter, uacryptex_core::Error> {
        match &mut self.as_handle_mut()?.inner {
            HandleInner::Pkcs12(store) => {
                uacryptex_core::storage::pkcs12::pkcs12_get_sign_adapter(store)
            }
            HandleInner::Sign(sa) => sa.clone_state(),
        }
    }

    pub(crate) fn dh_adapter(&mut self) -> Result<DhAdapter, uacryptex_core::Error> {
        match &mut self.as_handle_mut()?.inner {
            HandleInner::Pkcs12(store) => {
                uacryptex_core::storage::pkcs12::pkcs12_get_dh_adapter(store)
            }
            HandleInner::Sign(sa) => sa.dh_adapter(),
        }
    }

    pub(crate) fn matching_cert(&mut self) -> Result<Cert, uacryptex_core::Error> {
        match &mut self.as_handle_mut()?.inner {
            HandleInner::Sign(sa) => sa.cert().cloned(),
            HandleInner::Pkcs12(store) => {
                let cert_der = uacryptex_core::storage::pkcs12::pkcs12_get_certificate(store, 0)?
                    .ok_or(uacryptex_core::Error::NoCertificate)?;
                Cert::decode(&cert_der)
            }
        }
    }
}
