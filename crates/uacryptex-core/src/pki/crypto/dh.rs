//! DH adapter (`dh_adapter_init`, `cryptonite_manager.c`).

use der::{Any, Decode, Encode};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::crypto::aid::curve_params_from_spki_algorithm;
use crate::pki::crypto::aid::ecdsa_curve_from_spki_algorithm;
use crate::primitives::dstu4145::{compressed_key_from_spki_bitstring, dstu4145_dh};
use crate::primitives::intl::EcdsaCurve;
use crate::storage::pkcs8::{pkcs8_get_privatekey, PrivateKeyInfo};
use crate::{Error, Result};

enum DhKind {
    Dstu4145 {
        params: crate::primitives::dstu4145::CurveParams,
        private_key: Vec<u8>,
    },
    Ecdsa {
        curve: EcdsaCurve,
        private_key: Vec<u8>,
    },
}

/// Cryptonite `DhAdapter`.
pub struct DhAdapter {
    kind: DhKind,
    dh_aid: Vec<u8>,
}

impl DhAdapter {
    /// `dh_adapter_init`.
    pub fn init(private_key: &[u8], spki_aid_der: &[u8]) -> Result<Self> {
        let aid: AlgorithmIdentifier<Any> = AlgorithmIdentifier::from_der(spki_aid_der)
            .map_err(|e| Error::Internal(format!("dh aid decode: {e}")))?;
        let oid = aid.oid.to_string();
        let kind = if crate::pki::crypto::aid::oid_str_under(
            crate::pki::oid::OidId::PkiDstu4145WithGost3411,
            &oid,
        ) {
            DhKind::Dstu4145 {
                params: curve_params_from_spki_algorithm(spki_aid_der)?,
                private_key: private_key.to_vec(),
            }
        } else if crate::pki::oid::oid_matches_str(crate::pki::oid::OidId::EcPublicKeyType, &oid) {
            DhKind::Ecdsa {
                curve: ecdsa_curve_from_spki_algorithm(spki_aid_der)?,
                private_key: private_key.to_vec(),
            }
        } else {
            return Err(Error::Unsupported(format!(
                "unsupported DH algorithm OID: {oid}"
            )));
        };
        Ok(Self {
            kind,
            dh_aid: spki_aid_der.to_vec(),
        })
    }

    /// `dh_adapter_init` from PKCS#8 container.
    pub fn init_from_private_key_info(key: &PrivateKeyInfo) -> Result<Self> {
        let private_key = pkcs8_get_privatekey(key)?;
        let spki_aid = key
            .private_key_algorithm
            .to_der()
            .map_err(|e| Error::Internal(format!("private key algorithm encode: {e}")))?;
        Self::init(&private_key, &spki_aid)
    }

    /// `dha->get_alg`.
    pub fn algorithm_der(&self) -> &[u8] {
        &self.dh_aid
    }

    /// `dha->get_pub_key` — compressed DSTU public key octets.
    pub fn public_key(&self) -> Result<Vec<u8>> {
        match &self.kind {
            DhKind::Dstu4145 { params, private_key } => {
                let pk =
                    crate::primitives::dstu4145::public_key_from_private_key(params, private_key)?;
                crate::primitives::dstu4145::compress_public_key(params, &pk)
            }
            DhKind::Ecdsa { .. } => Err(Error::Unsupported(
                "ECDSA DH public key export not implemented".into(),
            )),
        }
    }

    /// `dha->dh` — peer key is compressed DSTU octets or ECDSA SPKI BIT STRING bytes.
    pub fn dh(&self, peer_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match &self.kind {
            DhKind::Dstu4145 { params, private_key } => {
                dstu4145_dh(params, true, private_key, peer_public_key)
            }
            DhKind::Ecdsa { .. } => Err(Error::Unsupported(
                "ECDSA DH key agreement not implemented".into(),
            )),
        }
    }

    /// Decompress peer SPKI BIT STRING wrapper for DSTU DH.
    pub fn dh_from_spki_bitstring(&self, spki_raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match &self.kind {
            DhKind::Dstu4145 { params, private_key } => {
                let compressed = compressed_key_from_spki_bitstring(spki_raw)?;
                dstu4145_dh(params, true, private_key, &compressed)
            }
            DhKind::Ecdsa { .. } => Err(Error::Unsupported(
                "ECDSA DH key agreement not implemented".into(),
            )),
        }
    }

    /// `dh_adapter_copy_with_alloc`.
    pub fn clone_state(&self) -> Result<Self> {
        Ok(Self {
            kind: match &self.kind {
                DhKind::Dstu4145 { params, private_key } => DhKind::Dstu4145 {
                    params: params.clone(),
                    private_key: private_key.clone(),
                },
                DhKind::Ecdsa { curve, private_key } => DhKind::Ecdsa {
                    curve: *curve,
                    private_key: private_key.clone(),
                },
            },
            dh_aid: self.dh_aid.clone(),
        })
    }
}
