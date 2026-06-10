//! EnvelopedData engine (`cryptonite/src/pkix/c/engine/enveloped_data_engine.c`).

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode};
use x509_cert::spki::AlgorithmIdentifier;

use super::super::enveloped_data::EnvelopedDataContainer;
use super::super::enveloped_types::{
    EncryptedContentInfo, EnvelopedData, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo,
    OriginatorIdentifierOrKey, OriginatorInfo, OriginatorPublicKey, RecipientEncryptedKey,
    RecipientEncryptedKeys, RecipientInfo, RecipientInfos,
};
use super::super::types::{CertificateChoices, CertificateSet, IssuerAndSerialNumber};
use crate::pki::cert::Cert;
use crate::pki::crypto::{
    create_gost28147_wrap_aid, curve_params_from_spki_algorithm, generate_session_key,
    get_content_cipher_aid, session_key_wrap_len, wrap_session_key, CipherAdapter, DhAdapter,
    MasterPrng,
};
use crate::pki::ext::object_identifier;
use crate::pki::oid::OidId;
use crate::primitives::dstu4145::{
    compress_public_key, generate_private_key, public_key_from_private_key, RandomBytes,
};
use crate::{Error, Result};

/// Cryptonite `EnvelopedDataEngine`.
pub struct EnvelopedDataEngine<'a> {
    dha: &'a DhAdapter,
    attrs: Option<x509_cert::attr::Attributes>,
    save_cert: bool,
    save_data: bool,
    data_oid: Option<ObjectIdentifier>,
    cipher_oid: Option<OidId>,
    data: Option<Vec<u8>>,
    originator_cert: Option<Cert>,
    recipient_certs: Vec<Cert>,
    prng: Option<MasterPrng>,
}

impl<'a> EnvelopedDataEngine<'a> {
    /// `eenvel_data_alloc`.
    pub fn new(dha: &'a DhAdapter) -> Self {
        Self {
            dha,
            attrs: None,
            save_cert: false,
            save_data: true,
            data_oid: None,
            cipher_oid: None,
            data: None,
            originator_cert: None,
            recipient_certs: Vec::new(),
            prng: None,
        }
    }

    pub fn set_originator_cert(&mut self, cert: &Cert) -> Result<()> {
        self.originator_cert = Some(cert.clone());
        Ok(())
    }

    pub fn set_unprotected_attrs(&mut self, attrs: x509_cert::attr::Attributes) {
        self.attrs = Some(attrs);
    }

    pub fn set_data(&mut self, oid: OidId, data: &[u8]) -> Result<()> {
        self.data_oid = Some(object_identifier(oid)?);
        self.data = Some(data.to_vec());
        Ok(())
    }

    pub fn set_encryption_oid(&mut self, oid: OidId) {
        self.cipher_oid = Some(oid);
    }

    pub fn set_save_cert(&mut self, save: bool) {
        self.save_cert = save;
    }

    pub fn set_save_data(&mut self, save: bool) {
        self.save_data = save;
    }

    pub fn set_prng(&mut self, prng: MasterPrng) {
        self.prng = Some(prng);
    }

    pub fn add_recipient(&mut self, cert: &Cert) {
        self.recipient_certs.push(cert.clone());
    }

    /// `eenvel_data_generate`.
    pub fn generate(&self) -> Result<(EnvelopedDataContainer, Option<Vec<u8>>)> {
        if self.recipient_certs.is_empty() {
            return Err(Error::InvalidParam(
                "enveloped data has no recipient".into(),
            ));
        }
        let cipher_oid = self
            .cipher_oid
            .ok_or_else(|| Error::InvalidParam("encryption OID not set".into()))?;
        let prng = self
            .prng
            .as_ref()
            .ok_or_else(|| Error::InvalidParam("PRNG not set".into()))?;
        let data = self
            .data
            .as_ref()
            .ok_or_else(|| Error::InvalidParam("content not set".into()))?;
        let data_oid = self
            .data_oid
            .as_ref()
            .ok_or_else(|| Error::InvalidParam("content OID not set".into()))?;
        let originator_cert = self
            .originator_cert
            .as_ref()
            .ok_or_else(|| Error::InvalidParam("originator certificate not set".into()))?;

        let originator_pub = self.dha.public_key()?;
        if !originator_cert.check_public_key_matches(&originator_pub) {
            return Err(Error::InvalidParam("wrong originator certificate".into()));
        }

        let mut dstu_prng = prng.dstu_prng()?;
        let session_key_len = session_key_wrap_len(cipher_oid)?;
        let session_key = generate_session_key(session_key_len, &mut dstu_prng)?;

        let originator_params =
            curve_params_from_spki_algorithm(&originator_cert.spki_algorithm_der()?)?;
        let mut recipient_infos_vec = Vec::new();

        for recipient_cert in &self.recipient_certs {
            let recipient_params =
                curve_params_from_spki_algorithm(&recipient_cert.spki_algorithm_der()?)?;
            let (originator, recipient_dha) = if originator_params.equals(&recipient_params) {
                (
                    originator_id_by_issuer_and_serial(originator_cert)?,
                    self.dha.clone_state()?,
                )
            } else {
                let mut temp_prng = prng.dstu_prng()?;
                let temp_priv = generate_private_key(&recipient_params, &mut temp_prng)?;
                let temp_pub = public_key_from_private_key(&recipient_params, &temp_priv)?;
                let compressed = compress_public_key(&recipient_params, &temp_pub)?;
                let spki_aid = recipient_cert.spki_algorithm_der()?;
                let temp_dha = DhAdapter::init(&temp_priv, &spki_aid)?;
                (
                    originator_id_by_public_key(&spki_aid, &compressed)?,
                    temp_dha,
                )
            };

            let recipient_info = generate_recipient_info(
                &recipient_dha,
                recipient_cert,
                &originator,
                &session_key,
                &mut dstu_prng,
            )?;
            recipient_infos_vec.push(recipient_info);
        }

        let cipher_aid = get_content_cipher_aid(&mut dstu_prng, cipher_oid, originator_cert)?;
        let cipher = CipherAdapter::init(&cipher_aid)?;
        let encrypted_data = cipher.encrypt(&session_key, data)?;

        let mut encrypted_content = EncryptedContentInfo {
            content_type: *data_oid,
            content_encryption_algorithm: decode_aid(&cipher_aid)?,
            encrypted_content: None,
        };
        if self.save_data {
            encrypted_content.encrypted_content = Some(
                OctetString::new(encrypted_data.clone())
                    .map_err(|e| Error::Internal(format!("encrypted content: {e}")))?,
            );
        }

        let originator_info = if self.save_cert {
            Some(OriginatorInfo {
                certs: Some(CertificateSet(
                    SetOfVec::try_from(vec![CertificateChoices::Certificate(
                        originator_cert.inner_certificate().clone(),
                    )])
                    .map_err(|e| Error::Internal(format!("certificate set: {e}")))?,
                )),
                crls: None,
            })
        } else {
            None
        };

        let recipient_infos = RecipientInfos(
            SetOfVec::try_from(recipient_infos_vec)
                .map_err(|e| Error::Internal(format!("recipient infos: {e}")))?,
        );

        let inner = EnvelopedData {
            version: 2,
            originator_info,
            recipient_infos,
            encrypted_content_info: encrypted_content,
            unprotected_attrs: self.attrs.clone(),
        };

        let external = if self.save_data {
            None
        } else {
            Some(encrypted_data)
        };

        Ok((EnvelopedDataContainer::from_inner(inner), external))
    }
}

fn decode_aid(der: &[u8]) -> Result<AlgorithmIdentifier<Any>> {
    AlgorithmIdentifier::from_der(der)
        .map_err(|e| Error::Internal(format!("algorithm identifier decode: {e}")))
}

fn originator_id_by_issuer_and_serial(cert: &Cert) -> Result<OriginatorIdentifierOrKey> {
    Ok(OriginatorIdentifierOrKey::IssuerAndSerialNumber(
        IssuerAndSerialNumber {
            issuer: cert.issuer().clone(),
            serial_number: x509_cert::serial_number::SerialNumber::new(&cert.serial_number())
                .map_err(|e| Error::Internal(format!("serial number: {e}")))?,
        },
    ))
}

fn originator_id_by_public_key(
    spki_aid: &[u8],
    compressed: &[u8],
) -> Result<OriginatorIdentifierOrKey> {
    use der::asn1::BitString;
    let bit_string = BitString::from_bytes(compressed)
        .map_err(|e| Error::Internal(format!("originator public key bit string: {e}")))?;
    Ok(OriginatorIdentifierOrKey::OriginatorKey(
        OriginatorPublicKey {
            algorithm: decode_aid(spki_aid)?,
            public_key: bit_string,
        },
    ))
}

fn generate_recipient_info(
    dha: &DhAdapter,
    recipient_cert: &Cert,
    originator: &OriginatorIdentifierOrKey,
    session_key: &[u8],
    prng: &mut impl RandomBytes,
) -> Result<RecipientInfo> {
    let mut ukm = [0u8; 64];
    prng.fill(&mut ukm)?;

    let recipient_pub = recipient_cert.spki_public_key_bytes()?;
    let wrapped = wrap_session_key(dha, &recipient_pub, session_key, &ukm)?;

    let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: recipient_cert.issuer().clone(),
        serial_number: x509_cert::serial_number::SerialNumber::new(&recipient_cert.serial_number())
            .map_err(|e| Error::Internal(format!("serial number: {e}")))?,
    });

    let rekey = RecipientEncryptedKey {
        rid,
        encrypted_key: OctetString::new(wrapped)
            .map_err(|e| Error::Internal(format!("encrypted key: {e}")))?,
    };

    let wrap_aid = create_gost28147_wrap_aid()?;
    let wrap_alg = decode_aid(&wrap_aid)?;
    let key_encryption_algorithm = AlgorithmIdentifier {
        oid: object_identifier(OidId::DhSinglePassCofactorDhGost34311kdfScheme)?,
        parameters: Some(
            Any::encode_from(&wrap_alg)
                .map_err(|e| Error::Internal(format!("wrap aid any: {e}")))?,
        ),
    };

    let kari = KeyAgreeRecipientInfo {
        version: 3,
        originator: originator.clone(),
        ukm: Some(OctetString::new(ukm).map_err(|e| Error::Internal(format!("ukm: {e}")))?),
        key_encryption_algorithm,
        recipient_encrypted_keys: RecipientEncryptedKeys(
            SetOfVec::try_from(vec![rekey])
                .map_err(|e| Error::Internal(format!("recipient encrypted keys: {e}")))?,
        ),
    };

    Ok(RecipientInfo::Kari(kari))
}
