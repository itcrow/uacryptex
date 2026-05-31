//! CMS / PKCS#7 SignedData (`cryptonite/src/pkix/c/api/signed_data.c`).

mod builder;
mod cades;
mod engine;
mod enveloped_data;
mod enveloped_decrypt;
mod enveloped_types;
mod ess;
mod ets;
mod signed_data;
mod signer_info;
mod types;

pub use builder::{build_content_info, build_signed_data, build_signed_data_with_stores};
pub use cades::{
    build_content_info_cades_a, build_content_info_cades_c, build_content_info_cades_lt,
    build_content_info_cades_t, build_content_info_cades_x,
};
pub use engine::{EnvelopedDataEngine, SignedDataEngine, SignerInfoEngine};
pub use enveloped_data::{
    encode_content_info as encode_enveloped_content_info, env_data_init,
    env_get_content_encryption_aid, EnvelopedDataContainer,
};
pub use enveloped_types::{
    EncryptedContentInfo, EnvelopedData, KeyAgreeRecipientInfo, KeyTransRecipientInfo,
    OriginatorIdentifierOrKey, OriginatorInfo, OriginatorPublicKey, RecipientEncryptedKey,
    RecipientEncryptedKeys, RecipientIdentifier, RecipientInfo, RecipientInfos,
};
pub use ess::{ess_cert_id_v2, signing_certificate_v2};
pub use ets::{
    archive_timestamp_imprint, cert_values, complete_certificate_refs, complete_revocation_refs,
    revocation_values_from_ocsp, CertValues, CompleteCertificateRefs, CompleteRevocationRefs,
    RevocationValues,
};
pub use signed_data::SignedDataContainer;
pub use signer_info::{
    cert_matches_signer_id, content_type_attribute, message_digest_attribute,
    signer_identifier_from_cert, signing_certificate_v2_attribute, verify_signer_info,
    verify_signer_info_without_data, verify_signing_cert_v2,
};
pub use types::{CertificateChoices, ContentInfo, EncapsulatedContentInfo, SignedData};
