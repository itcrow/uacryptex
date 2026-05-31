//! Signature BIT STRING encoding (`pkix_utils.c`: `sign_ba_to_bs`, `sign_bs_to_ba`).

use der::asn1::{BitString, OctetString, Uint};
use der::{Decode, Encode, Sequence};
use x509_cert::spki::AlgorithmIdentifier;

use crate::pki::crypto::{is_dstu4145_signature_oid, is_ecdsa_signature_oid};
use crate::{Error, Result};

#[derive(Sequence)]
struct EcdsaSigValue {
    r: Uint,
    s: Uint,
}

/// Encode a raw signature as an X.509 BIT STRING (`sign_ba_to_bs`).
pub fn sign_raw_to_bitstring(sign_aid_der: &[u8], raw: &[u8]) -> Result<BitString> {
    let aid: AlgorithmIdentifier<der::Any> = AlgorithmIdentifier::from_der(sign_aid_der)
        .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;
    let sign_oid = aid.oid.to_string();

    if is_dstu4145_signature_oid(&sign_oid) {
        let octets = OctetString::new(raw).map_err(|e| Error::Internal(format!("octets: {e}")))?;
        let wrapped = octets
            .to_der()
            .map_err(|e| Error::Internal(format!("octet string encode: {e}")))?;
        return BitString::new(0, wrapped.as_slice())
            .map_err(|e| Error::Internal(format!("bit string: {e}")));
    }

    if is_ecdsa_signature_oid(&sign_oid) {
        if raw.len() % 2 != 0 || raw.is_empty() {
            return Err(Error::InvalidParam("invalid ECDSA signature length".into()));
        }
        let mid = raw.len() / 2;
        let sig_der = EcdsaSigValue {
            r: ecdsa_component_to_uint(&raw[..mid])?,
            s: ecdsa_component_to_uint(&raw[mid..])?,
        }
        .to_der()
        .map_err(|e| Error::Internal(format!("ecdsa sig encode: {e}")))?;
        return BitString::new(0, sig_der.as_slice())
            .map_err(|e| Error::Internal(format!("bit string: {e}")));
    }

    Err(Error::Unsupported(format!(
        "unsupported signature algorithm for BIT STRING encoding: {sign_oid}"
    )))
}

/// Decode signature bytes from an X.509 BIT STRING (`sign_bs_to_ba`).
pub fn sign_bitstring_to_raw(sign_aid_der: &[u8], signature: &BitString) -> Result<Vec<u8>> {
    let aid: AlgorithmIdentifier<der::Any> = AlgorithmIdentifier::from_der(sign_aid_der)
        .map_err(|e| Error::Internal(format!("signature aid decode: {e}")))?;
    let sign_oid = aid.oid.to_string();

    if is_dstu4145_signature_oid(&sign_oid) {
        let octets = OctetString::from_der(signature.raw_bytes())
            .map_err(|e| Error::Internal(format!("dstu signature octets: {e}")))?;
        return Ok(octets.as_bytes().to_vec());
    }

    if is_ecdsa_signature_oid(&sign_oid) {
        let sig = EcdsaSigValue::from_der(signature.raw_bytes())
            .map_err(|e| Error::Internal(format!("ecdsa sig decode: {e}")))?;
        let mut r = uint_to_cryptonite_component(&sig.r)?;
        let mut s = uint_to_cryptonite_component(&sig.s)?;
        r.append(&mut s);
        return Ok(r);
    }

    Err(Error::Unsupported(format!(
        "unsupported signature algorithm for BIT STRING decoding: {sign_oid}"
    )))
}

fn ecdsa_component_to_uint(component_le: &[u8]) -> Result<Uint> {
    let mut be = component_le.to_vec();
    be.reverse();
    if be.first().is_some_and(|b| b & 0x80 != 0) {
        be.insert(0, 0);
    }
    Uint::new(&be).map_err(|e| Error::Internal(format!("ecdsa integer: {e}")))
}

fn uint_to_cryptonite_component(value: &Uint) -> Result<Vec<u8>> {
    let mut be = value.as_bytes().to_vec();
    while be.len() > 1 && be.last() == Some(&0) {
        be.pop();
    }
    be.reverse();
    Ok(be)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn ecdsa_sign_bitstring_roundtrip_matches_utest_creq_vector() {
        let sign_aid = hex("300A06082A8648CE3D040302");
        let raw = hex(
            "F6B6146A81D7A38EDA01E738F2BFF1FA5FEC6F163D382C31E03C0E9DAC29B375CA294D426A659C33BC27F03F89B301800230311DEA8503FF253826625C614BD9D3843C45EB84F362D1517CAEC5E4CF3736CB86D95E85413163F907005B564CFCBA5E",
        );
        let expected_bs = hex(
            "0368003065023100F6B6146A81D7A38EDA01E738F2BFF1FA5FEC6F163D382C31E03C0E9DAC29B375CA294D426A659C33BC27F03F89B301800230311DEA8503FF253826625C614BD9D3843C45EB84F362D1517CAEC5E4CF3736CB86D95E85413163F907005B564CFCBA5E",
        );
        let bs = sign_raw_to_bitstring(&sign_aid, &raw).unwrap();
        assert_eq!(bs.to_der().unwrap(), expected_bs);
        assert_eq!(sign_bitstring_to_raw(&sign_aid, &bs).unwrap(), raw);
    }
}
