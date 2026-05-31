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
        let (r_body, s_body) = decode_ecdsa_sig_value_bodies(signature.raw_bytes())?;
        let mut r = integer_body_to_cryptonite_component(&r_body);
        let mut s = integer_body_to_cryptonite_component(&s_body);
        r.append(&mut s);
        return Ok(r);
    }

    Err(Error::Unsupported(format!(
        "unsupported signature algorithm for BIT STRING decoding: {sign_oid}"
    )))
}

fn ecdsa_component_to_uint(component_le: &[u8]) -> Result<Uint> {
    // Cryptonite stores ECDSA scalars little-endian; DER INTEGER is big-endian.
    let mut be = component_le.to_vec();
    be.reverse();
    Uint::new(&be).map_err(|e| Error::Internal(format!("ecdsa integer: {e}")))
}

fn decode_ecdsa_sig_value_bodies(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (seq_tag, seq, trailing) = read_der_tlv(der)?;
    if seq_tag != 0x30 {
        return Err(Error::Internal("expected ECDSA SEQUENCE".into()));
    }
    if !trailing.is_empty() {
        return Err(Error::Internal("trailing ECDSA sig DER".into()));
    }
    let (r_tag, r_body, rest) = read_der_tlv(seq)?;
    let (s_tag, s_body, trailing) = read_der_tlv(rest)?;
    if r_tag != 0x02 || s_tag != 0x02 {
        return Err(Error::Internal("expected ECDSA INTEGER pair".into()));
    }
    if !trailing.is_empty() {
        return Err(Error::Internal("trailing ECDSA SEQUENCE data".into()));
    }
    Ok((r_body.to_vec(), s_body.to_vec()))
}

fn read_der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return Err(Error::Internal("truncated DER".into()));
    }
    let tag = input[0];
    let (len, header_len) = read_der_length(&input[1..])?;
    let content_start = 1 + header_len;
    let content_end = content_start
        .checked_add(len)
        .ok_or_else(|| Error::Internal("DER length overflow".into()))?;
    if input.len() < content_end {
        return Err(Error::Internal("truncated DER content".into()));
    }
    Ok((
        tag,
        &input[content_start..content_end],
        &input[content_end..],
    ))
}

fn read_der_length(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        return Err(Error::Internal("missing DER length".into()));
    }
    if input[0] & 0x80 == 0 {
        return Ok((input[0] as usize, 1));
    }
    let nbytes = (input[0] & 0x7f) as usize;
    if nbytes == 0 || input.len() < 1 + nbytes {
        return Err(Error::Internal("invalid DER length".into()));
    }
    let mut len = 0usize;
    for b in &input[1..=nbytes] {
        len = (len << 8) | (*b as usize);
    }
    Ok((len, 1 + nbytes))
}

fn integer_body_to_cryptonite_component(body: &[u8]) -> Vec<u8> {
    // Cryptonite `asn_INTEGER2ba`: copy INTEGER bytes, swap, trim trailing 0x00.
    let mut le = body.to_vec();
    le.reverse();
    if le.last() == Some(&0) {
        le.pop();
    }
    le
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
        let expected_bs = hex(
            "0368003065023100F6B6146A81D7A38EDA01E738F2BFF1FA5FEC6F163D382C31E03C0E9DAC29B375CA294D426A659C33BC27F03F89B301800230311DEA8503FF253826625C614BD9D3843C45EB84F362D1517CAEC5E4CF3736CB86D95E85413163F907005B564CFCBA5E",
        );
        let le_raw = hex(
            "8001B3893FF027BC339C656A424D29CA75B329AC9D0E3CE0312C383D166FEC5FFAF1BFF238E701DA8EA3D7816A14B6F65EBAFC4C565B0007F9633141855ED986CB3637CFE4C5AE7C51D162F384EB453C84D3D94B615C62263825FF0385EA1D31",
        );

        let bs = BitString::new(0, &expected_bs[3..]).expect("utest_creq CERTIFICATE_SIGN");
        assert_eq!(sign_bitstring_to_raw(&sign_aid, &bs).unwrap(), le_raw);

        let encoded = sign_raw_to_bitstring(&sign_aid, &le_raw).unwrap();
        assert_eq!(encoded.to_der().unwrap(), expected_bs);
        assert_eq!(sign_bitstring_to_raw(&sign_aid, &encoded).unwrap(), le_raw);
    }
}
