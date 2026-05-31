//! PKIX string utilities (`pkix_utils.c`).

use std::time::Duration;

use der::asn1::{GeneralizedTime, ObjectIdentifier, PrintableStringRef, UtcTime, Utf8StringRef};
use der::{Decode, Encode};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::time::Time;

use crate::pki::ext::object_identifier;
use crate::pki::oid::{oid_from_str, supported_name_attr, OidId};
use crate::{Error, Result};

/// Cryptonite `TIME_LIMIT` — GeneralizedTime from 2050-01-01 UTC.
const PKIX_TIME_LIMIT: i64 = 2_524_608_000;

/// `parse_key_value` — `{KEY=value}{KEY2=value2}` pairs; keys uppercased.
pub fn parse_key_value(input: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find('{') {
        let after_brace = &rest[start + 1..];
        let eq = after_brace
            .find('=')
            .ok_or_else(|| Error::InvalidParam("subject attribute missing '='".into()))?;
        let rbrace = after_brace
            .find('}')
            .ok_or_else(|| Error::InvalidParam("subject attribute missing '}'".into()))?;
        if eq > rbrace {
            return Err(Error::InvalidParam("malformed subject attribute".into()));
        }
        let key = &after_brace[..eq];
        let value = &after_brace[eq + 1..rbrace];
        if key.is_empty() || value.is_empty() {
            return Err(Error::InvalidParam(
                "empty subject attribute key or value".into(),
            ));
        }
        pairs.push((key.to_ascii_uppercase(), value.to_string()));
        rest = &after_brace[rbrace + 1..];
    }
    Ok(pairs)
}

/// Build X.501 Name from Cryptonite subject string (`ecert_request_set_subj_name`).
pub fn name_from_subject_string(subject_name: &str) -> Result<Name> {
    let pairs = parse_key_value(subject_name)?;
    let mut rdns = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let atv = attribute_type_and_value(&key, &value)?;
        let rdn = RelativeDistinguishedName::try_from(vec![atv])
            .map_err(|e| Error::Internal(format!("relative distinguished name: {e}")))?;
        rdns.push(rdn);
    }
    Ok(RdnSequence(rdns))
}

fn attribute_type_and_value(key: &str, value: &str) -> Result<AttributeTypeAndValue> {
    let oid = resolve_name_attr_oid(key)?;
    let encoded = if is_printable_name_attr(&oid) {
        PrintableStringRef::new(value)
            .map_err(|e| Error::Internal(format!("printable string: {e}")))?
            .to_der()
            .map_err(|e| Error::Internal(format!("printable string encode: {e}")))?
    } else {
        Utf8StringRef::new(value)
            .map_err(|e| Error::Internal(format!("utf8 string: {e}")))?
            .to_der()
            .map_err(|e| Error::Internal(format!("utf8 string encode: {e}")))?
    };
    Ok(AttributeTypeAndValue {
        oid,
        value: der::Any::from_der(&encoded)
            .map_err(|e| Error::Internal(format!("directory string: {e}")))?,
    })
}

fn resolve_name_attr_oid(key: &str) -> Result<ObjectIdentifier> {
    if let Ok(oid) = ObjectIdentifier::new(key) {
        return Ok(oid);
    }
    for i in 0.. {
        let Some((short, id)) = supported_name_attr(i) else {
            break;
        };
        if short.eq_ignore_ascii_case(key) {
            return object_identifier(id);
        }
    }
    if let Some(id) = oid_from_str(key) {
        return object_identifier(id);
    }
    Err(Error::Unsupported(format!(
        "unsupported subject name attribute: {key}"
    )))
}

fn is_printable_name_attr(oid: &ObjectIdentifier) -> bool {
    let Ok(country) = object_identifier(OidId::CountryName) else {
        return false;
    };
    let Ok(serial) = object_identifier(OidId::SerialNumber) else {
        return false;
    };
    oid == &country || oid == &serial
}

/// Encode Unix seconds as PKIX Time (UTCTime before 2050, else GeneralizedTime).
pub fn pkix_time_from_unix(unix_secs: i64) -> Result<Time> {
    let duration = Duration::from_secs(unix_secs as u64);
    if unix_secs >= PKIX_TIME_LIMIT {
        Ok(Time::GeneralTime(
            GeneralizedTime::from_unix_duration(duration)
                .map_err(|e| Error::Internal(format!("generalized time: {e}")))?,
        ))
    } else {
        Ok(Time::UtcTime(
            UtcTime::from_unix_duration(duration)
                .map_err(|e| Error::Internal(format!("utc time: {e}")))?,
        ))
    }
}

/// Parse dot-decimal OID for subject directory attributes.
pub fn object_identifier_from_text(text: &str) -> Result<ObjectIdentifier> {
    ObjectIdentifier::new(text).map_err(|e| Error::Internal(format!("object identifier: {e}")))
}

/// Normalize BER (indefinite length) to strict DER for `der` crate parsing.
pub(crate) fn ber_to_der(input: &[u8]) -> Result<Vec<u8>> {
    fn read_len(bytes: &[u8]) -> Result<(usize, usize, bool)> {
        if bytes.is_empty() {
            return Err(Error::Internal("truncated ASN.1 length".into()));
        }
        if bytes[0] == 0x80 {
            return Ok((0, 1, true));
        }
        if bytes[0] & 0x80 == 0 {
            return Ok((bytes[0] as usize, 1, false));
        }
        let count = (bytes[0] & 0x7f) as usize;
        if bytes.len() < 1 + count {
            return Err(Error::Internal("truncated ASN.1 length".into()));
        }
        let mut len = 0usize;
        for b in &bytes[1..=count] {
            len = (len << 8) | *b as usize;
        }
        Ok((len, 1 + count, false))
    }

    fn write_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xff {
            out.push(0x81);
            out.push(len as u8);
        } else if len <= 0xffff {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        } else {
            out.push(0x83);
            out.push((len >> 16) as u8);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }

    fn normalize_range(input: &[u8], start: usize, end: usize, out: &mut Vec<u8>) -> Result<usize> {
        let mut pos = start;
        while pos < end {
            if pos + 2 <= end && input[pos] == 0 && input[pos + 1] == 0 {
                return Ok(pos + 2);
            }
            let tag = input[pos];
            pos += 1;
            let (len, len_bytes, indefinite) = read_len(&input[pos..])?;
            pos += len_bytes;

            if indefinite {
                if tag & 0x20 == 0 {
                    return Err(Error::Internal(
                        "indefinite length on primitive ASN.1 value".into(),
                    ));
                }
                let mut body = Vec::new();
                while pos < end {
                    if pos + 2 <= end && input[pos] == 0 && input[pos + 1] == 0 {
                        pos += 2;
                        break;
                    }
                    pos = normalize_range(input, pos, end, &mut body)?;
                }
                out.push(tag);
                write_len(out, body.len());
                out.extend_from_slice(&body);
                continue;
            }

            if pos + len > end {
                return Err(Error::Internal("truncated ASN.1 value".into()));
            }
            let content = &input[pos..pos + len];
            pos += len;

            if tag & 0x20 != 0 {
                out.push(tag);
                let mut nested = Vec::new();
                normalize_range(content, 0, content.len(), &mut nested)?;
                write_len(out, nested.len());
                out.extend_from_slice(&nested);
            } else {
                out.push(tag);
                write_len(out, len);
                out.extend_from_slice(content);
            }
        }
        Ok(pos)
    }

    let mut out = Vec::with_capacity(input.len());
    normalize_range(input, 0, input.len(), &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_value_multiple_attrs() {
        let pairs = parse_key_value("{CN=Test}{C=UA}").unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("CN".into(), "Test".into()));
        assert_eq!(pairs[1], ("C".into(), "UA".into()));
    }

    #[test]
    fn name_from_subject_string_cn() {
        let name = name_from_subject_string("{CN=Good CA}").unwrap();
        assert!(!name.is_empty());
        let der = name.to_der().unwrap();
        let roundtrip = Name::from_der(&der).unwrap();
        assert_eq!(roundtrip, name);
    }
}
