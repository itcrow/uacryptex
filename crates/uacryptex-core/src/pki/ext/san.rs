//! Subject Alternative Name builders (`ext_create_subj_alt_name_directly`).

use der::asn1::{
    Ia5String, ObjectIdentifier, OctetString, PrintableStringRef, Utf8StringRef,
};
use der::{Any, Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::Extension;

use super::{build_extension, encode_as_ext_value};
use crate::pki::oid::OidId;
use crate::pki::utils::name_from_subject_string;
use crate::{Error, Result};

/// Cryptonite `GeneralName_PR` (RFC 5280 §4.2.1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum GeneralNameKind {
    OtherName = 0,
    Rfc822Name = 1,
    DnsName = 2,
    X400Address = 3,
    DirectoryName = 4,
    EdiPartyName = 5,
    UniformResourceIdentifier = 6,
    IpAddress = 7,
    RegisteredId = 8,
}

impl GeneralNameKind {
    pub fn from_i32(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::OtherName),
            1 => Ok(Self::Rfc822Name),
            2 => Ok(Self::DnsName),
            3 => Ok(Self::X400Address),
            4 => Ok(Self::DirectoryName),
            5 => Ok(Self::EdiPartyName),
            6 => Ok(Self::UniformResourceIdentifier),
            7 => Ok(Self::IpAddress),
            8 => Ok(Self::RegisteredId),
            _ => Err(Error::InvalidParam(format!(
                "unknown GeneralName kind: {value}"
            ))),
        }
    }
}

/// `ext_create_subj_alt_name_directly` — arbitrary `GeneralName` entries.
///
/// `names[i]` encoding by `types[i]`:
/// - `DnsName`, `Rfc822Name`, `UniformResourceIdentifier` — IA5 text
/// - `IpAddress` — lowercase hex (4 or 16 bytes)
/// - `RegisteredId` — dotted OID
/// - `DirectoryName` — Cryptonite `{KEY=value}` subject string
/// - `OtherName` — `oid=value` where `value` may be prefixed with `utf8:`, `printable:`, or `der:` (hex)
/// - `EdiPartyName` — `der:` + hex of full `EDIPartyName` DER
pub fn ext_create_subj_alt_name_directly(
    critical: bool,
    types: &[GeneralNameKind],
    names: &[&str],
) -> Result<Extension> {
    if types.is_empty() || names.is_empty() {
        return Err(Error::InvalidParam(
            "subject alternative name list is empty".into(),
        ));
    }
    if types.len() != names.len() {
        return Err(Error::InvalidParam(
            "subject alternative name types and names length mismatch".into(),
        ));
    }

    let gns = types
        .iter()
        .zip(names.iter())
        .map(|(kind, name)| general_name_from_kind(*kind, name))
        .collect::<Result<Vec<_>>>()?;
    let san = SubjectAltName(gns);
    let value = encode_as_ext_value(&san)?;
    build_extension(OidId::SubjectAltNameExtension, critical, value)
}

/// Convenience: DNS + e-mail (Cryptonite `ecert_request_set_subj_alt_name`).
pub fn ext_create_subj_alt_name_dns_email(
    critical: bool,
    dns: &str,
    email: &str,
) -> Result<Extension> {
    ext_create_subj_alt_name_directly(
        critical,
        &[GeneralNameKind::DnsName, GeneralNameKind::Rfc822Name],
        &[dns, email],
    )
}

fn general_name_from_kind(kind: GeneralNameKind, name: &str) -> Result<GeneralName> {
    if name.is_empty() {
        return Err(Error::InvalidParam("general name value is empty".into()));
    }
    match kind {
        GeneralNameKind::Rfc822Name => ia5_general_name(name, GeneralName::Rfc822Name),
        GeneralNameKind::DnsName => ia5_general_name(name, GeneralName::DnsName),
        GeneralNameKind::UniformResourceIdentifier => {
            ia5_general_name(name, GeneralName::UniformResourceIdentifier)
        }
        GeneralNameKind::IpAddress => {
            let bytes = decode_hex(name).map_err(|e| Error::InvalidParam(e))?;
            if bytes.len() != 4 && bytes.len() != 16 {
                return Err(Error::InvalidParam(
                    "ip address must be 4 or 16 bytes".into(),
                ));
            }
            Ok(GeneralName::IpAddress(
                OctetString::new(bytes)
                    .map_err(|e| Error::Internal(format!("ip address: {e}")))?,
            ))
        }
        GeneralNameKind::RegisteredId => {
            let oid = ObjectIdentifier::new(name)
                .map_err(|e| Error::InvalidParam(format!("registered id: {e}")))?;
            Ok(GeneralName::RegisteredId(oid))
        }
        GeneralNameKind::DirectoryName => Ok(GeneralName::DirectoryName(
            name_from_subject_string(name)?,
        )),
        GeneralNameKind::OtherName => other_name_from_text(name),
        GeneralNameKind::EdiPartyName => edi_party_name_from_text(name),
        GeneralNameKind::X400Address => Err(Error::Unsupported(
            "x400Address is not supported".into(),
        )),
    }
}

fn ia5_general_name<F>(text: &str, wrap: F) -> Result<GeneralName>
where
    F: FnOnce(Ia5String) -> GeneralName,
{
    let ia5 = Ia5String::new(text).map_err(|e| Error::InvalidParam(format!("ia5 name: {e}")))?;
    Ok(wrap(ia5))
}

fn other_name_from_text(input: &str) -> Result<GeneralName> {
    use x509_cert::ext::pkix::name::OtherName;

    let (oid_text, value_text) = input.split_once('=').ok_or_else(|| {
        Error::InvalidParam(
            "otherName must be encoded as oid=value (optional utf8:/printable:/der: prefix)"
                .into(),
        )
    })?;
    let type_id = ObjectIdentifier::new(oid_text)
        .map_err(|e| Error::InvalidParam(format!("otherName type id: {e}")))?;
    let value = if let Some(hex) = value_text.strip_prefix("der:") {
        let bytes = decode_hex(hex).map_err(|e| Error::InvalidParam(e))?;
        Any::from_der(&bytes)
            .map_err(|e| Error::Internal(format!("otherName der value: {e}")))?
    } else if let Some(text) = value_text.strip_prefix("printable:") {
        let ps = PrintableStringRef::new(text)
            .map_err(|e| Error::InvalidParam(format!("otherName printable: {e}")))?;
        Any::from_der(
            &ps.to_der()
                .map_err(|e| Error::Internal(format!("otherName printable encode: {e}")))?,
        )
        .map_err(|e| Error::Internal(format!("otherName printable any: {e}")))?
    } else {
        let text = value_text.strip_prefix("utf8:").unwrap_or(value_text);
        let utf8 = Utf8StringRef::new(text)
            .map_err(|e| Error::InvalidParam(format!("otherName utf8: {e}")))?;
        Any::from_der(
            &utf8
                .to_der()
                .map_err(|e| Error::Internal(format!("otherName utf8 encode: {e}")))?,
        )
        .map_err(|e| Error::Internal(format!("otherName utf8 any: {e}")))?
    };
    Ok(GeneralName::OtherName(OtherName { type_id, value }))
}

fn decode_hex(input: &str) -> std::result::Result<Vec<u8>, String> {
    let s = input.trim();
    if s.len() % 2 != 0 {
        return Err("hex string length must be even".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> std::result::Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit: {b}")),
    }
}

fn edi_party_name_from_text(input: &str) -> Result<GeneralName> {
    use x509_cert::ext::pkix::name::EdiPartyName;

    let hex = input
        .strip_prefix("der:")
        .ok_or_else(|| Error::InvalidParam("ediPartyName requires der:HEX encoding".into()))?;
    let bytes = decode_hex(hex).map_err(|e| Error::InvalidParam(e))?;
    let edi = EdiPartyName::from_der(&bytes)
        .map_err(|e| Error::Internal(format!("ediPartyName decode: {e}")))?;
    Ok(GeneralName::EdiPartyName(edi))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::ext::ext_get_value;

    fn builder_input(gn: &GeneralName) -> (GeneralNameKind, String) {
        match gn {
            GeneralName::OtherName(on) => {
                let value = if let Ok(text) = Utf8StringRef::try_from(&on.value) {
                    format!("utf8:{text}")
                } else if let Ok(text) = PrintableStringRef::try_from(&on.value) {
                    format!("printable:{text}")
                } else {
                    format!("der:{}", hex::encode(on.value.value()))
                };
                (
                    GeneralNameKind::OtherName,
                    format!("{}={value}", on.type_id),
                )
            }
            GeneralName::Rfc822Name(s) => (GeneralNameKind::Rfc822Name, s.to_string()),
            GeneralName::DnsName(s) => (GeneralNameKind::DnsName, s.to_string()),
            GeneralName::UniformResourceIdentifier(s) => {
                (GeneralNameKind::UniformResourceIdentifier, s.to_string())
            }
            GeneralName::RegisteredId(oid) => (GeneralNameKind::RegisteredId, oid.to_string()),
            GeneralName::IpAddress(bytes) => {
                (GeneralNameKind::IpAddress, hex::encode(bytes.as_bytes()))
            }
            GeneralName::DirectoryName(name) => (
                GeneralNameKind::DirectoryName,
                name.to_string(),
            ),
            GeneralName::EdiPartyName(edi) => (
                GeneralNameKind::EdiPartyName,
                format!("der:{}", hex::encode(edi.to_der().unwrap())),
            ),
        }
    }

    #[test]
    fn dstu_utest_san_roundtrip() {
        let expected = hex::decode(
            "3081A3A056060C2B0601040181974601010402A0460C4430343635352C20D0BC2E20D09AD0B8D197D0B22C20D09BD18CD0B2D196D0B2D181D18CD0BAD0B020D0BFD0BBD0BED189D0B02C20D0B1D183D0B4D0B8D0BDD0BED0BA2038A022060C2B0601040181974601010401A0120C102B333830283434292032343830303130820E6163736B6964642E676F762E75618115696E666F726D406163736B6964642E676F762E7561",
        )
        .unwrap();
        let reference = SubjectAltName::from_der(&expected).unwrap();
        let mut kinds = Vec::new();
        let mut names = Vec::new();
        for gn in &reference.0 {
            let (kind, name) = builder_input(gn);
            kinds.push(kind);
            names.push(name);
        }
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ext = ext_create_subj_alt_name_directly(false, &kinds, &name_refs).unwrap();
        assert_eq!(ext_get_value(&ext), expected);
    }
}
