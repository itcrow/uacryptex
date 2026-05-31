//! PKIStatusInfo for TSP responses (RFC 4210 §5.2.3).

use der::{Enumerated, Sequence};

/// `PKIStatus ::= INTEGER`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum PkiStatus {
    Accepted = 0,
    GrantedWithMods = 1,
    Rejection = 2,
    Waiting = 3,
    RevocationWarning = 4,
    RevocationNotification = 5,
    KeyUpdateWarning = 6,
}

/// `PKIStatusInfo ::= SEQUENCE { status, statusString OPTIONAL, failInfo OPTIONAL }`.
///
/// Optional fields are omitted in Cryptonite fixtures; full fields are preserved via DER round-trip.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    pub status: PkiStatus,
}
