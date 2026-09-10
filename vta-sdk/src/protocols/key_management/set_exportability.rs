//! `keys/set-exportability/0.1` — whether a key's private half may be released.

use serde::{Deserialize, Serialize};

use crate::keys::KeyRecord;

/// Ask a custodian to change whether one key may be exported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SetKeyExportabilityBody {
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
    /// The state the key should be in afterwards — **not a delta**.
    ///
    /// Absolute so a producer that retries a request whose reply was lost lands
    /// where it asked rather than the opposite. A `toggle` member would
    /// reintroduce exactly that failure, which is why the spec has none and one
    /// of its negative fixtures is a request carrying one.
    pub exportable: bool,
}

/// The record as it now stands.
///
/// Wrapped in `key` to match `keys/show` and `keys/create`, which is what the
/// spec's response schema says. Returning the whole record lets a producer
/// confirm the state it asked for without a second round trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SetKeyExportabilityResultBody {
    pub key: KeyRecord,
}
