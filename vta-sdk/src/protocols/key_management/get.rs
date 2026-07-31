use serde::{Deserialize, Serialize};

use crate::keys::KeyRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetKeyBody {
    #[serde(rename = "keyId", alias = "key_id")]
    pub key_id: String,
}

pub type GetKeyResultBody = KeyRecord;

/// `keys/show/0.1` response — the record under `key`, or `null` where the
/// maintainer holds none for that identifier.
///
/// "No such key" is a successful answer, not an error: a caller that cannot
/// distinguish absence from failure retries a lookup that will never succeed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetKeyResponseBody {
    pub key: Option<KeyRecord>,
}
