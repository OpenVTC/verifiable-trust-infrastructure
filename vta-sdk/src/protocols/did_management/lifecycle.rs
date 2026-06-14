//! Wire types for read-only DID lifecycle operations that don't fit
//! the existing `create` / `update` / `delete` / `list` modules:
//! currently just `get_did_webvh_log`.

use serde::{Deserialize, Serialize};

/// Trust-task payload for `spec/vta/webvh/dids/get-log/1.0`.
/// Fetches the raw `did.jsonl` for an authed caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDidWebvhLogBody {
    pub did: String,
}

/// Response body. `log` is `None` when the DID is known but has no
/// log on disk (rare; usually means a partial provision); use that
/// signal to differentiate "DID not found" (404) from "DID exists
/// but no log yet" (200 + null).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDidWebvhLogResultBody {
    pub did: String,
    pub log: Option<String>,
}
