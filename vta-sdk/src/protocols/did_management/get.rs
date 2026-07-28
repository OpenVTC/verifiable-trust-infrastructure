use serde::{Deserialize, Serialize};

use crate::webvh::WebvhDidRecord;

/// Request for `spec/vta/webvh/dids/get/1.0`.
///
/// Absorbs the former `dids/get-log/1.0`: that task took the same
/// `{did}`, ran the same lookup under the same context check, and
/// differed only in which representation it returned. Two Trust Tasks
/// for one read is a bigger interface than the operation needs, so the
/// representation is now a request flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct GetDidWebvhBody {
    pub did: String,
    /// Also return the raw `did.jsonl`.
    ///
    /// Off by default: the log grows with every published version, so a
    /// caller that only wants the record should not pay for it.
    #[serde(default)]
    pub include_log: bool,
}

/// Response for `spec/vta/webvh/dids/get/1.0`.
///
/// The record is flattened, so this is a strict **superset** of both
/// shapes it replaces — the bare `WebvhDidRecord` this task used to
/// return, and the `{did, log}` of the retired `dids/get-log`. Callers
/// of either keep reading the fields they already read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDidWebvhResultBody {
    #[serde(flatten)]
    pub record: WebvhDidRecord,
    /// The raw `did.jsonl`, when `includeLog` was set.
    ///
    /// `None` means either "not requested" or "requested, but this DID
    /// has no log on disk" — the latter is rare and usually a partial
    /// provision. The caller knows which it asked for, so the two are
    /// not distinguished here; a caller that did ask and got `None` has
    /// learned the DID exists without a log (as opposed to the 404 it
    /// would get for an unknown DID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}
