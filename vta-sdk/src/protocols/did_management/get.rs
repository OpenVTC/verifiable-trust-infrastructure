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
/// The record is carried under `record`, as `spec/vta/webvh/dids/get/1.0`
/// requires.
///
/// It was `#[serde(flatten)]` from #849 until now, to make the folded task a
/// strict superset of the two shapes it replaced — the bare `WebvhDidRecord`
/// this task returned, and the `{did, log}` of the retired `dids/get-log`. That
/// bought a migration window at a price nothing had measured: a flattened
/// record cannot satisfy a response that is `additionalProperties: false`, so
/// **no conforming client could read any of the eleven members**, and the `ext`
/// slot was unreachable too.
///
/// Its own sibling is the argument. `dids/list` carries the same component
/// under `dids` and has always conformed, so flattening made `get` the one
/// outlier in its family — and a `log` member at the top level beside a
/// flattened record is a name collision waiting for the record to grow one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDidWebvhResultBody {
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
