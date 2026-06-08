//! DIDComm wire types for VTC join-request submission.
//!
//! The corresponding REST endpoint is `POST /v1/join-requests`;
//! over DIDComm the message `type` field IS the Trust Task URL
//! (workspace convention) and the DIDComm authcrypt sender
//! authenticates the applicant DID — no separate holder-binding
//! signature is needed (the envelope already binds the sender).

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// DIDComm message `type` for a join-request submission.
pub const JOIN_REQUEST_SUBMIT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0";

/// DIDComm message `type` for the VTC's reply (the submission
/// receipt). Carried as a `thid` reply to the submit message id.
pub const JOIN_REQUEST_SUBMIT_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/submit-receipt/1.0";

/// Body of the submit message. Applicant_did comes from the
/// DIDComm `from` field, not the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSubmitBody {
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
}

/// Body of the receipt message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestSubmitReceiptBody {
    pub request_id: Uuid,
    /// Status string. Always `"pending"` for a successful submit;
    /// future protocol versions may add `"deferred"` etc.
    pub status: String,
}

// ---------------------------------------------------------------------------
// Accept — reciprocal VMC (join ceremony close, join-requests/accept/1.0)
// ---------------------------------------------------------------------------

/// DIDComm message `type` for a join-request accept: the admitted
/// member counter-signs the issued VMC to form the bidirectional DTG
/// membership edge. `memberDid` comes from the DIDComm `from` field.
pub const JOIN_REQUEST_ACCEPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/accept/1.0";

/// DIDComm `type` for the VTC's accept reply (the reciprocation
/// receipt). Carried as a `thid` reply to the accept message id.
pub const JOIN_REQUEST_ACCEPT_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/accept-receipt/1.0";

/// Body of the accept message. `memberDid` comes from the DIDComm
/// `from` field (the authcrypt sender) — the envelope binds the member,
/// so no separate signature is needed. `vc` is the member-issued
/// reciprocal VC (a DI VC whose issuer is the member); `vmcId` names the
/// VMC it reciprocates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestAcceptBody {
    /// The join request being reciprocated. Over REST this is the
    /// `{id}` path segment; over DIDComm (no path) it travels in the
    /// body. The member learns it from the submit receipt's `requestId`.
    pub request_id: Uuid,
    pub vmc_id: String,
    pub vc: JsonValue,
}

/// Body of the accept receipt message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestAcceptReceiptBody {
    pub request_id: Uuid,
    /// Status string. `"accepted"` once the reciprocal edge is recorded.
    pub status: String,
    /// `id` of the recorded member-issued reciprocal VC.
    pub reciprocal_vc_id: String,
}

// ---------------------------------------------------------------------------
// Manifest — pre-submit discovery (join-requests/manifest/1.0)
// ---------------------------------------------------------------------------

/// DIDComm message `type` for a join-request manifest request: discover
/// the community's join evidence requirements. Read; empty request body.
pub const JOIN_REQUEST_MANIFEST_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/manifest/1.0";

/// DIDComm `type` for the VTC's manifest reply.
pub const JOIN_REQUEST_MANIFEST_RESPONSE_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/manifest-response/1.0";

/// One community evidence requirement — a named DCQL Presentation
/// Definition the applicant may present against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestCriterion {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub presentation_definition: JsonValue,
}

/// Manifest response: the community's join evidence requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestManifestResponseBody {
    pub community_did: String,
    pub criteria: Vec<ManifestCriterion>,
}

// ---------------------------------------------------------------------------
// Status — applicant poll (join-requests/status/1.0)
// ---------------------------------------------------------------------------

/// DIDComm message `type` for an applicant status poll. `applicantDid`
/// is the DIDComm `from` field (authcrypt sender).
pub const JOIN_REQUEST_STATUS_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/status/1.0";

/// DIDComm `type` for the VTC's status reply.
pub const JOIN_REQUEST_STATUS_RESPONSE_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/join-requests/status-response/1.0";

/// Body of the status message (DIDComm). Over REST the `{id}` is the
/// path segment; over DIDComm it travels here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestStatusBody {
    pub request_id: Uuid,
}

/// Status response: the request's lifecycle, plus (when `deferred`) what
/// the applicant must present next.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequestStatusResponseBody {
    pub request_id: Uuid,
    /// `pending` | `deferred` | `approved` | `rejected` | `withdrawn`.
    pub status: String,
    /// Outstanding requirements — present only for a `deferred` request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    /// The DCQL the applicant should answer over `present` — present only
    /// for a `deferred` request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<JsonValue>,
}

// ---------------------------------------------------------------------------
// Self-remove (M1.11.1 DIDComm twin)
// ---------------------------------------------------------------------------

/// DIDComm `type` for a member-side self-removal.
pub const MEMBER_SELF_REMOVE_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/members/self-remove/1.0";

/// VTC's reply with the resolved disposition + audit hint.
pub const MEMBER_SELF_REMOVE_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/members/self-remove-receipt/1.0";

/// Body of the self-remove message. `did` comes from the DIDComm
/// `from` field — the caller's authcrypt sender authenticates
/// them. Disposition optional; falls back to the Member's stored
/// `departure_preference` and then to PolicyDefault→Tombstone.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelfRemoveBody {
    #[serde(default)]
    pub disposition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfRemoveReceiptBody {
    pub did: String,
    /// Resolved disposition (`"purge"` | `"tombstone"` |
    /// `"historical"`). `policydefault` is never returned —
    /// the daemon resolves it before responding.
    pub disposition: String,
    pub removed: bool,
}
