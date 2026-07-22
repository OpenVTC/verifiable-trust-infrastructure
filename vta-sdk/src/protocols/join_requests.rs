//! Trust Task wire types for the VTC join-request ceremony family.
//!
//! Each body below is a [`trust_tasks_rs::TrustTask`] **payload**; the
//! document `type` is one of the `JOIN_REQUEST_*_TYPE` URIs. The success
//! reply is a framework `#response` document carrying a [`VerdictResponse`]
//! (the `request`/`submit` verb) or a read body (manifest/status/accept);
//! failures are framework `trust-task-error` documents, never DIDComm
//! problem-reports.
//!
//! ## URI shape (canonical registry)
//!
//! ```text
//! https://trusttasks.org/spec/vtc/join-requests/{verb}/{maj}.{min}
//! ```
//!
//! These moved off the private `trusttasks.org/openvtc/vtc` authority
//! (SPEC §6.5) and onto the canonical registry, where the ceremony's
//! tasks are published as `spec/vtc/join-requests/*`. The path keeps the
//! `/spec/<slug>/<maj.min>` shape the framework requires, so the URIs
//! still parse as [`trust_tasks_rs::TypeUri`].
//!
//! The two `*_RECEIPT_TYPE` consts stay on the old authority on purpose:
//! a receipt is a fire-and-forget ack rather than a Trust Task response,
//! and the registry publishes no receipt task — emitting a canonical URI
//! for one would name a spec that does not exist. The success-response
//! variant is the same URI with a `#response` fragment (the
//! `*_RESPONSE_TYPE` consts), minted by `TrustTask::respond_with`.
//!
//! ## Transports
//!
//! - **REST**: the request body is the TrustTask document; routing is by
//!   the document `type`. The holder identity is the document `issuer` +
//!   `proof`; replay binding is `recipient` (= the VTC DID) + `expiresAt`.
//! - **DIDComm**: the message `type` IS the Trust Task URL and the message
//!   body is the TrustTask document; the authcrypt sender authenticates
//!   the holder (no separate signature needed).

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Trust Task `type` for a join-request submission (the ceremony `request`
/// verb). Payload [`JoinRequestSubmitBody`]; response [`VerdictResponse`].
pub const JOIN_REQUEST_SUBMIT_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/submit/0.1";

/// `#response` variant of [`JOIN_REQUEST_SUBMIT_TYPE`] — the type of the
/// success document `respond_with` mints; carries a [`VerdictResponse`].
pub const JOIN_REQUEST_SUBMIT_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/submit/0.1#response";

/// Reply `type` used by the **credential-exchange** join close-the-loop
/// (`credential-exchange/present`), which results in a join and echoes this
/// receipt. Distinct from the Trust Task `submit` conversion above; retained
/// for that not-yet-converted path. Carries a [`JoinRequestSubmitReceiptBody`].
/// Async acknowledgement sent by the VTC after a submit. Deliberately
/// still on the `openvtc/vtc/` authority: the canonical registry has no
/// receipt task — the ceremony's canonical surface is
/// submit/accept/status/manifest plus their `#response` forms, and a
/// receipt is a separate fire-and-forget ack, not a Trust Task response.
/// Inventing `spec/vtc/join-requests/submit-receipt` here would mean
/// emitting a URI that resolves to nothing in the registry.
pub const JOIN_REQUEST_SUBMIT_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/spec/join-requests/submit-receipt/1.0";

/// Body of the credential-exchange join receipt (see
/// [`JOIN_REQUEST_SUBMIT_RECEIPT_TYPE`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestSubmitReceiptBody {
    pub request_id: Uuid,
    /// Status string — e.g. `"pending"` / `"approved"`.
    pub status: String,
}

/// Payload of the submit document. The applicant DID is the TrustTask
/// `issuer` (REST: document proof; DIDComm: authcrypt sender), not a body
/// field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestSubmitBody {
    pub vp: JsonValue,
    #[serde(default)]
    pub registry_consent: bool,
    #[serde(default)]
    pub extensions: JsonValue,
}

// ---------------------------------------------------------------------------
// Accept — reciprocal VMC (join ceremony close, join-requests/accept/1.0)
// ---------------------------------------------------------------------------

/// Trust Task `type` for a join-request accept: the admitted member
/// counter-signs the issued VMC to form the bidirectional DTG membership
/// edge. `memberDid` is the TrustTask `issuer` (DIDComm authcrypt sender /
/// REST document proof).
pub const JOIN_REQUEST_ACCEPT_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/accept/0.1";

/// `#response` variant of [`JOIN_REQUEST_ACCEPT_TYPE`] — carries a
/// [`JoinRequestAcceptReceiptBody`].
pub const JOIN_REQUEST_ACCEPT_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/accept/0.1#response";

/// Body of the accept message. `memberDid` comes from the DIDComm
/// `from` field (the authcrypt sender) — the envelope binds the member,
/// so no separate signature is needed. `vc` is the member-issued
/// reciprocal VC (a DI VC whose issuer is the member); `vmcId` names the
/// VMC it reciprocates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

/// Trust Task `type` for a join-request manifest request: discover the
/// community's join evidence requirements. Public read; empty payload.
pub const JOIN_REQUEST_MANIFEST_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/manifest/0.1";

/// `#response` variant of [`JOIN_REQUEST_MANIFEST_TYPE`] — carries a
/// [`JoinRequestManifestResponseBody`].
pub const JOIN_REQUEST_MANIFEST_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/manifest/0.1#response";

/// One community evidence requirement — a named DCQL Presentation
/// Definition the applicant may present against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ManifestCriterion {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub presentation_definition: JsonValue,
}

/// Manifest response: the community's join evidence requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestManifestResponseBody {
    pub community_did: String,
    pub criteria: Vec<ManifestCriterion>,
}

// ---------------------------------------------------------------------------
// Status — applicant poll (join-requests/status/1.0)
// ---------------------------------------------------------------------------

/// Trust Task `type` for an applicant status poll. The applicant DID is
/// the TrustTask `issuer` (DIDComm authcrypt sender / REST document proof).
pub const JOIN_REQUEST_STATUS_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/status/0.1";

/// `#response` variant of [`JOIN_REQUEST_STATUS_TYPE`] — carries a
/// [`JoinRequestStatusResponseBody`].
pub const JOIN_REQUEST_STATUS_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/join-requests/status/0.1#response";

/// Body of the status message (DIDComm). Over REST the `{id}` is the
/// path segment; over DIDComm it travels here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct JoinRequestStatusBody {
    pub request_id: Uuid,
}

/// Status response: the request's lifecycle, plus (when `deferred`) what
/// the applicant must present next.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
// Verdict — the shared `request`/`present` response envelope
// (docs/05-design-notes/vtc-ceremony-protocol.md §3)
// ---------------------------------------------------------------------------

/// The policy effect of a ceremony decision. A `deny` means the policy
/// **refused** a well-formed, verified request — it is NOT how framework
/// errors (invalid VIC, expired, malformed) are signalled; those are
/// `trust-task-error` documents (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum VerdictEffect {
    /// Admitted. `with` carries the granted role + obligations and the
    /// host-added `bundleRef` (sealed credential pointer) where issuance
    /// occurred.
    Allow,
    /// Policy refused. `with` carries `code` + `reason`.
    Deny,
    /// Parked for a human/quorum decision. `with` carries `queue` + `reason`.
    Refer,
    /// More evidence required. `with` carries `needs` +
    /// `presentationDefinition`; the applicant continues over `present`.
    RequestMore,
}

/// The effect-dependent detail of a [`Verdict`]. Modelled as one flat
/// struct with optional fields (rather than an enum) so the wire object is
/// stable and additive across ceremonies; only the fields relevant to the
/// `effect` are populated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerdictWith {
    // effect = allow
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligations: Option<JsonValue>,
    /// The issued Verifiable Membership Credential, returned inline on an
    /// auto-admit `allow` over REST (over DIDComm it is delivered in a
    /// follow-up message and this is omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmc: Option<JsonValue>,
    /// The issued role VEC — same delivery story as [`Self::vmc`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_vec: Option<JsonValue>,
    /// Sealed-transfer pointer to the issued credential bundle — added by
    /// the host on issuing ceremonies that seal, not emitted by the policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_ref: Option<JsonValue>,
    // effect = deny
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    // effect = refer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    // effect = request_more
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<JsonValue>,
}

/// A ceremony decision: the policy `effect` plus its effect-dependent
/// detail. Shared by every `request`/`present` response across ceremony
/// families.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Verdict {
    pub effect: VerdictEffect,
    pub with: VerdictWith,
}

/// The `request`/`present` success-response **payload** (rides inside the
/// `#response` TrustTask document, whose `threadId` carries the ceremony
/// thread). `requestId` is the persisted `JoinRequest` id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerdictResponse {
    pub request_id: Uuid,
    pub verdict: Verdict,
}

impl VerdictResponse {
    /// `allow` verdict for an auto-admitted applicant, with the issued
    /// credentials returned inline (REST) or omitted (DIDComm follow-up).
    pub fn allow(
        request_id: Uuid,
        role: Option<String>,
        vmc: Option<JsonValue>,
        role_vec: Option<JsonValue>,
    ) -> Self {
        Self {
            request_id,
            verdict: Verdict {
                effect: VerdictEffect::Allow,
                with: VerdictWith {
                    role,
                    vmc,
                    role_vec,
                    ..Default::default()
                },
            },
        }
    }

    /// `refer` verdict — the request was persisted `Pending` for a human
    /// admin decision (`approve`/`reject`).
    pub fn refer(request_id: Uuid, queue: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            request_id,
            verdict: Verdict {
                effect: VerdictEffect::Refer,
                with: VerdictWith {
                    queue: Some(queue.into()),
                    reason: Some(reason.into()),
                    ..Default::default()
                },
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Self-remove (M1.11.1 DIDComm twin)
// ---------------------------------------------------------------------------

/// DIDComm `type` for a member-side self-removal.
pub const MEMBER_SELF_REMOVE_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/members/self-remove/1.0";

/// VTC's reply with the resolved disposition + audit hint.
/// Async acknowledgement for a self-remove. Stays on `openvtc/vtc/`
/// for the same reason as [`JOIN_REQUEST_SUBMIT_RECEIPT_TYPE`] — no
/// canonical receipt task exists.
pub const MEMBER_SELF_REMOVE_RECEIPT_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/members/self-remove-receipt/1.0";

/// Body of the self-remove message. `did` comes from the DIDComm
/// `from` field — the caller's authcrypt sender authenticates
/// them. Disposition optional; falls back to the Member's stored
/// `departure_preference` and then to PolicyDefault→Tombstone.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SelfRemoveBody {
    #[serde(default)]
    pub disposition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SelfRemoveReceiptBody {
    pub did: String,
    /// Resolved disposition (`"purge"` | `"tombstone"` |
    /// `"historical"`). `policydefault` is never returned —
    /// the daemon resolves it before responding.
    pub disposition: String,
    pub removed: bool,
}
