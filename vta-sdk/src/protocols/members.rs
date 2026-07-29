//! Member-side membership-credential exchange (`members/*`).
//!
//! Membership between a persona DID and a VTC is a **pair of VMCs**: the VTC
//! issues a `MembershipCredential` to the member at admission
//! (community → member), and the member issues one back to the VTC
//! (member → community), so each side holds a credential asserting the other's
//! membership edge. This family carries the **full reciprocal VMC** and lets
//! it be (re)exchanged at any point — at join time with
//! [`MemberVmcBody::request_id`] set (which also closes the approved join
//! request; the retired `join-requests/accept` semantics), or unprompted /
//! on request later:
//!
//! - [`MEMBER_REQUEST_VMC_TYPE`] — VTC → member: "please issue + send your VMC".
//!   Admin-triggered from the VTC; delivered over DIDComm to the member's agent.
//! - [`MEMBER_VMC_TYPE`] — member → VTC: the member-issued VMC (a Data-Integrity
//!   VC whose `issuer` is the member and whose `credentialSubject.id` is the
//!   community DID). The VTC verifies the proof + binding and stores it.
//! - [`MEMBER_VMC_RESPONSE_TYPE`] — VTC → member: a receipt acknowledging the
//!   stored VMC.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `type` array tag a member-issued membership credential must carry
/// (alongside `VerifiableCredential`). Same credential type the VTC issues for
/// its half of the pair — the direction is given by `issuer` /
/// `credentialSubject.id`, not the type.
///
/// The value is the canonical DTG / W3C tag `MembershipCredential` — exactly
/// what `dtg-credentials` emits (`DTGCredentialType::Membership`) and what the
/// VTC's own issuance stamps. The `VERIFIABLE_` prefix in the *name* is
/// historical; the *tag* is `MembershipCredential`, not
/// `VerifiableMembershipCredential`, so a credential built with the typed
/// `dtg-credentials` API verifies without hand-rolling the VC JSON.
pub const VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE: &str = "MembershipCredential";

/// VTC → member: request that the member issue and send their reciprocal VMC.
pub const MEMBER_REQUEST_VMC_TYPE: &str = "https://trusttasks.org/spec/vtc/members/request-vmc/0.1";

/// Member → VTC: a member-issued [`VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE`] VMC,
/// the member → community half of the membership pair.
pub const MEMBER_VMC_TYPE: &str = "https://trusttasks.org/spec/vtc/members/vmc/0.1";

/// VTC → member: receipt acknowledging a stored member VMC. The `#response`
/// variant of [`MEMBER_VMC_TYPE`].
pub const MEMBER_VMC_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/vmc/0.1#response";

/// Body of a [`MEMBER_REQUEST_VMC_TYPE`] request. The member should issue a VMC
/// whose `credentialSubject.id` is `community_did` and send it back as a
/// [`MEMBER_VMC_TYPE`] message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestMemberVmcBody {
    /// The community (VTC) DID the member's VMC must name as its subject.
    pub community_did: String,
    /// Optional operator-supplied reason ("renewal", "audit", …) surfaced to
    /// the member's agent / log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body of a [`MEMBER_VMC_TYPE`] submission: the member-issued VMC verbatim.
/// `vc.issuer` is the member DID (the authcrypt sender / DI-proof signer) and
/// `vc.credentialSubject.id` is the community DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberVmcBody {
    /// The member-issued membership credential (a Data-Integrity VC).
    pub vc: Value,
    /// Optional: an **approved** join request this delivery also closes
    /// (`vtc/members/vmc/0.1`'s `requestId`, which carries the retired
    /// `join-requests/accept` semantics). When present and naming an approved
    /// request whose applicant is the delivering member, the VTC records the
    /// delivered credential as the reciprocal half of that join and echoes
    /// `request_id` in the receipt. A UUID in string form — `members` compiles
    /// featureless, so the module avoids the optional `uuid` dependency;
    /// consumers parse and refuse a malformed id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Body of a [`MEMBER_VMC_RESPONSE_TYPE`] receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberVmcReceiptBody {
    /// The member whose VMC was stored.
    pub member_did: String,
    /// The stored VMC's top-level `id`.
    pub vmc_id: String,
    /// Always `"stored"` on success.
    pub status: String,
    /// Echoed when the delivery also closed a join request (the submission
    /// carried [`MemberVmcBody::request_id`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
