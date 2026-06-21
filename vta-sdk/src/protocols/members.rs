//! Member-side membership-credential exchange (`members/*`).
//!
//! Membership between a persona DID and a VTC is a **pair of VMCs**: the VTC
//! issues a `VerifiableMembershipCredential` to the member at admission
//! (community → member), and the member issues one back to the VTC
//! (member → community), so each side holds a credential asserting the other's
//! membership edge. The join-ceremony `accept` step records a member-issued
//! *acknowledgement*; this family carries the **full reciprocal VMC** and lets
//! it be (re)exchanged at any point after admission:
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
pub const VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE: &str = "VerifiableMembershipCredential";

/// VTC → member: request that the member issue and send their reciprocal VMC.
pub const MEMBER_REQUEST_VMC_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/spec/members/request-vmc/1.0";

/// Member → VTC: a member-issued [`VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE`] VMC,
/// the member → community half of the membership pair.
pub const MEMBER_VMC_TYPE: &str = "https://trusttasks.org/openvtc/vtc/spec/members/vmc/1.0";

/// VTC → member: receipt acknowledging a stored member VMC. The `#response`
/// variant of [`MEMBER_VMC_TYPE`].
pub const MEMBER_VMC_RESPONSE_TYPE: &str =
    "https://trusttasks.org/openvtc/vtc/spec/members/vmc/1.0#response";

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
}
