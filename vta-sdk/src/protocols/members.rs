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
/// The canonical DTG tag, exactly as `dtg-credentials` emits it
/// (`DTGCredentialType::Membership`) and as the VTC's own issuance stamps it.
///
/// The name previously carried a `VERIFIABLE_` prefix that the *value* never
/// had. That gap is not cosmetic: it is how
/// `"VerifiableEndorsementCredential"` came to be hand-rolled into the
/// recognition path, where it matched nothing any VTC issues and silently
/// broke cross-community recognition for every real presentation
/// (OpenVTC/verifiable-trust-infrastructure#1062). A constant whose name
/// disagrees with its value invites exactly that.
pub const MEMBERSHIP_CREDENTIAL_TYPE: &str = "MembershipCredential";

/// Wire `type` tag of a VEC, per DTG Credentials §VEC.
///
/// Sibling of [`MEMBERSHIP_CREDENTIAL_TYPE`], and here for the same reason:
/// the recognition path had this one as a bare literal, spelled wrongly, with
/// nothing to compare it against.
pub const ENDORSEMENT_CREDENTIAL_TYPE: &str = "EndorsementCredential";

/// VTC → member: request that the member issue and send their reciprocal VMC.
pub const MEMBER_REQUEST_VMC_TYPE: &str = "https://trusttasks.org/spec/vtc/members/request-vmc/0.1";

/// Member → VTC: a member-issued [`MEMBERSHIP_CREDENTIAL_TYPE`] VMC,
/// the member → community half of the membership pair.
pub const MEMBER_VMC_TYPE: &str = "https://trusttasks.org/spec/vtc/members/vmc/0.1";

/// VTC → member: receipt acknowledging a stored member VMC. The `#response`
/// variant of [`MEMBER_VMC_TYPE`].
pub const MEMBER_VMC_RESPONSE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/vmc/0.1#response";

/// VTC → member: **unsolicited** notice that the community removed them.
///
/// Distinct from the self-remove receipt
/// ([`crate::protocols::join_requests::MEMBER_SELF_REMOVE_RECEIPT_TYPE`]) in the
/// way that matters: a receipt answers a request the member made and is
/// correlated to it, so the member is already waiting for it. This answers
/// nothing — the member did not ask, is not waiting, and may be offline. Sending
/// one for a member-initiated departure would tell somebody who chose to leave
/// that they were removed.
pub const MEMBER_REMOVAL_NOTICE_TYPE: &str =
    "https://trusttasks.org/spec/vtc/members/removal-notice/0.1";

/// Which removal happened, as carried in [`RemovalNoticeBody::code`].
///
/// Two variants rather than one `removed` flag because they differ in what
/// recourse the member has: an administrator's removal ran the community's
/// removal policy, a super-administrator's purge deliberately skipped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemovalCode {
    /// Policy-governed removal by an administrator.
    AdminRemoved,
    /// Forceful super-administrator deletion; skips the removal policy.
    Purged,
}

/// Body of a [`MEMBER_REMOVAL_NOTICE_TYPE`] notice.
///
/// Every field except `reason` is required, because a notice that omits any of
/// them fails to answer one of the questions a removed member has: what
/// happened, to what, when, and on whose say-so.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalNoticeBody {
    /// The removed member's DID.
    ///
    /// Carried in the payload as well as the DIDComm envelope so a notice that
    /// is retained or forwarded — detached from the transport that delivered
    /// it — still names its own subject.
    pub did: String,
    /// Which removal happened.
    pub code: RemovalCode,
    /// How the member's published record was handled: `purge`, `tombstone` or
    /// `historical`. Always concrete — `policydefault` is resolved before the
    /// notice is sent, since naming an unresolved default tells the member
    /// nothing about their own record.
    pub disposition: String,
    /// The operator's stated reason, verbatim.
    ///
    /// `None` when the community gave none, which is a different claim from an
    /// empty string and is kept distinguishable on the wire. This is the
    /// member's only account of why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the removal took effect (RFC 3339).
    ///
    /// Deliberately not the notice's own send time: the two diverge whenever
    /// the member was offline, and it is the decision that has to be placeable
    /// in time.
    pub decided_at: String,
    /// DID of the administrator who decided.
    ///
    /// Names the deciding authority rather than the community, because "the
    /// community removed me" is unanswerable and "this administrator removed
    /// me" is. The community itself is the DIDComm sender.
    pub decided_by: String,
}

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
