//! Member domain model — spec §5.2.
//!
//! ## Why a separate keyspace from `acl:`
//!
//! Plan §D3: `acl:<did>` (auth-gate) and `members:<did>`
//! (community-membership metadata) are 1:1 by DID but logically
//! distinct. The auth path reads ACL rows on every request and
//! shouldn't pay the cost of loading the richer Member metadata.
//! Lifecycle is matched — creating a Member is always atomic with
//! writing the ACL row, and removal is similarly paired — so the
//! per-DID consistency invariant is upheld inside the same fjall
//! transaction.
//!
//! ## What's deferred to Phase 2+
//!
//! Spec §5.2's `status_list_index`, `current_vmc_id`, and
//! `current_role_vec_id` are credential pointers populated by
//! Phase 2's VTA-oracle issuance flow. They ship as `Option<T>`
//! slots from day one so Phase 2 can populate them without a
//! migration; Phase 1 always writes `None`.
//!
//! Spec §10.1's `Disposition` enum carries
//! `PolicyDefault` which (per plan §D6) resolves to `Tombstone`
//! in Phase 1 until `removal.rego` lands in Phase 2. The
//! `Disposition` enum is defined here so the value is on the wire
//! from day one; the resolver indirection lives at the removal
//! call site.

pub mod inbound_vmc;
pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub use storage::{
    DEFAULT_DEPARTURE_PREFERENCE, MEMBER_EXTENSIONS_MAX_BYTES, delete_member, get_member,
    list_members, list_members_paginated, store_member,
};

/// One community member. 1:1 with a [`crate::acl::VtcAclEntry`]
/// row by DID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub did: String,
    pub joined_at: DateTime<Utc>,
    /// Random-with-decoys status-list slot (spec §6.2). Populated by
    /// Phase 2's issuance flow; `None` until then.
    #[serde(default)]
    pub status_list_index: Option<u32>,
    /// Operator-controlled flag: when `true`, the community may
    /// publish the member's DID via the trust-registry sync path
    /// (spec §8.2). Default `false` until the member opts in.
    #[serde(default)]
    pub publish_consent: bool,
    /// Member-controlled preference for `DELETE /v1/members/me`
    /// disposition handling (spec §10.2).
    #[serde(default = "Disposition::default_preference")]
    pub departure_preference: Disposition,
    /// ID of the currently-active VMC for this member (spec §6.1).
    /// Populated by Phase 2's issuance flow.
    #[serde(default)]
    pub current_vmc_id: Option<String>,
    /// ID of the currently-active role VEC (spec §6.1).
    /// Populated by Phase 2's issuance flow.
    #[serde(default)]
    pub current_role_vec_id: Option<String>,
    /// Community-defined extensions slot (spec §3-M). Bounded by
    /// [`MEMBER_EXTENSIONS_MAX_BYTES`] = 16 KiB at the route
    /// layer.
    #[serde(default)]
    pub extensions: JsonValue,
    /// Set when the member departs (spec §10.2). `None` for live
    /// members; `Some(_)` distinguishes a Tombstoned or Historical
    /// row from an active one. `Purge` deletes the Member row
    /// outright — those rows never carry `removed_at`.
    ///
    /// Phase 2's renewal + VMC issuance paths consult this so they
    /// don't mint a credential for a departed member that the
    /// reconciler hasn't yet caught up on.
    #[serde(default)]
    pub removed_at: Option<DateTime<Utc>>,
    /// Personhood flag (spec §6.3 + Phase 4 M4.1). `true` after a
    /// successful `POST /v1/members/{did}/personhood/assert`
    /// (M4.3); flipped back to `false` on revoke (M4.4) or
    /// renewal-time policy downgrade (M4.2.2). Surfaced on the
    /// member's VMC `credentialSubject.personhood` field — every
    /// renewed VMC re-evaluates this against `personhood.rego`.
    #[serde(default)]
    pub personhood: bool,
    /// Timestamp of the most recent successful personhood assert
    /// (Phase 4 M4.1). `None` when personhood was never asserted
    /// or has been revoked. The default `personhood.rego` (M4.2)
    /// reads this to compute an "age" input for time-based
    /// expiry policies. Per planning-review D2: the *evidence*
    /// VP is verified at assert time and discarded — only this
    /// timestamp persists.
    #[serde(default)]
    pub personhood_asserted_at: Option<DateTime<Utc>>,
    /// `id` of the member-issued reciprocal VC that closed the
    /// bidirectional DTG membership edge (`join-requests/accept/1.0`).
    /// `None` until the member discharges the `reciprocate_vmc`
    /// obligation; `Some(_)` marks the edge reciprocated. The
    /// membership (ACL + VMC) is effective at admit regardless — this
    /// is the member → community half of the edge.
    #[serde(default)]
    pub reciprocal_vc_id: Option<String>,
    /// Timestamp the reciprocation was recorded. Paired with
    /// [`Self::reciprocal_vc_id`]; `None` until accept.
    #[serde(default)]
    pub accepted_at: Option<DateTime<Utc>>,
    /// Whether this member auto-joined by presenting a verified
    /// Invitation Credential (VIC). Set at admit time on the
    /// invitation path; surfaced in the admin UI as a "joined via
    /// invitation" badge. `#[serde(default)]` keeps pre-existing
    /// member rows (written before this field) deserialising as
    /// `false`.
    #[serde(default)]
    pub joined_via_invitation: bool,
    /// The member → community half of the membership VMC pair: the
    /// member-issued `VerifiableMembershipCredential` (a Data-Integrity VC
    /// whose `issuer` is this member and `credentialSubject.id` is the
    /// community DID), received over the `members/vmc/1.0` exchange and
    /// verified before storage. `None` until the member sends one. Distinct
    /// from [`Self::reciprocal_vc_id`], which is the join-ceremony
    /// acknowledgement; this is the full reciprocal VMC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_vmc: Option<JsonValue>,
    /// Top-level `id` of [`Self::member_vmc`], for display / dedup without
    /// reparsing the body. `None` until a member VMC is stored.
    #[serde(default)]
    pub member_vmc_id: Option<String>,
    /// When the member VMC was received + stored. Paired with
    /// [`Self::member_vmc`].
    #[serde(default)]
    pub member_vmc_received_at: Option<DateTime<Utc>>,
}

impl Member {
    /// Construct a new member with the conventional defaults the
    /// join-approval flow writes (M1.10):
    ///
    /// - `joined_at` = now
    /// - `publish_consent` = false (opt-in)
    /// - `departure_preference` = `PolicyDefault` (resolves to
    ///   `Tombstone` until the policy engine ships in Phase 2)
    /// - credential pointers + extensions absent
    pub fn fresh(did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            joined_at: Utc::now(),
            status_list_index: None,
            publish_consent: false,
            departure_preference: Disposition::default_preference(),
            current_vmc_id: None,
            current_role_vec_id: None,
            extensions: JsonValue::Null,
            removed_at: None,
            personhood: false,
            personhood_asserted_at: None,
            reciprocal_vc_id: None,
            accepted_at: None,
            joined_via_invitation: false,
            member_vmc: None,
            member_vmc_id: None,
            member_vmc_received_at: None,
        }
    }

    /// Record the member-issued reciprocal VMC (member → community half of the
    /// pair), stamping the receipt time. The caller verifies the credential
    /// (issuer, subject binding, proof) before calling this.
    pub fn record_member_vmc(&mut self, vmc_id: impl Into<String>, vmc: JsonValue) {
        self.member_vmc_id = Some(vmc_id.into());
        self.member_vmc = Some(vmc);
        self.member_vmc_received_at = Some(Utc::now());
    }

    /// Record the member-issued reciprocal VC that closes the
    /// bidirectional membership edge (`join-requests/accept/1.0`),
    /// stamping the time. Idempotent at the call site — the accept
    /// flow guards against re-recording a different VC.
    pub fn record_reciprocation(&mut self, reciprocal_vc_id: impl Into<String>) {
        self.reciprocal_vc_id = Some(reciprocal_vc_id.into());
        self.accepted_at = Some(Utc::now());
    }

    /// Returns `true` if this Member has been tombstoned or marked
    /// historical. Always `false` immediately after [`Self::fresh`].
    pub fn is_removed(&self) -> bool {
        self.removed_at.is_some()
    }

    /// Convert the live row to a tombstone: clear every
    /// PII-bearing / credential-bearing field, leave `did` +
    /// `joined_at` intact, stamp `removed_at`. Tombstoned rows
    /// retain enough metadata for "who was a member" queries
    /// but carry no live profile data.
    pub fn tombstone(&mut self) {
        self.publish_consent = false;
        self.departure_preference = Disposition::default_preference();
        self.current_vmc_id = None;
        self.current_role_vec_id = None;
        self.extensions = JsonValue::Null;
        self.removed_at = Some(Utc::now());
        // Tombstone wipes personhood — it's a PII-bearing
        // assertion (timestamps reveal when the operator
        // performed the assert ceremony). Members reasserting
        // after un-tombstone would have to re-present
        // evidence.
        self.personhood = false;
        self.personhood_asserted_at = None;
        // The reciprocal edge is bound to the wiped VMC — drop it too;
        // a re-admitted member reciprocates afresh.
        self.reciprocal_vc_id = None;
        self.accepted_at = None;
        // The member-issued VMC names the (now departed) membership edge —
        // drop it; a re-admitted member sends a fresh one.
        self.member_vmc = None;
        self.member_vmc_id = None;
        self.member_vmc_received_at = None;
    }

    /// Mark the row historical — keep all fields verbatim, just
    /// stamp `removed_at`.
    pub fn mark_historical(&mut self) {
        self.removed_at = Some(Utc::now());
    }
}

/// Spec §5.5 disposition for a removal. Determines what happens to
/// the Member record + status-list slot on member departure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(utoipa::ToSchema)]
pub enum Disposition {
    /// Hard delete — Member row removed entirely. RTBF default.
    Purge,
    /// Member row anonymised (DID retained, profile fields
    /// blanked). Default for `PolicyDefault` in Phase 1 (plan §D6).
    Tombstone,
    /// Member row retained verbatim, marked departed. For
    /// audit-significant communities.
    Historical,
    /// Defer to `removal.rego`'s `min_disposition`. In Phase 1
    /// resolves to `Tombstone`; Phase 2 swaps the resolver.
    PolicyDefault,
}

impl Disposition {
    fn default_preference() -> Self {
        Disposition::PolicyDefault
    }

    /// Resolve `PolicyDefault` to a concrete disposition. In
    /// Phase 1 this always returns [`Disposition::Tombstone`];
    /// Phase 2 reads the active `removal.rego` policy.
    pub fn resolve(self) -> Disposition {
        match self {
            Disposition::PolicyDefault => Disposition::Tombstone,
            other => other,
        }
    }
}
