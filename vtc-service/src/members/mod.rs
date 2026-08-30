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
pub mod match_code;
pub mod pseudonym;
pub mod storage;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub use storage::{
    DEFAULT_DEPARTURE_PREFERENCE, MEMBER_EXTENSIONS_MAX_BYTES, delete_member, get_member,
    list_members, list_members_paginated, store_member,
};

/// Pull the top-level `id` off a credential in its wire (JSON) form.
///
/// The typed `VerifiableCredential` does not expose `id` — issuance splices it
/// onto the wire form — so the id is only readable from JSON, which is also the
/// form the bodies are stored in. [`crate::ceremony::execute::top_level_id`] is
/// the typed front door onto this.
pub(crate) fn top_level_id(vc: &JsonValue) -> Option<String> {
    vc.get("id").and_then(JsonValue::as_str).map(str::to_string)
}

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
    /// The community-issued VMC itself — the membership **grant**, the
    /// community → member half of the edge.
    ///
    /// Kept, not just pointed at. Three things need the body and not the id:
    ///
    /// 1. **Digest verification.** A member-issued VMC carries a `digest` of
    ///    the grant it acknowledges, and DTG Core Credentials says an
    ///    acknowledgement whose digest matches no valid grant MUST NOT be
    ///    treated as completing a membership edge. Checking that needs the
    ///    grant's claims, which an id does not carry.
    /// 2. **Re-delivery.** A member who lost their copy could previously only
    ///    be given a *newly minted* one, which is a different credential with
    ///    a different digest — silently invalidating the acknowledgement they
    ///    had already sent.
    /// 3. **Operator visibility.** "Which credentials does this member hold
    ///    from us" was unanswerable from this row.
    ///
    /// `None` on rows written before this field existed, and on members whose
    /// issuance predates it; the id is still there, so those rows stay
    /// readable and are treated as pre-digest (see
    /// [`crate::members::inbound_vmc`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_vmc: Option<JsonValue>,
    /// ID of the currently-active role VEC (spec §6.1).
    /// Populated by Phase 2's issuance flow.
    #[serde(default)]
    pub current_role_vec_id: Option<String>,
    /// The role VEC itself, kept for the same reasons as
    /// [`Self::current_vmc`] — re-delivery and operator visibility. It is not
    /// digest-bound to anything, so nothing verifies against it; it is here so
    /// that "what did we issue this member" has one answer rather than two
    /// half-answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_role_vec: Option<JsonValue>,
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
    /// member-issued `MembershipCredential` (a Data-Integrity VC
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
    /// Whether [`Self::member_vmc`]'s `digest` was verified against
    /// [`Self::current_vmc`] when it arrived — i.e. whether the membership edge
    /// is **complete**.
    ///
    /// Storing the answer rather than recomputing it on read is deliberate:
    /// what was verified is a fact about the moment of receipt, and the grant
    /// can be re-issued afterwards. Recomputing would let a later renewal
    /// silently re-decide a past verification.
    ///
    /// `#[serde(default)]` reads `false` on every row written before this
    /// existed, which is the truthful answer for all of them: nothing checked
    /// a digest, so nothing verified one.
    #[serde(default)]
    pub member_vmc_bound: bool,
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
            current_vmc: None,
            current_role_vec_id: None,
            current_role_vec: None,
            extensions: JsonValue::Null,
            removed_at: None,
            personhood: false,
            personhood_asserted_at: None,
            reciprocal_vc_id: None,
            accepted_at: None,
            joined_via_invitation: false,
            member_vmc: None,
            member_vmc_id: None,
            member_vmc_bound: false,
            member_vmc_received_at: None,
        }
    }

    /// Record the community-issued VMC + role VEC this member was granted,
    /// keeping both the ids and the bodies.
    ///
    /// Replacing the grant invalidates any acknowledgement bound to the old
    /// one — the digest covers the grant's claims, so a re-issued grant has a
    /// different digest — and the member owes a fresh acknowledgement. That is
    /// deliberate: it is what stops consent to one membership carrying over to
    /// a different one. Clearing [`Self::member_vmc`] here is what makes the
    /// obligation visible rather than leaving a stale acknowledgement standing
    /// against a grant it no longer matches.
    pub fn record_issued_credentials(&mut self, vmc: JsonValue, role_vec: JsonValue) {
        let vmc_id = top_level_id(&vmc);
        let superseded = self.current_vmc_id.is_some() && self.current_vmc_id != vmc_id;

        self.current_vmc_id = vmc_id;
        self.current_vmc = Some(vmc);
        self.current_role_vec_id = top_level_id(&role_vec);
        self.current_role_vec = Some(role_vec);

        if superseded {
            self.member_vmc = None;
            self.member_vmc_id = None;
            self.member_vmc_received_at = None;
            self.member_vmc_bound = false;
        }
    }

    /// Record a re-minted role VEC, leaving the membership grant alone.
    ///
    /// A role change re-mints the VEC only. The grant is untouched, so the
    /// member's acknowledgement of it still stands and MUST NOT be dropped —
    /// which is why this is separate from
    /// [`Self::record_issued_credentials`].
    pub fn record_role_vec(&mut self, role_vec: JsonValue) {
        self.current_role_vec_id = top_level_id(&role_vec);
        self.current_role_vec = Some(role_vec);
    }

    /// Record the member-issued reciprocal VMC (member → community half of the
    /// pair), stamping the receipt time. The caller verifies the credential
    /// (issuer, subject binding, proof, and its digest against
    /// [`Self::current_vmc`]) before calling this.
    pub fn record_member_vmc(&mut self, vmc_id: impl Into<String>, vmc: JsonValue, bound: bool) {
        self.member_vmc_id = Some(vmc_id.into());
        self.member_vmc = Some(vmc);
        self.member_vmc_received_at = Some(Utc::now());
        self.member_vmc_bound = bound;
    }

    /// Is this membership edge complete — both VMCs of the pair present, with
    /// the member's half bound to the grant this community issued?
    ///
    /// The single definition of "complete" for this row. The graph, the admin
    /// UI, and anything that asserts this member's membership to a third party
    /// all have to answer it the same way, and a community asserting a
    /// membership MUST be able to produce the member-issued VMC that completes
    /// the edge.
    ///
    /// Says nothing about validity windows or revocation: those are questions
    /// about an instant, and this row does not get to choose the instant.
    pub fn membership_edge_complete(&self) -> bool {
        self.current_vmc_id.is_some() && self.member_vmc_id.is_some() && self.member_vmc_bound
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
        self.current_vmc = None;
        self.current_role_vec_id = None;
        self.current_role_vec = None;
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
        self.member_vmc_bound = false;
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
