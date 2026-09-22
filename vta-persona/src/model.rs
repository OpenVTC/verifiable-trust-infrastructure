//! The record shapes the `persona/*` Trust Task family made normative.
//!
//! Two scopes, and the split is a security control rather than a filing
//! decision. The **attribute pool and profiles are agent-scoped** — one person,
//! one set of attributes about themselves, above every trust context — so that the
//! correlation index can see the risk it most needs to report: the same value
//! presented by two personas in two different contexts, which a per-context
//! index cannot see by construction. **Bindings, contacts and disclosure
//! records are context-scoped**, because a persona lives in a context and so do
//! its counterparties.
//!
//! Nothing here enforces that split — [`crate::storage`] holds the key layout
//! and the dispatcher holds the authorization — but the types are arranged so
//! that a function taking an agent-scoped record cannot be handed a
//! context-scoped one by accident.

use serde::{Deserialize, Serialize};

use crate::claim_types::{ReleaseRequirement, Sensitivity};

/// A ULID in Crockford base32. Record identity for attributes and profiles.
///
/// Chosen over a UUID because the leading 48 bits are a timestamp, so a
/// key-ordered scan of the store is also creation-ordered and `list` needs no
/// secondary sort.
pub type Ulid = String;

/// A value of the store's monotonic write counter.
///
/// Monotonic **per store**, not per record — the `vta/app-state` precedent, and
/// for the reason that note recorded after implementing it the other way: one
/// number has to serve as both the optimistic-concurrency token and the change
/// feed watermark, and per-record counters are not comparable to each other, so
/// no single value could mean "everything changed after this point".
///
/// Consumers treat versions as opaque and monotonic. A record's version can
/// jump by any amount between two writes, because its neighbours consumed the
/// intervening values.
pub type Version = u64;

/// Where a value came from — the member that makes this store worth building on
/// a trust stack rather than in an address book.
///
/// Provenance survives to the verifier, so a recipient can tell, per field, what
/// the holder typed from what an issuer attested.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Provenance {
    /// The holder supplied it.
    SelfAsserted,

    /// Derived from a credential in the vault.
    ///
    /// The stored value is a **cache for display**; the credential is the truth.
    /// It is re-derived on read and fails closed — never presenting a stale
    /// value — when the credential has been revoked, has expired, or has been
    /// archived or deleted. Presenting a cached value whose backing has been
    /// withdrawn would assert something the issuer has taken back.
    #[serde(rename_all = "camelCase")]
    CredentialBacked {
        credential_id: String,
        /// RFC 6901 JSON Pointer to the claim within the credential.
        claim_path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        issuer_did: Option<String>,
        /// The disclosure rung this claim was, or will be, presented at.
        #[serde(skip_serializing_if = "Option::is_none")]
        proof: Option<ProofRung>,
    },

    /// Minted per verifier at disclosure time and recorded against them, so
    /// every relying party receives a different value that routes back to the
    /// holder.
    ///
    /// A deployment need not operate a relay to be conformant, but the shape
    /// must exist: retrofitting per-verifier values into a pool-of-values model
    /// is a migration rather than an addition.
    #[serde(rename_all = "camelCase")]
    Generated {
        generator: String,
        #[serde(default = "default_true")]
        per_verifier: bool,
    },
}

fn default_true() -> bool {
    true
}

/// How strongly a credential-backed claim is hidden when presented, ordered
/// most private first.
///
/// The distinction between the first two and the last two is **of kind, not
/// degree**: only [`Predicate`](ProofRung::Predicate) and
/// [`Derived`](ProofRung::Derived) avoid handing two verifiers a join key. A
/// selective disclosure still carries the issuer's signature unchanged, so two
/// presentations are linkable however few claims each revealed.
///
/// Selection defaults to the highest rung the credential's format supports and
/// **never silently falls** to a lower one — see [`Ord`], which is derived so
/// that "highest supported" is a `max()` rather than a hand-written table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProofRung {
    /// Proves a statement over a claim without disclosing the claim.
    Predicate,
    /// Discloses exactly the claims needed, via a proof that differs on every
    /// presentation.
    Derived,
    /// Discloses exactly the claims needed, under a constant issuer signature.
    SelectiveDisclosure,
    /// Discloses the entire credential.
    Whole,
}

/// The JSON shape of a value, declared so a consumer can render and compare
/// without guessing.
///
/// The store validates that a value agrees with this and does nothing further:
/// it does **not** validate a phone number against a phone-number grammar. That
/// is a producer's affordance, and a store that grows opinions about the
/// contents of its records eventually blocks its consumer's release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValueType {
    String,
    Number,
    Boolean,
    Date,
    Object,
}

impl ValueType {
    /// Whether `value` agrees with the declared type.
    ///
    /// `Date` accepts a string — the store does not parse it. Validating the
    /// grammar here would be the store growing an opinion, and a holder whose
    /// perfectly good local date format is refused has no recourse.
    #[must_use]
    pub fn accepts(self, value: &serde_json::Value) -> bool {
        use serde_json::Value as J;
        matches!(
            (self, value),
            (Self::String | Self::Date, J::String(_))
                | (Self::Number, J::Number(_))
                | (Self::Boolean, J::Bool(_))
                | (Self::Object, J::Object(_))
        )
    }
}

/// Why a credential-backed value could not be re-derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StaleReason {
    Revoked,
    Expired,
    Archived,
    Deleted,
    NotFound,
}

/// One atomic attribute a holder keeps about themselves. **Agent-scoped.**
///
/// Several attributes may share a `type` — three phone numbers, a legal name and
/// a preferred name — which is why `attribute_id` is the identity of an attribute and
/// `type` is not.
/// **Not exhaustively constructible from outside this crate**, and the reason
/// is its own history: `sensitivity` arrived in #1299 and `release` in #1310,
/// each a `pub` field on a struct any consumer could write as a literal, so
/// each was a compatibility break for a record that is only going to keep
/// growing as the persona specification does. Marked once, in a release that
/// already carried the break, so the next member is an addition rather than
/// another one.
///
/// Nothing outside this crate builds one today — an `Attribute` arrives from
/// the store or from a deserialised document — so this costs a consumer
/// nothing it was actually doing. Inside the crate, literal construction is
/// unaffected.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Attribute {
    pub attribute_id: Ulid,
    /// Vocabulary token — `name.legal`, `phone.mobile`. The store's own; every
    /// external vocabulary is a mapping applied at presentation by a renderer,
    /// not at rest.
    pub r#type: String,
    pub value_type: ValueType,
    /// Encrypted at rest. Absent for a metadata-only view, and absent when a
    /// credential-backed value could not be re-derived — a consumer reads
    /// `stale` to tell those apart rather than inferring from the absence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    /// The holder's own words, for their own picker. Never disclosed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub provenance: Provenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_reason: Option<StaleReason>,
    /// Set **only** where the holder decided it explicitly.
    ///
    /// Absent is not `normal`: it records that no decision was made, and the
    /// default is derived from the claim-type registry at read
    /// ([`crate::claim_types::sensitivity_of`]). Storing the resolved value
    /// instead would freeze it — a later tightening of the registry would then
    /// protect new attributes and leave this one exposed.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<Sensitivity>,
    /// What it takes to let this attribute **leave**, where the holder decided
    /// it explicitly. Same rule as `sensitivity`: absent means no decision, and
    /// the default is derived from the registry at read.
    ///
    /// This field was deliberately withheld until there was a gate to honour
    /// it — "a stored override for a gate that does not exist is a promise the
    /// holder would be entitled to rely on". `persona/disclosure/present` now
    /// enforces `release: stepUp`, so the promise is one the agent keeps.
    ///
    /// Like `sensitivity`, an override wins in **both** directions — see
    /// [`crate::claim_types::release_of`] for why loosening is honoured rather
    /// than quietly refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseRequirement>,
    pub version: Version,
    /// Earlier versions the store still holds, and the faces that are the
    /// reason. Filled on read — never stored with the record — so a holder who
    /// overwrote a value learns it is not gone, and why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_versions: Vec<RetainedVersion>,
    pub created_at: String,
    pub updated_at: String,
}

/// An earlier version of an attribute, kept because a face pins it. Values are
/// not included: the holder reads one through the face that pins it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RetainedVersion {
    pub version: Version,
    pub updated_at: String,
    /// The faces pinning it. Never empty: a version nothing pins is not kept.
    pub pinned_by: Vec<Ulid>,
}

/// One line of a profile, in exactly one of four forms.
///
/// Together they are the whole of a profile's flexibility, and each covers a
/// case the others handle badly. Omission is exclusion — there is no removal
/// marker, because a profile is a whitelist and a blacklist over a growing pool
/// leaks by default the first time an attribute is added.
///
/// # `deny_unknown_fields` is load-bearing
///
/// `#[serde(untagged)]` tries variants in declaration order and takes the first
/// that deserializes. Without the clause, serde ignores unknown members, so the
/// permissive `Ref` — which needs only `ref` — also matches `{ref, override}`
/// and `{ref, pinVersion}`: an override silently degrades into a live reference
/// and a pin into an unpinned one. That is a disclosure changing behind the
/// holder's back, and it is *valid* output, so nothing downstream rejects it.
///
/// The clause makes an extra member *fail* a variant rather than match it
/// loosely, which fixes the defect at its cause. The variants are therefore
/// declared in reading order — general to specific — rather than in the order
/// that happened to be safe.
///
/// That ordering is deliberate and not merely tidier. Declaring the permissive
/// `Ref` last would also avoid the bug, and holding both mechanisms would mean
/// neither was ever exercised: a later edit dropping the clause would pass
/// every test, and the next edit reordering the variants would then be
/// silently fatal. With `Ref` first, the clause is the only thing standing
/// between the holder and a degraded disclosure, so
/// `each_profile_entry_form_survives_a_round_trip` fails the moment it is
/// removed. The published schema closes each form the same way, and
/// `trust-tasks-rs` generates the same pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ProfileEntry {
    /// Reference the pool attribute, live. Editing the pool updates every
    /// profile referencing it, which is the point.
    Ref {
        r#ref: Ulid,
        /// The role this entry plays in the face — see [`ProfileEntry::slot`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot: Option<String>,
    },
    /// Reference it as it was at a version. For a profile that must keep
    /// presenting the value a counterparty already verified.
    Pinned {
        r#ref: Ulid,
        #[serde(rename = "pinVersion")]
        pin_version: Version,
        /// The role this entry plays in the face — see [`ProfileEntry::slot`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot: Option<String>,
    },
    /// The same attribute, a different value here.
    ///
    /// Replaces value and label **only**: type, valueType and provenance are
    /// inherited. Letting an override replace provenance would let a
    /// self-asserted value present as attested, which is the one thing
    /// provenance exists to prevent.
    Override {
        r#ref: Ulid,
        r#override: OverrideValue,
        /// The role this entry plays in the face — see [`ProfileEntry::slot`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot: Option<String>,
    },
    /// A value that never enters the pool, and so can never leak into another
    /// profile.
    Inline {
        inline: InlineValue,
        /// The role this entry plays in the face — see [`ProfileEntry::slot`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slot: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverrideValue {
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InlineValue {
    pub r#type: String,
    pub value_type: ValueType,
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub provenance: Provenance,
}

impl ProfileEntry {
    /// The pool attribute this entry draws on, if any.
    ///
    /// `None` for an inline entry, which is what makes a context-local profile
    /// checkable: one is valid exactly when every entry returns `None` here.
    #[must_use]
    pub fn referenced(&self) -> Option<&str> {
        match self {
            Self::Ref { r#ref, .. } | Self::Pinned { r#ref, .. } | Self::Override { r#ref, .. } => {
                Some(r#ref)
            }
            Self::Inline { .. } => None,
        }
    }

    /// The role this entry plays in its face, where the holder named one —
    /// `displayName` for what the face calls itself.
    ///
    /// On every form, because a face may call itself by a pool value, a pinned
    /// one, an override or a value typed only here. Unique within a face:
    /// [`duplicate_slot`] finds the first repeat.
    #[must_use]
    pub fn slot(&self) -> Option<&str> {
        match self {
            Self::Ref { slot, .. }
            | Self::Pinned { slot, .. }
            | Self::Override { slot, .. }
            | Self::Inline { slot, .. } => slot.as_deref(),
        }
    }
}

/// The first slot two entries of one face both claim, if any.
///
/// A slot answers one question — "what does this face call itself" — with one
/// entry, and two answers is no answer: a consumer would pick one by position,
/// and which one it picked would change the moment the holder reordered the
/// face. So a face repeating a slot is refused whole, by both the pool and the
/// context-local write paths.
#[must_use]
pub fn duplicate_slot(entries: &[ProfileEntry]) -> Option<&str> {
    let mut seen = std::collections::BTreeSet::new();
    entries
        .iter()
        .filter_map(ProfileEntry::slot)
        .find(|s| !seen.insert(*s))
}

/// A named projection over the pool. **Agent-scoped**, like the pool it draws
/// from.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub profile_id: Ulid,
    /// The holder's name for it — "Work", "Gaming". Not disclosed.
    pub name: String,
    /// Ordered; the order is display order.
    pub entries: Vec<ProfileEntry>,
    /// Credentials associated with this profile as **inventory** — what this
    /// persona can prove — as distinct from the evidence relationship a
    /// credential-backed attribute expresses. The two answer different
    /// questions and must not be read as one another.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_refs: Vec<String>,
    /// Where this face may be worn. Absent reads as anywhere. A context-local
    /// face never carries one — it is worn in its context by construction.
    #[serde(default, skip_serializing_if = "FaceReach::is_anywhere")]
    pub reach: FaceReach,
    /// Whether the holder still wears this face. A face written before the
    /// field existed reads as active, which is what it was.
    #[serde(default, skip_serializing_if = "ProfileStatus::is_active")]
    pub status: ProfileStatus,
    /// When it was retired. Present exactly when `status` is `Retired`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
    pub version: Version,
    pub created_at: String,
    pub updated_at: String,
}

/// Whether a face is still worn — `persona/profile/retire`, design note
/// `persona-context-first.md` §9.4.
///
/// Mirrors the vault's archival axis rather than inventing a sibling: a retired
/// face is out of pickers and cannot be worn, and everything it carries and
/// every disclosure it made is kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProfileStatus {
    #[default]
    Active,
    Retired,
}

/// Where a pool face may be worn — `persona/profile/put` `reach`, design note
/// `persona-context-first.md` §5.4.
///
/// An enum, not `allowed_contexts: Vec<String>`. This workspace has been
/// bitten three times (#746, #769, #770) by an empty context list meaning two
/// opposite things; here "unrestricted" and "nowhere" cannot be confused,
/// because `Only` is never empty (the wire requires one context) and nowhere
/// is not a reach at all — it is a retired face.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FaceReach {
    #[default]
    Anywhere,
    #[serde(rename_all = "camelCase")]
    Only { context_ids: Vec<String> },
}

impl FaceReach {
    #[must_use]
    pub fn is_anywhere(&self) -> bool {
        *self == Self::Anywhere
    }

    /// Whether a face with this reach may be worn in `context_id`.
    #[must_use]
    pub fn admits(&self, context_id: &str) -> bool {
        match self {
            Self::Anywhere => true,
            Self::Only { context_ids } => context_ids.iter().any(|c| c == context_id),
        }
    }
}

impl ProfileStatus {
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }
}

/// A colour **name**, resolved by each consumer against its own palette.
///
/// Never a literal. A hex value cannot be legible in a terminal, a light theme
/// and a dark one at once, so a stored one is wrong somewhere and the holder
/// has no way to know where — and a consumer that reserves colours to carry
/// meaning (an error, a warning, an irreversible act) cannot keep a decorative
/// choice out of that channel unless the set is closed.
///
/// None of the eight is named for success, warning or danger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FacetColour {
    Slate,
    Indigo,
    Teal,
    Moss,
    Sand,
    Clay,
    Rose,
    Plum,
}

/// A named part of the holder's life, and what belongs to it. **Agent-scoped.**
///
/// An *arrangement*, not a container: nothing is stored inside a facet, and
/// deleting one deletes nothing but the arrangement. That distinction is the
/// whole of its design, and it is worth stating in the type because the
/// intuitive reading is the other one — a grouping that looked like a folder,
/// and behaved like one, would make `delete` the most dangerous call in this
/// crate, and a holder cannot tell which kind they have from the button.
///
/// `#[non_exhaustive]` from the start, for the reason [`Attribute`] acquired it
/// after two compatibility breaks: this record is going to grow as the persona
/// specification does, and the next member should be an addition rather than a
/// third break.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Facet {
    pub facet_id: Ulid,
    /// The holder's own word — "Work", "Home". Never disclosed, and never
    /// interpreted: it is not a scope, a policy input, or a name a counterparty
    /// sees. It is also the most revealing member in the record, which is easy
    /// to miss because it carries no value *about* the holder: "Work" discloses
    /// nothing and "the divorce" discloses a great deal. It MUST NOT reach an
    /// operational log or a metric label.
    pub name: String,
    pub colour: FacetColour,
    /// One or two emoji. Stored opaquely and never parsed; a consumer that
    /// cannot render it shows the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    /// Profiles belonging to this facet. A profile belongs to **at most one**,
    /// because this is where a consumer reads its colour from and two answers
    /// is no answer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub face_ids: Vec<Ulid>,
    /// Attributes belonging to this facet. An attribute **may** belong to
    /// several — a mobile number is genuinely part of both a working life and a
    /// home one — so no exclusivity is enforced here and none may be inferred.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attribute_ids: Vec<Ulid>,
    pub version: Version,
    pub created_at: String,
    pub updated_at: String,
}

/// Assignment of a profile to a persona DID. **Context-scoped.**
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
    pub persona_did: String,
    /// `None` clears the binding. A persona with no profile is a legitimate and
    /// common state — a throwaway identity that presents nothing — so this is a
    /// first-class value rather than an absence to be inferred.
    pub profile_id: Option<Ulid>,
    /// Attributes the holder opted into publishing on the persona's own public
    /// surface. Empty unless explicitly set: a published value is one document
    /// every relying party sees identically, which is a permanent correlation
    /// point that per-verifier projection exists to avoid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_entries: Vec<Ulid>,
    pub version: Version,
    pub bound_at: String,
    /// When the binding ends on its own (RFC 3339). Past it, every read treats
    /// the binding as cleared whether or not the sweeper has run — see
    /// `BindingRecord::into_read`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rung_ordering_makes_highest_supported_a_max() {
        // Ord is derived so that rung selection is `max()` over what a format
        // supports, not a hand-written table that can disagree with itself.
        assert!(ProofRung::Predicate < ProofRung::Derived);
        assert!(ProofRung::Derived < ProofRung::SelectiveDisclosure);
        assert!(ProofRung::SelectiveDisclosure < ProofRung::Whole);

        let supported = [ProofRung::Whole, ProofRung::Derived];
        assert_eq!(supported.iter().min().copied(), Some(ProofRung::Derived));
    }

    #[test]
    fn value_type_accepts_only_its_own_shape() {
        let s = serde_json::json!("x");
        let n = serde_json::json!(1);
        assert!(ValueType::String.accepts(&s));
        assert!(!ValueType::String.accepts(&n));
        assert!(ValueType::Number.accepts(&n));
        // A date is carried as a string and deliberately not parsed here.
        assert!(ValueType::Date.accepts(&s));
        assert!(!ValueType::Date.accepts(&n));
    }

    #[test]
    fn inline_entries_reference_nothing() {
        // This is what makes a context-local profile checkable: it is valid
        // exactly when no entry references the pool.
        let inline = ProfileEntry::Inline {
            slot: None,
            inline: InlineValue {
                r#type: "x:handle".into(),
                value_type: ValueType::String,
                value: serde_json::json!("g"),
                label: None,
                provenance: Provenance::SelfAsserted,
            },
        };
        assert!(inline.referenced().is_none());

        let by_ref = ProfileEntry::Ref {
            slot: None,
            r#ref: "01J8".into(),
        };
        assert_eq!(by_ref.referenced(), Some("01J8"));
    }

    /// The four forms must stay distinguishable on the wire.
    ///
    /// Asserted on round-tripped **bytes**, not on the parsed enum: a
    /// degradation does not fail to parse, it parses as the wrong thing and
    /// re-encodes shorter. Comparing the document to itself is what catches
    /// that; comparing enum variants would only catch it for the one case
    /// where the variant names differ.
    ///
    /// Remove `deny_unknown_fields` from `ProfileEntry` and this test fails on
    /// the `override` and `pinned` cases.
    #[test]
    fn each_profile_entry_form_survives_a_round_trip() {
        let cases = [
            ("ref", serde_json::json!({ "ref": "01J8" })),
            (
                "pinned",
                serde_json::json!({ "ref": "01J8", "pinVersion": 3 }),
            ),
            (
                "override",
                serde_json::json!({
                    "ref": "01J8",
                    "override": { "value": "+61 400 000 000" },
                }),
            ),
            (
                "inline",
                serde_json::json!({
                    "inline": {
                        "type": "name.display",
                        "value": "Ada",
                        "valueType": "string",
                        "provenance": { "kind": "selfAsserted" },
                    }
                }),
            ),
            (
                "ref+slot",
                serde_json::json!({ "ref": "01J8", "slot": "displayName" }),
            ),
            (
                "pinned+slot",
                serde_json::json!({ "ref": "01J8", "pinVersion": 3, "slot": "primaryPhone" }),
            ),
            (
                "override+slot",
                serde_json::json!({
                    "ref": "01J8",
                    "override": { "value": "Mickey" },
                    "slot": "displayName",
                }),
            ),
            (
                "inline+slot",
                serde_json::json!({
                    "inline": {
                        "type": "name.display",
                        "value": "Donald",
                        "valueType": "string",
                        "provenance": { "kind": "selfAsserted" },
                    },
                    "slot": "displayName",
                }),
            ),
        ];

        for (label, doc) in cases {
            let parsed: ProfileEntry =
                serde_json::from_value(doc.clone()).unwrap_or_else(|e| panic!("{label}: {e}"));
            let back = serde_json::to_value(&parsed).expect("re-encodes");
            assert_eq!(back, doc, "{label} form did not survive the round trip");
        }
    }

    /// A slotted pin must not become a slotted live reference. `slot` is on
    /// every form, so it cannot be what discriminates them — the rest of the
    /// members still must, and this is the case where getting that wrong
    /// presents a value the holder froze as whatever the pool holds now.
    #[test]
    fn a_slotted_pin_is_still_a_pin() {
        let parsed: ProfileEntry = serde_json::from_value(serde_json::json!({
            "ref": "01J8", "pinVersion": 7, "slot": "displayName"
        }))
        .expect("parses");
        assert!(
            matches!(&parsed, ProfileEntry::Pinned { pin_version: 7, slot: Some(s), .. } if s == "displayName"),
            "a slotted pin parsed as {parsed:?}"
        );
    }

    #[test]
    fn a_repeated_slot_is_found_and_distinct_slots_are_not() {
        let e = |slot: Option<&str>| ProfileEntry::Ref {
            r#ref: "01J8".into(),
            slot: slot.map(str::to_string),
        };
        assert_eq!(
            duplicate_slot(&[e(Some("displayName")), e(None), e(None)]),
            None
        );
        assert_eq!(
            duplicate_slot(&[e(Some("displayName")), e(Some("avatar"))]),
            None
        );
        assert_eq!(
            duplicate_slot(&[e(Some("displayName")), e(None), e(Some("displayName"))]),
            Some("displayName")
        );
    }

    /// The failure with teeth, stated on its own: a pin that quietly becomes a
    /// bare reference presents whatever the pool holds *now* instead of the
    /// version the holder chose to freeze.
    #[test]
    fn a_pin_does_not_collapse_into_a_bare_reference() {
        let parsed: ProfileEntry =
            serde_json::from_value(serde_json::json!({ "ref": "01J8", "pinVersion": 7 }))
                .expect("parses");
        assert!(
            matches!(parsed, ProfileEntry::Pinned { pin_version, .. } if pin_version == 7),
            "a pinned entry parsed as {parsed:?}"
        );
    }
}
