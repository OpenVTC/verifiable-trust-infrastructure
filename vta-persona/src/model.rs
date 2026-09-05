//! The record shapes the `persona/*` Trust Task family made normative.
//!
//! Two scopes, and the split is a security control rather than a filing
//! decision. The **attribute pool and profiles are agent-scoped** — one person,
//! one set of facts about themselves, above every trust context — so that the
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

/// One atomic fact a holder keeps about themselves. **Agent-scoped.**
///
/// Several attributes may share a `type` — three phone numbers, a legal name and
/// a preferred name — which is why `attribute_id` is the identity of a fact and
/// `type` is not.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    pub version: Version,
    pub created_at: String,
    pub updated_at: String,
}

/// One line of a profile, in exactly one of four forms.
///
/// Together they are the whole of a profile's flexibility, and each covers a
/// case the others handle badly. Omission is exclusion — there is no removal
/// marker, because a profile is a whitelist and a blacklist over a growing pool
/// leaks by default the first time an attribute is added.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProfileEntry {
    /// Reference the pool attribute, live. Editing the pool updates every
    /// profile referencing it, which is the point.
    Ref { r#ref: Ulid },
    /// Reference it as it was at a version. For a profile that must keep
    /// presenting the value a counterparty already verified.
    Pinned {
        r#ref: Ulid,
        #[serde(rename = "pinVersion")]
        pin_version: Version,
    },
    /// The same fact, a different value here.
    ///
    /// Replaces value and label **only**: type, valueType and provenance are
    /// inherited. Letting an override replace provenance would let a
    /// self-asserted value present as attested, which is the one thing
    /// provenance exists to prevent.
    Override {
        r#ref: Ulid,
        r#override: OverrideValue,
    },
    /// A value that never enters the pool, and so can never leak into another
    /// profile.
    Inline { inline: InlineValue },
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
            Self::Ref { r#ref } | Self::Pinned { r#ref, .. } | Self::Override { r#ref, .. } => {
                Some(r#ref)
            }
            Self::Inline { .. } => None,
        }
    }
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
            r#ref: "01J8".into(),
        };
        assert_eq!(by_ref.referenced(), Some("01J8"));
    }
}
