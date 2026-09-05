//! Wire payloads for the persona Trust Tasks (`spec/persona/*`).
//!
//! A fourth holder store beside the secrets vault, the credential vault and
//! [`crate::protocols::app_state`]: the holder's **own** identity — the
//! attributes they hold about themselves, the profiles that project over
//! those attributes, the persona DID a given context presents under, and the
//! contacts other people have disclosed to them.
//!
//! ## The boundary these types are shaped around
//!
//! Two scopes, and the split is not an access-control list — it is the
//! addressing:
//!
//! * **Agent-scoped**, above every trust context: the attribute pool
//!   (`attribute/*`), the profiles built over it (`profile/*`), correlation
//!   analysis, and the renderer registry. A caller reaching these must be
//!   *unrestricted* — an administrator scoped to a single context is refused,
//!   because the pool is not any context's to read.
//! * **Context-scoped**: bindings (`binding/*`), contacts (`contact/*`),
//!   disclosure (`disclosure/*`) and the context's own local profiles
//!   (`local/*`).
//!
//! Nothing inside a context may read the pool. The holder *pushes* a
//! materialised projection down; a context never pulls. That is why
//! [`LocalProfileEntry`] is a separate type from [`ProfileEntry`] rather than
//! the same type with some variants unused: a context-local profile can only
//! be built from [`inline`](LocalProfileEntry::inline) values, so there is
//! nowhere in the type to put a pool identifier. The published schema says the
//! same thing, and this mirror keeps saying it in Rust.
//!
//! ## Request bodies only
//!
//! Responses come back as [`Value`], as they do for `app-state`. These are the
//! shapes a caller must get right to be understood; a response is read by
//! whatever is rendering it.
//!
//! ## Why hand-written here and generated in the service
//!
//! `vta-service` builds these payloads from `trust-tasks-rs` directly, because
//! a mirror is a second definition of one contract and free to drift. This
//! crate cannot: `trust-tasks-rs` is an **optional** dependency here and the
//! `client` feature does not enable it, so a types-only consumer must not be
//! made to pull the generated tree in. Two source-level censuses cover the gap
//! the generated types would otherwise have closed — `payload_ext_census`
//! (every `deny_unknown_fields` body carries `ext`) and `payload_null_census`
//! (no optional member may serialize as `null`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Shared vocabulary
// ---------------------------------------------------------------------------

/// What a stored value *is*, as opposed to what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    String,
    Number,
    Boolean,
    Date,
    Object,
}

/// How strongly a credential-backed claim is hidden when presented, ordered
/// **most private first**.
///
/// The distinction between the first two and the last two is of kind, not
/// degree: only `Predicate` and `Derived` avoid handing two verifiers a join
/// key. A request that cannot be met at the rung asked for is refused rather
/// than quietly served at a lower one — a silent privacy downgrade discloses
/// material the holder believed was hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProofRung {
    /// Proves a statement over a claim without disclosing the claim.
    Predicate,
    /// Discloses exactly the claims needed, via a proof that differs on every
    /// presentation, so two disclosures cannot be joined.
    Derived,
    /// Discloses exactly the claims needed, but carries the issuer's signature
    /// unchanged — so two disclosures **are** linkable.
    SelectiveDisclosure,
    /// Discloses the entire credential.
    Whole,
}

/// Where a value came from, which is what decides how it may be presented.
///
/// Tagged on `kind` rather than inferred from which members are present, so a
/// `credentialBacked` claim missing its `credentialId` is a parse failure
/// rather than a claim that silently degrades to self-asserted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Provenance {
    /// The holder typed it. True of most of an address book.
    SelfAsserted,
    /// Backed by a credential the holder holds.
    #[serde(rename_all = "camelCase")]
    CredentialBacked {
        /// Vault identifier of the backing credential.
        credential_id: String,
        /// RFC 6901 JSON Pointer to the claim within it, e.g.
        /// `/credentialSubject/familyName`.
        claim_path: String,
        /// Advisory only. A consumer verifies the credential rather than
        /// trusting this member.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer_did: Option<String>,
        /// The rung this claim was, or will be, presented at.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<ProofRung>,
    },
    /// Minted by the agent — a relay address, a per-verifier alias.
    #[serde(rename_all = "camelCase")]
    Generated {
        /// Names the minting scheme, e.g. `relayEmail`. Maintainer-defined.
        generator: String,
        /// When true — the default, and the only useful setting — a distinct
        /// value is minted for each verifier.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        per_verifier: Option<bool>,
    },
}

// ---------------------------------------------------------------------------
// Profile entries
// ---------------------------------------------------------------------------

/// The value an [`ProfileEntry::Override`] substitutes for the pool's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OverrideValue {
    /// Replaces the pool attribute's value for this profile only.
    pub value: Value,
    /// Replaces its label too, when given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A value that lives in a profile and nowhere else.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InlineValue {
    /// The vocabulary token naming what this value is — `name.legal`,
    /// `phone.mobile`. Dotted, most-general segment first; `x:` opens an
    /// extension namespace.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// The value itself.
    pub value: Value,
    /// What the value is.
    pub value_type: ValueType,
    /// Where it came from.
    pub provenance: Provenance,
    /// The holder's own name for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// One line of an **agent-scoped** profile: how this profile takes a value.
///
/// Four forms, and the difference between them is the difference between "show
/// my current mobile" and "show the mobile I gave this employer in March":
///
/// * [`Ref`](Self::Ref) — track the pool. Editing the attribute changes what
///   this profile presents.
/// * [`Pinned`](Self::Pinned) — track one *version*. Later edits do not reach
///   it.
/// * [`Override`](Self::Override) — present something else entirely, without
///   putting that something in the pool.
/// * [`Inline`](Self::Inline) — a value that exists only here.
///
/// # `deny_unknown_fields` is load-bearing
///
/// This is an untagged union, so serde tries the variants in order and takes
/// the first that deserializes. Without `deny_unknown_fields` the `Ref` form —
/// which needs only `ref` — matches an `{ref, override}` document too, and the
/// override is dropped: the holder's substituted value silently becomes a live
/// reference to the pool, and a pin silently becomes unpinned. That is a
/// disclosure changing behind the holder's back, and it is the exact bug this
/// crate's counterpart hit before the schema's own `deny_unknown_fields` was
/// mirrored here. With the clause, an extra member makes a variant *fail*
/// rather than match loosely, so the forms stay distinguishable no matter what
/// order they are declared in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum ProfileEntry {
    /// Track the pool attribute at whatever version it currently holds.
    Ref {
        #[serde(rename = "ref")]
        attribute_id: String,
    },
    /// Track one specific version of the pool attribute.
    #[serde(rename_all = "camelCase")]
    Pinned {
        #[serde(rename = "ref")]
        attribute_id: String,
        pin_version: ::std::num::NonZeroU64,
    },
    /// Take the pool attribute's identity but present a different value.
    Override {
        #[serde(rename = "ref")]
        attribute_id: String,
        #[serde(rename = "override")]
        override_value: OverrideValue,
    },
    /// A value that exists only in this profile.
    Inline { inline: InlineValue },
}

/// One line of a **context-local** profile.
///
/// Inline only — and that is the one-way boundary, expressed as a type rather
/// than as a check. A profile built inside a trust context cannot reference,
/// pin or override an attribute in the agent-scoped pool, because there is
/// nowhere in this struct to name one. A context that wants the holder's real
/// mobile number gets it because the holder pushed it down, never because
/// something inside the context reached up for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalProfileEntry {
    /// The value, carried in full. There is no other form.
    pub inline: InlineValue,
}

// ---------------------------------------------------------------------------
// The pool — agent-scoped. `persona/attribute/*`
// ---------------------------------------------------------------------------

/// `spec/persona/attribute/put/1.0` — create or update one pool attribute.
///
/// Omit [`attribute_id`](Self::attribute_id) to create. Supplying one makes a
/// create idempotent; supplying one that already exists is an update, and the
/// VTA refuses rather than silently overwriting when the version precondition
/// says otherwise.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaAttributePutBody {
    /// The vocabulary token naming what this value is.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// The value.
    pub value: Value,
    /// What the value is.
    pub value_type: ValueType,
    /// Where it came from.
    pub provenance: Provenance,
    /// The holder's own name for it — "work mobile", "the flat".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Address an existing attribute, or make a create idempotent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    /// Optimistic-concurrency precondition: the attribute must be at exactly
    /// this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1). Carried explicitly
    /// so `deny_unknown_fields` still refuses a *typo* while letting through
    /// the one member the spec says a conforming producer may always send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/attribute/list/1.0` — enumerate the pool.
///
/// Metadata-only by default. [`include_values`](Self::include_values) is what
/// turns a listing into a read of the holder's identity, which is why it is
/// opt-in rather than the default a caller forgets to narrow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaAttributeListBody {
    /// Match on a dotted prefix — `phone` returns `phone.mobile` and
    /// `phone.work`. The vocabulary is prefix-groupable precisely so a
    /// consumer that has never heard of a token can still file it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_prefix: Option<String>,
    /// Return values, not just metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_values: Option<bool>,
    /// Include attributes whose backing credential could no longer be
    /// re-derived. Defaults to true: a holder deciding what to present needs
    /// to see that something went stale, not to have it quietly omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_stale: Option<bool>,
    /// Page size. Absent takes the maintainer's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<::std::num::NonZeroU64>,
    /// Continuation token from a previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/attribute/delete/1.0` — remove one pool attribute.
///
/// Without [`cascade`](Self::cascade) the delete is refused while any profile
/// still references the attribute, rather than leaving those profiles
/// presenting a dangling reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaAttributeDeleteBody {
    /// The attribute to remove.
    pub attribute_id: String,
    /// Also drop every profile entry that references it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cascade: Option<bool>,
    /// Optimistic-concurrency precondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Profiles — agent-scoped. `persona/profile/*`
// ---------------------------------------------------------------------------

/// `spec/persona/profile/put/1.0` — create or update an agent-scoped profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaProfilePutBody {
    /// The holder's name for this projection — "work", "gaming", "the one my
    /// family sees".
    pub name: String,
    /// How this profile takes each of its values. See [`ProfileEntry`].
    pub entries: Vec<ProfileEntry>,
    /// Credentials tagged as belonging with this profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_refs: Vec<String>,
    /// Address an existing profile, or make a create idempotent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Optimistic-concurrency precondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/profile/get/1.0` — read one profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaProfileGetBody {
    /// The profile to read.
    pub profile_id: String,
    /// Resolve every entry against the pool and return the values this profile
    /// would actually present, rather than the references it is built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve: Option<bool>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/profile/list/1.0` — enumerate agent-scoped profiles.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaProfileListBody {
    /// Page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<::std::num::NonZeroU64>,
    /// Continuation token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/profile/delete/1.0` — remove an agent-scoped profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaProfileDeleteBody {
    /// The profile to remove.
    pub profile_id: String,
    /// Also clear every binding that points at it. Without this the delete is
    /// refused while a persona still presents under the profile — a context
    /// losing its identity mid-relationship is not something to do by
    /// omission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unbind: Option<bool>,
    /// Optimistic-concurrency precondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Bindings — context-scoped. `persona/binding/*`
// ---------------------------------------------------------------------------

/// `spec/persona/binding/set/1.0` — assign a profile to a persona DID within
/// one context.
///
/// This is the push across the boundary: the profile is resolved
/// agent-side and a *materialised* projection is written into the context.
/// The context receives values, never pool identifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaBindingSetBody {
    /// The context the binding lives in.
    pub context_id: String,
    /// The persona DID this binding is for.
    pub persona_did: String,
    /// The agent-scoped profile to project. Omit to clear the binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Attributes disclosed without asking — the subset a verifier in this
    /// context receives with no per-disclosure decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_entries: Vec<String>,
    /// Optimistic-concurrency precondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/binding/get/1.0` — what one persona DID presents in one
/// context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaBindingGetBody {
    /// The context.
    pub context_id: String,
    /// The persona DID.
    pub persona_did: String,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/binding/list/1.0` — every persona bound in one context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaBindingListBody {
    /// The context.
    pub context_id: String,
    /// Page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<::std::num::NonZeroU64>,
    /// Continuation token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Contacts — context-scoped. `persona/contact/*`
// ---------------------------------------------------------------------------

/// One claim inside a contact document, as the *other* party published it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactClaim {
    /// The vocabulary token.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// The value.
    pub value: Value,
    /// What the value is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<ValueType>,
    /// The publisher's own label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What the publisher claimed about where the value came from. Advisory
    /// until the backing credential is verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

/// What someone disclosed about themselves.
///
/// Stored as received. The holder does not merge it into their own pool, and
/// that separation is the point: a contact is somebody else's account of
/// themselves, not a fact the holder is asserting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactDocument {
    /// The claims the publisher disclosed.
    pub claims: Vec<ContactClaim>,
    /// The publisher's own version counter, if they carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_version: Option<::std::num::NonZeroU64>,
    /// Who published it, as they named themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<Value>,
}

/// `spec/persona/contact/put/1.0` — record what a peer disclosed.
///
/// A new revision rather than an overwrite: the previous one is retained while
/// anything still references it, so "what did they tell me in March" survives
/// them changing their mind in April.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaContactPutBody {
    /// The context this contact belongs to.
    pub context_id: String,
    /// The DID the disclosure came from.
    pub subject_did: String,
    /// Which of the holder's own personas knows this contact. Required, not
    /// optional: a contact filed against no persona is a contact the holder
    /// cannot later reason about disclosing to.
    pub known_by_persona: String,
    /// What they disclosed.
    pub document: ContactDocument,
    /// Credentials received alongside it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_refs: Vec<String>,
    /// The holder's private annotation. Never disclosed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/contact/get/1.0` — read one contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaContactGetBody {
    /// The context.
    pub context_id: String,
    /// The contact.
    pub contact_id: String,
    /// Read one specific revision instead of the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<::std::num::NonZeroU64>,
    /// Return every retained revision, so a holder can see what changed and
    /// when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_history: Option<bool>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/contact/list/1.0` — enumerate contacts in one context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaContactListBody {
    /// The context.
    pub context_id: String,
    /// Only contacts filed against this persona.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_by_persona: Option<String>,
    /// Only contacts whose current revision is newer than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_since: Option<String>,
    /// Page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<::std::num::NonZeroU64>,
    /// Continuation token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/contact/delete/1.0` — forget a contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaContactDeleteBody {
    /// The context.
    pub context_id: String,
    /// The contact.
    pub contact_id: String,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Disclosure — context-scoped. `persona/disclosure/*`
// ---------------------------------------------------------------------------

/// `spec/persona/disclosure/preview/1.0` — what would this disclosure reveal?
///
/// Signs nothing and sends nothing. The first of two calls that cannot be
/// collapsed: the `previewId` it returns is what
/// [`PersonaDisclosurePresentBody`] consumes, so there is no code path to a
/// disclosure that skipped the summary. Single-use and short-lived — a preview
/// approved an hour ago is not evidence of approval now.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaDisclosurePreviewBody {
    /// The context.
    pub context_id: String,
    /// The persona that would present. Its binding supplies the profile.
    pub persona_did: String,
    /// Who would receive it. Required rather than optional, because half of
    /// what a preview says is who is asking — one that could not name the
    /// recipient would be a list of fields rather than a decision.
    pub verifier_did: String,
    /// Claim types the verifier asked for. Omit to preview everything the
    /// bound profile would present; when present, nothing outside it is
    /// returned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_claims: Vec<String>,
    /// The verifier's stated reason, carried into the preview and the
    /// disclosure record so a holder deciding later has the context a holder
    /// deciding now had.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Which output format to prepare for. Omit for the canonical form. It
    /// matters to the *preview* because renderers differ in what they can
    /// carry, and a holder is owed that before deciding rather than after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renderer: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/disclosure/present/1.0` — hand over what the preview showed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaDisclosurePresentBody {
    /// The context.
    pub context_id: String,
    /// The preview being acted on. Consumed — a second `present` on the same
    /// id is refused rather than riding the earlier decision.
    pub preview_id: String,
    /// Verifier-supplied nonce to bind the disclosure to this exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// Ask for the disclosure as a self-issued credential rather than a bare
    /// document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<Value>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/disclosure/history/1.0` — what was disclosed, to whom, when.
///
/// The record the holder needs to answer "what does this verifier already
/// know", which is also what makes a later preview rankable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaDisclosureHistoryBody {
    /// Narrow to one context. Omit to read across all of them — which is a
    /// holder-scoped read, and gated as one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Narrow to one verifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_did: Option<String>,
    /// Narrow to one claim type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_type: Option<String>,
    /// Only disclosures after this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<::std::num::NonZeroU64>,
    /// Continuation token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Correlation and renderers — agent-scoped.
// ---------------------------------------------------------------------------

/// `spec/persona/correlation/analyze/1.0` — how linkable would this make me?
///
/// Reads the pool and writes nothing. Note the inversion that is easy to get
/// backwards: a credential presented **whole** correlates *more* than a
/// self-asserted value, because the issuer's signature is byte-identical at
/// every verifier — while a derived proof correlates *less*, because it
/// differs on every presentation. Severity is a function of value and rung
/// together, never of provenance alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaCorrelationAnalyzeBody {
    /// Analyse one existing attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_id: Option<String>,
    /// Analyse an entire profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Analyse a value the holder has not stored — "what would happen if I
    /// gave them this". The answer is worth more before the disclosure than
    /// after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<Value>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/renderers/list/1.0` — the output formats this VTA can
/// produce, and what each one **cannot carry**.
///
/// Lossiness is declared rather than discovered. A holder is owed "this
/// verifier will see your work number but not that your employer attested it"
/// before deciding, not after.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaRenderersListBody {
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

// ---------------------------------------------------------------------------
// Context-local profiles and bindings. `persona/local/*`
// ---------------------------------------------------------------------------

/// `spec/persona/local/profile/put/1.0` — a profile that lives inside one
/// context.
///
/// For an identity the holder keeps *only* here, with no pool attribute behind
/// it. Its entries are [`LocalProfileEntry`] — inline only — so a context
/// cannot build a profile that reaches into the agent-scoped pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaLocalProfilePutBody {
    /// The context this profile belongs to.
    pub context_id: String,
    /// The holder's name for it.
    pub name: String,
    /// Its values, carried in full.
    pub entries: Vec<LocalProfileEntry>,
    /// Address an existing local profile, or make a create idempotent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Optimistic-concurrency precondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/local/profile/get/1.0` — read one context-local profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaLocalProfileGetBody {
    /// The context.
    pub context_id: String,
    /// The profile.
    pub profile_id: String,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/local/profile/list/1.0` — enumerate one context's own
/// profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaLocalProfileListBody {
    /// The context.
    pub context_id: String,
    /// Page size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<::std::num::NonZeroU64>,
    /// Continuation token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/local/profile/delete/1.0` — remove a context-local profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaLocalProfileDeleteBody {
    /// The context.
    pub context_id: String,
    /// The profile.
    pub profile_id: String,
    /// Also clear any local binding pointing at it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unbind: Option<bool>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

/// `spec/persona/local/binding/set/1.0` — bind a persona DID to a
/// **context-local** profile.
///
/// The counterpart to [`PersonaBindingSetBody`] for an identity that never
/// existed above the context. There is no pool read on this path at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonaLocalBindingSetBody {
    /// The context.
    pub context_id: String,
    /// The persona DID.
    pub persona_did: String,
    /// The context-local profile to bind. Omit to clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Optimistic-concurrency precondition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four profile-entry forms must stay distinguishable.
    ///
    /// This is an untagged union: serde tries the variants and takes the first
    /// that deserializes. `Ref` needs only `ref`, so without
    /// `deny_unknown_fields` it matches every one of these documents — and an
    /// override becomes a live reference, a pin becomes unpinned, and the
    /// holder's disclosure changes without them touching it. The assertion is
    /// on round-tripped *bytes* rather than on the enum, because what reaches
    /// the VTA is the document, not the value that produced it.
    #[test]
    fn each_profile_entry_form_survives_a_round_trip() {
        let cases = [
            (
                "ref",
                serde_json::json!({ "ref": "01J0000000000000000000000A" }),
            ),
            (
                "pinned",
                serde_json::json!({
                    "ref": "01J0000000000000000000000A",
                    "pinVersion": 3,
                }),
            ),
            (
                "override",
                serde_json::json!({
                    "ref": "01J0000000000000000000000A",
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
        ];

        for (label, doc) in cases {
            let parsed: ProfileEntry =
                serde_json::from_value(doc.clone()).unwrap_or_else(|e| panic!("{label}: {e}"));
            let back = serde_json::to_value(&parsed).expect("re-encodes");
            assert_eq!(back, doc, "{label} form did not survive the round trip");
        }
    }

    /// A pinned entry must not degrade into an unpinned one.
    ///
    /// Stated separately from the round-trip above because this is the failure
    /// with teeth: the degraded document is still *valid*, so nothing rejects
    /// it — the VTA simply presents whatever the pool holds now instead of the
    /// version the holder pinned.
    #[test]
    fn a_pin_does_not_collapse_into_a_bare_reference() {
        let doc = serde_json::json!({
            "ref": "01J0000000000000000000000A",
            "pinVersion": 7,
        });
        let parsed: ProfileEntry = serde_json::from_value(doc).expect("parses");
        assert!(
            matches!(parsed, ProfileEntry::Pinned { pin_version, .. } if pin_version.get() == 7),
            "a pinned entry parsed as {parsed:?}"
        );
    }

    /// A context-local profile entry has nowhere to name a pool attribute.
    ///
    /// The one-way boundary, checked as a parse failure rather than as a
    /// convention: a document that tries to reference the agent-scoped pool
    /// from inside a context is refused by the type, not by a handler that
    /// might forget.
    #[test]
    fn a_local_entry_cannot_reference_the_pool() {
        let doc = serde_json::json!({ "ref": "01J0000000000000000000000A" });
        serde_json::from_value::<LocalProfileEntry>(doc)
            .expect_err("a local entry must not accept a pool reference");
    }

    /// Provenance is tagged, so an incomplete `credentialBacked` claim is a
    /// parse failure rather than a claim that quietly becomes self-asserted.
    #[test]
    fn credential_backed_provenance_needs_its_credential() {
        serde_json::from_value::<Provenance>(serde_json::json!({ "kind": "credentialBacked" }))
            .expect_err("credentialBacked without a credentialId must not parse");
    }
}
