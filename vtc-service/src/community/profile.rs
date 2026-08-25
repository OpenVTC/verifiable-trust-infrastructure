//! [`CommunityProfile`] — the singleton record describing the
//! community itself.
//!
//! Per spec §5.1:
//!
//! - `community_did` is **immutable** — set at install (M0.6) and
//!   never reshapeable from REST. PUT requests that try to change
//!   it return 409.
//! - All other fields are editable by an admin via `PUT
//!   /v1/community/profile`.
//! - `extensions` is the universal extensibility slot (§3-M). Opaque
//!   JSON; the VTC validates only that the serialised blob fits
//!   inside [`MAX_EXTENSIONS_BYTES`].
//! - `language` defaults to `"en"` (BCP 47). No translation
//!   handling yet — that's a deliberate v2 deferral per spec §18.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Fjall key under which the singleton profile is stored. Stable
/// for the lifetime of the VTC.
pub const PROFILE_STORAGE_KEY: &[u8] = b"community/profile";

/// Hard cap on the serialised size of the [`CommunityProfile::extensions`]
/// blob, per plan **D4**. PUT requests carrying a larger blob return
/// 413. Larger blobs would inflate every audit + backup row that
/// references the profile.
pub const MAX_EXTENSIONS_BYTES: usize = 16 * 1024;

/// Length caps (in Unicode scalar values) for the operator-set public
/// profile text fields. Served on the unauth public-profile endpoint,
/// so they're bounded to keep the response — and every audit/backup row
/// that references the profile — from carrying unbounded content.
const MAX_NAME_LEN: usize = 200;
const MAX_DESCRIPTION_LEN: usize = 4_000;
const MAX_LOGO_URL_LEN: usize = 2_048;
const MAX_CONTACT_EMAIL_LEN: usize = 320;

/// Reject a field whose char count exceeds `max`. No-op when the field
/// is absent from the patch.
fn cap_len(field: &str, value: Option<&str>, max: usize) -> Result<(), AppError> {
    if let Some(v) = value
        && v.chars().count() > max
    {
        return Err(AppError::Validation(format!(
            "{field} exceeds {max} characters (got {})",
            v.chars().count()
        )));
    }
    Ok(())
}

/// Identifier form a community declares when it has not chosen one. DTG
/// Credentials recommends relationship DIDs, so silence declares the more
/// conservative expectation rather than the more convenient one.
pub const RELATIONSHIP_IDENTIFIER_DEFAULT: &str = "pairwise";

/// The two identifier forms a community may declare.
pub const RELATIONSHIP_IDENTIFIER_FORMS: [&str; 2] = ["attributed", "pairwise"];

fn default_relationship_identifier() -> String {
    RELATIONSHIP_IDENTIFIER_DEFAULT.to_string()
}

/// What a community's governance asserts about personhood, and therefore
/// whether its VMCs may be read as PHCs.
///
/// DTG Credentials §Personhood Credentials: "A PHC is simply a VMC issued by
/// a VTC whose governance enforces: real human personhood; exactly one
/// membership per person."  Those two clauses are the two booleans here.
///
/// ## Both halves, separately
///
/// They are separate fields because they are separately achievable, and a
/// community that has one without the other should be able to say so. This
/// daemon's in-person vetting supports the first — an administrator meets
/// someone and issues them an identity-verification endorsement — and does
/// nothing at all for the second. Collapsing them into one `is_phc` flag
/// would force every such community to either overclaim or stay silent.
///
/// ## Declaration, not enforcement — and the honesty rule that follows
///
/// Like [`CommunityProfile::relationship_identifier_default`], this describes
/// what the community's governance requires. Nothing here makes the daemon
/// enforce anything.
///
/// That makes an overclaim worse than silence. Before this field, a verifier
/// reading a `PersonhoodCredential` type had no authoritative source and knew
/// it; a `singleMembership: true` from a community that does not enforce
/// uniqueness gives that verifier a false one. **Do not set a flag the
/// community's governance does not actually require** — and note that
/// requiring it is not the same as this daemon checking it. `personhood.rego`
/// is where a requirement becomes a gate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct PersonhoodGovernance {
    /// Governance requires that members are real humans.
    ///
    /// Defaults to `false`: a community that has not considered the question
    /// asserts nothing, which is the only safe default for a claim a verifier
    /// may rely on.
    #[serde(default)]
    pub real_human: bool,
    /// Governance requires that each person holds at most one membership in
    /// **this** community.
    ///
    /// Per-community by definition — the spec's glossary says "exactly one
    /// membership in that VTC" — so a single community can satisfy this
    /// without any network above it.
    ///
    /// This is the half that needs an anchor the community cannot supply
    /// itself: nothing in the credential graph distinguishes one person with
    /// two DIDs from two people. See `docs/03-vtc/personhood-and-graph.md`.
    #[serde(default)]
    pub single_membership: bool,
    /// DIDs of the identity-verification providers whose credentials this
    /// community accepts as personhood evidence.
    ///
    /// §Governance Considerations item 1: identity-proofing requirements
    /// "including acceptable IDVPs and IDVCs" are the community's to define
    /// and are "published via trust registries". A community that vets its
    /// own members in person lists its own C-DID here — it is acting as its
    /// own IDVP, which §IDVC permits.
    ///
    /// Advisory to verifiers, not a gate: `personhood.rego` decides what is
    /// actually accepted. An empty list means the community has not published
    /// one, not that it accepts everything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_idvps: Vec<String>,
    /// Where the governance framework this all refers to can be read.
    ///
    /// The ToIP Governance Metamodel the spec cites expects a human-readable
    /// document behind these assertions. The booleans above are the
    /// machine-readable summary; this is the thing they summarise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_framework_url: Option<String>,
}

impl PersonhoodGovernance {
    /// Whether this community's governance claims its VMCs are PHCs.
    ///
    /// **Both** clauses, because the spec's definition is a conjunction. A
    /// community asserting real-human but not single-membership has members
    /// it believes are people; it does not have personhood credentials, and
    /// one person may hold several of them.
    pub fn claims_phc(&self) -> bool {
        self.real_human && self.single_membership
    }
}

/// The singleton record. Field names are wire contract — operators
/// + the admin UX read this shape directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CommunityProfile {
    /// Immutable — set at install time. PUT requests cannot change
    /// this; see [`CommunityProfileUpdate`].
    pub community_did: String,
    pub name: String,
    pub description: String,
    pub logo_url: Option<String>,
    pub public_url: Option<String>,
    pub contact_email: Option<String>,
    /// BCP 47 language tag. Defaults to `"en"`.
    pub language: String,
    /// Which identifier form this community expects members to issue
    /// relationship credentials under — `"attributed"` (the member's
    /// membership DID, so edges name them) or `"pairwise"` (a relationship
    /// DID unique to each counterparty).
    ///
    /// A **declaration, not an enforcement**: the member still chooses per
    /// relationship, and both forms are accepted. It exists so a client can
    /// read what the community expects *before* minting — a public
    /// open-source community reasonably declares `attributed`, one organised
    /// around privacy declares `pairwise`.
    ///
    /// A community that wants to *require* a form does so in
    /// `relationships.rego`, which receives `identifier_form` on every
    /// publish. Defaults to `"pairwise"`, matching DTG Credentials'
    /// recommendation, so a community that has not considered the question
    /// declares the more conservative expectation.
    ///
    /// `serde(default)` is load-bearing: a config export taken before this
    /// field existed must still import. Without it every saved export becomes
    /// unreadable — which the admin-config round-trip tests caught.
    #[serde(default = "default_relationship_identifier")]
    pub relationship_identifier_default: String,
    /// What this community's governance says about personhood.
    ///
    /// DTG Credentials §Personhood Credentials puts PHC status here rather
    /// than in the credential: "PHC status is determined by governance and
    /// trust registries, not by credential structure", and the
    /// `PersonhoodCredential` type this daemon stamps on a vetted member's
    /// VMC is described there as a *non-authoritative hint*. §Governance
    /// Considerations item 2 is blunter still: "Whether a VMC qualifies as a
    /// PHC is a governance determination, not a schema property."
    ///
    /// Without this field a conformant verifier had nothing to read. The
    /// type array told it not to trust the type array, and there was no
    /// second place to look.
    #[serde(default)]
    pub personhood: PersonhoodGovernance,
    pub created_at: DateTime<Utc>,
    /// Opaque per-community JSON. Capped at [`MAX_EXTENSIONS_BYTES`]
    /// when serialised. Defaults to `null` when no extension data
    /// is set.
    ///
    /// Omitted from the wire when null. The canonical `CommunityProfile`
    /// component types this `object` and does not require it, so absent is the
    /// conforming way to say "none" and `null` is a type error. It went out as
    /// `null` until #1107 — the conformance fixture set a non-empty object, so
    /// a hand-chosen value hid it even after the fixture was built from this
    /// very struct. Deriving a fixture from the real type only helps for the
    /// members you do not then hand-set.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub extensions: Value,
}

impl CommunityProfile {
    /// Build a fresh profile for a newly-installed community. The
    /// `community_did` becomes immutable after this point.
    pub fn new(community_did: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            community_did: community_did.into(),
            name: name.into(),
            description: String::new(),
            logo_url: None,
            public_url: None,
            contact_email: None,
            language: "en".into(),
            relationship_identifier_default: RELATIONSHIP_IDENTIFIER_DEFAULT.into(),
            // A fresh community asserts nothing about personhood. An
            // operator turns these on when their governance says so.
            personhood: PersonhoodGovernance::default(),
            created_at: Utc::now(),
            extensions: Value::Null,
        }
    }
}

/// PUT-shaped patch. Distinct from [`CommunityProfile`] because the
/// `community_did` and `created_at` fields are immutable — exposing
/// them on the request body invites tampering, so we drop them at
/// the type level.
///
/// Every field is `Option` so a PUT can update a subset of fields
/// while leaving the rest unchanged. Setting `extensions: Some(Value::Null)`
/// clears the blob; omitting it (`None`) leaves it untouched.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct CommunityProfileUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub logo_url: Option<Option<String>>,
    pub public_url: Option<Option<String>>,
    pub contact_email: Option<Option<String>>,
    pub language: Option<String>,
    /// See [`CommunityProfile::relationship_identifier_default`]. Must be one
    /// of [`RELATIONSHIP_IDENTIFIER_FORMS`].
    pub relationship_identifier_default: Option<String>,
    /// See [`PersonhoodGovernance`]. Replaced wholesale rather than merged
    /// field-by-field: the two booleans are a conjunction the operator is
    /// asserting together, and a partial patch that flipped one while leaving
    /// the other at whatever it happened to be is how a community ends up
    /// claiming PHC status it did not mean to claim.
    pub personhood: Option<PersonhoodGovernance>,
    pub extensions: Option<Value>,
}

impl CommunityProfileUpdate {
    /// Apply the patch to `profile` in-place, returning the list of
    /// field names that actually changed. The list feeds the
    /// `CommunityProfileUpdated` audit event (M0.1.5) and the route
    /// response.
    ///
    /// Validates [`Self::extensions`] size **before** mutating
    /// anything, so a too-large extension blob doesn't half-apply
    /// the patch.
    pub fn apply(self, profile: &mut CommunityProfile) -> Result<Vec<String>, AppError> {
        if let Some(ext) = &self.extensions {
            let bytes = serde_json::to_vec(ext).map_err(AppError::Serialization)?;
            if bytes.len() > MAX_EXTENSIONS_BYTES {
                return Err(AppError::Validation(format!(
                    "extensions blob exceeds {MAX_EXTENSIONS_BYTES} bytes (got {})",
                    bytes.len()
                )));
            }
        }

        // Cap the operator-set text fields — they're served on the
        // unauth `/v1/community/public-profile`, so an unbounded value
        // is a stored-payload lever. Validate BEFORE mutating anything
        // so an over-cap field doesn't half-apply the patch.
        cap_len("name", self.name.as_deref(), MAX_NAME_LEN)?;
        cap_len(
            "description",
            self.description.as_deref(),
            MAX_DESCRIPTION_LEN,
        )?;
        cap_len(
            "contactEmail",
            self.contact_email.as_ref().and_then(|v| v.as_deref()),
            MAX_CONTACT_EMAIL_LEN,
        )?;
        if let Some(Some(logo)) = self.logo_url.as_ref() {
            cap_len("logoUrl", Some(logo), MAX_LOGO_URL_LEN)?;
            // A logo URL ends up in an <img src> on the public page;
            // restrict it to http(s) so it can't carry a `javascript:`
            // / `data:` payload.
            if !(logo.is_empty() || logo.starts_with("https://") || logo.starts_with("http://")) {
                return Err(AppError::Validation(
                    "logoUrl must be an http(s) URL".into(),
                ));
            }
        }

        // Validated before mutating, with the other pre-checks: an
        // unrecognised value would be published to clients as the community's
        // expectation, and they cannot act on a form they do not understand.
        if let Some(form) = self.relationship_identifier_default.as_deref()
            && !RELATIONSHIP_IDENTIFIER_FORMS.contains(&form)
        {
            return Err(AppError::Validation(format!(
                "relationshipIdentifierDefault must be one of {:?} (got {form:?})",
                RELATIONSHIP_IDENTIFIER_FORMS
            )));
        }

        // Validated with the other pre-checks, for the same reason: a
        // governance URL is published to clients as where this community's
        // rules can be read, and one that is not fetchable over http(s) is
        // either a mistake or a lever — the same reasoning as `logoUrl`.
        if let Some(p) = self.personhood.as_ref()
            && let Some(url) = p.governance_framework_url.as_deref()
            && !(url.starts_with("https://") || url.starts_with("http://"))
        {
            return Err(AppError::Validation(
                "personhood.governanceFrameworkUrl must be an http(s) URL".into(),
            ));
        }
        // Refuse the overclaim outright rather than publish it. `claims_phc`
        // is what a verifier reads to decide whether these VMCs are PHCs, and
        // the spec's own §Governance Considerations makes acceptable IDVPs
        // part of what governance must publish. A community claiming PHC
        // status while naming nobody it trusts to verify identity has not
        // written that governance down — and a verifier cannot tell an
        // unwritten policy from a permissive one.
        if let Some(p) = self.personhood.as_ref()
            && p.claims_phc()
            && p.accepted_idvps.is_empty()
        {
            return Err(AppError::Validation(
                "personhood claiming both realHuman and singleMembership must name at least \
                 one entry in acceptedIdvps — a community acting as its own identity-\
                 verification provider lists its own DID"
                    .into(),
            ));
        }

        let mut changed = Vec::new();
        if let Some(personhood) = self.personhood
            && profile.personhood != personhood
        {
            profile.personhood = personhood;
            changed.push("personhood".into());
        }
        if let Some(form) = self.relationship_identifier_default
            && profile.relationship_identifier_default != form
        {
            profile.relationship_identifier_default = form;
            changed.push("relationshipIdentifierDefault".into());
        }
        if let Some(name) = self.name
            && profile.name != name
        {
            profile.name = name;
            changed.push("name".into());
        }
        if let Some(description) = self.description
            && profile.description != description
        {
            profile.description = description;
            changed.push("description".into());
        }
        if let Some(logo_url) = self.logo_url
            && profile.logo_url != logo_url
        {
            profile.logo_url = logo_url;
            changed.push("logoUrl".into());
        }
        if let Some(public_url) = self.public_url
            && profile.public_url != public_url
        {
            profile.public_url = public_url;
            changed.push("publicUrl".into());
        }
        if let Some(contact_email) = self.contact_email
            && profile.contact_email != contact_email
        {
            profile.contact_email = contact_email;
            changed.push("contactEmail".into());
        }
        if let Some(language) = self.language
            && profile.language != language
        {
            profile.language = language;
            changed.push("language".into());
        }
        if let Some(extensions) = self.extensions
            && profile.extensions != extensions
        {
            profile.extensions = extensions;
            changed.push("extensions".into());
        }
        Ok(changed)
    }
}

/// Load the singleton profile. Returns `Ok(None)` if no profile has
/// been initialised yet — the caller (handler) turns that into 404.
pub async fn load_profile(ks: &KeyspaceHandle) -> Result<Option<CommunityProfile>, AppError> {
    ks.get(PROFILE_STORAGE_KEY.to_vec()).await
}

/// Persist (insert or replace) the singleton profile.
pub async fn store_profile(
    ks: &KeyspaceHandle,
    profile: &CommunityProfile,
) -> Result<(), AppError> {
    ks.insert(PROFILE_STORAGE_KEY.to_vec(), profile).await
}

/// Iterate profile fields as `(key, old_value, new_value)` triples
/// (camelCase keys — wire-stable). Includes `community_did` so a
/// mismatched-but-allowed (fresh-install) import surfaces it in the
/// diff. The single source of truth for "which profile fields exist"
/// — both the admin-config import preview and the audit before/after
/// enrichment build on it.
pub(crate) fn profile_field_pairs(
    current: Option<&CommunityProfile>,
    incoming: &CommunityProfile,
) -> Vec<(&'static str, Option<Value>, Option<Value>)> {
    let s = |v: &str| Value::String(v.to_string());
    let opt_s = |v: &Option<String>| match v {
        Some(s) => Value::String(s.clone()),
        None => Value::Null,
    };
    vec![
        (
            "communityDid",
            current.map(|p| s(&p.community_did)),
            Some(s(&incoming.community_did)),
        ),
        ("name", current.map(|p| s(&p.name)), Some(s(&incoming.name))),
        (
            "description",
            current.map(|p| s(&p.description)),
            Some(s(&incoming.description)),
        ),
        (
            "logoUrl",
            current.map(|p| opt_s(&p.logo_url)),
            Some(opt_s(&incoming.logo_url)),
        ),
        (
            "publicUrl",
            current.map(|p| opt_s(&p.public_url)),
            Some(opt_s(&incoming.public_url)),
        ),
        (
            "contactEmail",
            current.map(|p| opt_s(&p.contact_email)),
            Some(opt_s(&incoming.contact_email)),
        ),
        (
            "language",
            current.map(|p| s(&p.language)),
            Some(s(&incoming.language)),
        ),
        (
            "extensions",
            current.map(|p| p.extensions.clone()),
            Some(incoming.extensions.clone()),
        ),
    ]
}

/// Before/after [`FieldChange`]s for the fields that actually changed
/// between `prior` and `incoming`. Powers the `changes` enrichment on
/// the `CommunityProfileUpdated` audit event.
pub(crate) fn profile_changes(
    prior: Option<&CommunityProfile>,
    incoming: &CommunityProfile,
) -> Vec<vti_common::audit::FieldChange> {
    profile_field_pairs(prior, incoming)
        .into_iter()
        .filter(|(_, old, new)| old != new)
        .map(|(field, old, new)| vti_common::audit::FieldChange {
            field: field.to_string(),
            old,
            new,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn temp_ks() -> (KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        (store.keyspace("community-test").expect("ks"), dir)
    }

    fn sample() -> CommunityProfile {
        CommunityProfile::new("did:webvh:vtc.example.com:abc", "Example Community")
    }

    #[tokio::test]
    async fn load_returns_none_when_not_initialised() {
        let (ks, _dir) = temp_ks();
        let got = load_profile(&ks).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn store_then_load_round_trips() {
        let (ks, _dir) = temp_ks();
        let p = sample();
        store_profile(&ks, &p).await.unwrap();
        let back = load_profile(&ks).await.unwrap().unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn apply_no_fields_yields_empty_changeset() {
        let mut p = sample();
        let snapshot = p.clone();
        let changed = CommunityProfileUpdate::default().apply(&mut p).unwrap();
        assert!(changed.is_empty());
        assert_eq!(p, snapshot);
    }

    #[test]
    fn apply_changes_only_returned_fields() {
        let mut p = sample();
        let update = CommunityProfileUpdate {
            name: Some("Renamed".into()),
            description: Some("Now described".into()),
            ..CommunityProfileUpdate::default()
        };
        let changed = update.apply(&mut p).unwrap();
        assert_eq!(changed, vec!["name", "description"]);
        assert_eq!(p.name, "Renamed");
        assert_eq!(p.description, "Now described");
    }

    #[test]
    fn apply_omits_unchanged_value_from_changeset() {
        let mut p = sample();
        // Re-asserting the same name should produce an empty change set.
        let update = CommunityProfileUpdate {
            name: Some(p.name.clone()),
            ..CommunityProfileUpdate::default()
        };
        let changed = update.apply(&mut p).unwrap();
        assert!(changed.is_empty());
    }

    #[test]
    fn apply_handles_optional_field_clears() {
        let mut p = sample();
        p.logo_url = Some("https://a.example/logo.png".into());

        let update = CommunityProfileUpdate {
            logo_url: Some(None),
            ..CommunityProfileUpdate::default()
        };
        let changed = update.apply(&mut p).unwrap();
        assert_eq!(changed, vec!["logoUrl"]);
        assert!(p.logo_url.is_none());
    }

    #[test]
    fn rejects_oversized_text_fields() {
        for (label, update) in [
            (
                "name",
                CommunityProfileUpdate {
                    name: Some("x".repeat(MAX_NAME_LEN + 1)),
                    ..Default::default()
                },
            ),
            (
                "description",
                CommunityProfileUpdate {
                    description: Some("x".repeat(MAX_DESCRIPTION_LEN + 1)),
                    ..Default::default()
                },
            ),
            (
                "contactEmail",
                CommunityProfileUpdate {
                    contact_email: Some(Some("x".repeat(MAX_CONTACT_EMAIL_LEN + 1))),
                    ..Default::default()
                },
            ),
        ] {
            let mut p = sample();
            let err = update
                .apply(&mut p)
                .expect_err("oversized must be rejected");
            assert!(matches!(err, AppError::Validation(_)), "{label}: {err:?}");
        }
    }

    #[test]
    fn rejects_non_http_logo_url_but_accepts_https() {
        let mut p = sample();
        let bad = CommunityProfileUpdate {
            logo_url: Some(Some("javascript:alert(1)".into())),
            ..Default::default()
        };
        assert!(bad.apply(&mut p).is_err());

        let mut p = sample();
        let ok = CommunityProfileUpdate {
            logo_url: Some(Some("https://cdn.example.com/logo.png".into())),
            ..Default::default()
        };
        assert_eq!(ok.apply(&mut p).unwrap(), vec!["logoUrl"]);
    }

    #[test]
    fn extensions_under_limit_apply() {
        let mut p = sample();
        let blob = json!({ "x": "a".repeat(100) });
        let update = CommunityProfileUpdate {
            extensions: Some(blob.clone()),
            ..CommunityProfileUpdate::default()
        };
        update.apply(&mut p).unwrap();
        assert_eq!(p.extensions, blob);
    }

    #[test]
    fn extensions_at_limit_apply() {
        let mut p = sample();
        // A string just under the cap, accounting for JSON quoting +
        // 4-byte object framing `{"":""}`.
        let body_len = MAX_EXTENSIONS_BYTES - 10;
        let blob = json!({ "k": "a".repeat(body_len) });
        let serialised = serde_json::to_vec(&blob).unwrap();
        assert!(serialised.len() <= MAX_EXTENSIONS_BYTES);
        let update = CommunityProfileUpdate {
            extensions: Some(blob),
            ..CommunityProfileUpdate::default()
        };
        update.apply(&mut p).unwrap();
    }

    #[test]
    fn extensions_over_limit_rejected_with_validation_error() {
        let mut p = sample();
        let original_name = p.name.clone();
        let huge = json!({ "k": "a".repeat(MAX_EXTENSIONS_BYTES + 10) });
        let update = CommunityProfileUpdate {
            // Combine with a name change to confirm the failed
            // validation aborts BEFORE other fields apply.
            name: Some("would-have-changed".into()),
            extensions: Some(huge),
            ..CommunityProfileUpdate::default()
        };
        let err = update.apply(&mut p).expect_err("too large");
        assert!(matches!(err, AppError::Validation(_)));
        assert_eq!(p.name, original_name, "name must not have been mutated");
    }

    #[test]
    fn profile_default_language_is_en() {
        let p = sample();
        assert_eq!(p.language, "en");
    }

    // ─── personhood governance ───────────────────────────────────────────

    fn governance(real_human: bool, single_membership: bool) -> PersonhoodGovernance {
        PersonhoodGovernance {
            real_human,
            single_membership,
            accepted_idvps: vec!["did:webvh:idvp.example".into()],
            governance_framework_url: Some("https://acme.example/governance".into()),
        }
    }

    /// A fresh community asserts nothing. Any other default would have every
    /// community that never considered the question publishing a claim a
    /// verifier might rely on.
    #[test]
    fn a_new_community_claims_no_personhood() {
        let p = sample();
        assert!(!p.personhood.real_human);
        assert!(!p.personhood.single_membership);
        assert!(!p.personhood.claims_phc());
        assert!(p.personhood.accepted_idvps.is_empty());
    }

    /// The spec's definition is a conjunction: "real human personhood" **and**
    /// "exactly one membership per person". Either half alone is not a PHC —
    /// a community with the first has members it believes are people, and one
    /// person may hold several of their credentials.
    #[test]
    fn phc_needs_both_halves() {
        assert!(!governance(false, false).claims_phc());
        assert!(!governance(true, false).claims_phc());
        assert!(!governance(false, true).claims_phc());
        assert!(governance(true, true).claims_phc());
    }

    /// The honesty rule. A community claiming PHC status while naming nobody
    /// it trusts to verify identity has not written its governance down, and
    /// a verifier cannot tell an unwritten policy from a permissive one.
    #[test]
    fn a_phc_claim_must_name_an_idvp() {
        let mut p = sample();
        let err = CommunityProfileUpdate {
            personhood: Some(PersonhoodGovernance {
                accepted_idvps: vec![],
                ..governance(true, true)
            }),
            ..CommunityProfileUpdate::default()
        }
        .apply(&mut p)
        .expect_err("a PHC claim with no IDVP must be refused");

        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            !p.personhood.claims_phc(),
            "the refused claim must not have half-applied"
        );
    }

    /// The same emptiness is fine when no PHC claim is being made — a
    /// community may say "our members are people" without having published a
    /// list of who may attest that.
    #[test]
    fn a_partial_claim_may_name_no_idvp() {
        let mut p = sample();
        let changed = CommunityProfileUpdate {
            personhood: Some(PersonhoodGovernance {
                accepted_idvps: vec![],
                ..governance(true, false)
            }),
            ..CommunityProfileUpdate::default()
        }
        .apply(&mut p)
        .expect("a non-PHC claim needs no IDVP list");

        assert!(changed.contains(&"personhood".to_string()));
        assert!(p.personhood.real_human);
    }

    /// A governance URL is published as where this community's rules can be
    /// read. Same reasoning as `logoUrl`: a non-http(s) value is either a
    /// mistake or a lever.
    #[test]
    fn the_governance_url_must_be_http() {
        let mut p = sample();
        let err = CommunityProfileUpdate {
            personhood: Some(PersonhoodGovernance {
                governance_framework_url: Some("javascript:alert(1)".into()),
                ..governance(true, true)
            }),
            ..CommunityProfileUpdate::default()
        }
        .apply(&mut p)
        .expect_err("a non-http governance URL must be refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    /// Replaced wholesale, not merged. Patching one boolean while the other
    /// keeps whatever it happened to be is how a community ends up claiming
    /// PHC status it never asserted.
    #[test]
    fn a_personhood_patch_replaces_rather_than_merges() {
        let mut p = sample();
        p.personhood = governance(true, true);

        CommunityProfileUpdate {
            personhood: Some(PersonhoodGovernance {
                real_human: true,
                single_membership: false,
                accepted_idvps: vec![],
                governance_framework_url: None,
            }),
            ..CommunityProfileUpdate::default()
        }
        .apply(&mut p)
        .expect("downgrading a claim is always allowed");

        assert!(!p.personhood.claims_phc(), "the claim must have dropped");
        assert!(
            p.personhood.accepted_idvps.is_empty(),
            "the old IDVP list must not survive a replacement that omitted it"
        );
        assert!(p.personhood.governance_framework_url.is_none());
    }

    /// A config written before this field existed must still load — the same
    /// property `relationshipIdentifierDefault` needed, and which the
    /// admin-config round-trip tests caught when it was missing.
    #[test]
    fn a_profile_without_personhood_still_deserializes() {
        let mut raw = serde_json::to_value(sample()).expect("profile -> json");
        raw.as_object_mut().expect("object").remove("personhood");

        let p: CommunityProfile = serde_json::from_value(raw).expect("pre-field config must load");
        assert!(!p.personhood.claims_phc());
    }
}
