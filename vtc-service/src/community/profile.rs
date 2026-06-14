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
    pub created_at: DateTime<Utc>,
    /// Opaque per-community JSON. Capped at [`MAX_EXTENSIONS_BYTES`]
    /// when serialised. Defaults to `null` when no extension data
    /// is set.
    #[serde(default)]
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

        let mut changed = Vec::new();
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
}
