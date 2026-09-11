//! Community branding — how the community presents itself to an applicant's
//! client.
//!
//! One row in the `community` keyspace at [`BRANDING_STORAGE_KEY`]. Published
//! as `branding` on `join-requests/manifest/0.2`, and managed by an admin with
//! `GET`/`PUT /v1/community/branding`. The shape is the manifest's own
//! [`CommunityBranding`], generated from `vtc/join-requests/manifest/0.2`: what
//! an admin stores is exactly what the manifest publishes. Every member is
//! optional, and a community that has set none publishes no `branding` at all.

use vta_sdk::protocols::join_requests::manifest::v0_2::{
    CommunityBranding, CommunityBrandingAccentColor,
};
use vta_sdk::protocols::vetting::CheckShape;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Storage key in the `community` keyspace. Beside
/// [`super::PROFILE_STORAGE_KEY`], and backed up with it.
pub const BRANDING_STORAGE_KEY: &[u8] = b"community/branding";

/// Nothing set: a community with this branding publishes none.
#[must_use]
pub fn is_empty(branding: &CommunityBranding) -> bool {
    branding.display_name.is_none()
        && branding.accent_color.is_none()
        && branding.logo_url.is_none()
        && branding.ext.is_none()
}

/// The stored branding, or the empty branding when none has been set.
pub async fn load_branding(ks: &KeyspaceHandle) -> Result<CommunityBranding, AppError> {
    match ks.get_raw(BRANDING_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("community branding decode: {e}"))),
        None => Ok(CommunityBranding::default()),
    }
}

/// Replace the branding, and return what was stored. Checks it against the
/// manifest schema first, and writes `accentColor` in lower case, as the
/// manifest specification asks (the colour is compared case-insensitively). An
/// empty branding removes the row, so the manifest publishes none.
pub async fn store_branding(
    ks: &KeyspaceHandle,
    branding: &CommunityBranding,
) -> Result<CommunityBranding, AppError> {
    branding
        .check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let mut stored = branding.clone();
    stored.accent_color = stored
        .accent_color
        .map(|c| CommunityBrandingAccentColor::try_from(c.to_ascii_lowercase()))
        .transpose()
        .map_err(|e| AppError::Validation(format!("accentColor: {e}")))?;
    if is_empty(&stored) {
        ks.remove(BRANDING_STORAGE_KEY.to_vec()).await?;
        return Ok(stored);
    }
    let key = String::from_utf8(BRANDING_STORAGE_KEY.to_vec()).expect("key is ASCII");
    ks.insert(key, &stored).await?;
    Ok(stored)
}

/// The wire names of the members that differ between `before` and `after`,
/// for the audit record.
pub fn fields_changed(before: &CommunityBranding, after: &CommunityBranding) -> Vec<String> {
    let mut changed = Vec::new();
    if before.display_name != after.display_name {
        changed.push("displayName".to_string());
    }
    if before.accent_color != after.accent_color {
        changed.push("accentColor".to_string());
    }
    if before.logo_url != after.logo_url {
        changed.push("logoUrl".to_string());
    }
    // `ext` is an open map with no equality of its own; compare what it
    // serialises to.
    if serde_json::to_value(&before.ext).ok() != serde_json::to_value(&after.ext).ok() {
        changed.push("ext".to_string());
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    async fn ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("community").unwrap();
        (dir, store, ks)
    }

    fn branded_json() -> Value {
        json!({
            "displayName": "Linux Kernel",
            "accentColor": "#1a2b3c",
            "logoUrl": "https://kernel.example.org/logo.svg"
        })
    }

    fn branding(value: Value) -> CommunityBranding {
        serde_json::from_value(value).unwrap()
    }

    fn wire(branding: &CommunityBranding) -> Value {
        serde_json::to_value(branding).unwrap()
    }

    #[tokio::test]
    async fn branding_round_trips_and_clearing_it_removes_the_row() {
        let (_d, _s, ks) = ks().await;
        assert!(is_empty(&load_branding(&ks).await.unwrap()));
        store_branding(&ks, &branding(branded_json()))
            .await
            .unwrap();
        assert_eq!(wire(&load_branding(&ks).await.unwrap()), branded_json());
        store_branding(&ks, &CommunityBranding::default())
            .await
            .unwrap();
        assert!(ks.get_raw(BRANDING_STORAGE_KEY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_accent_color_is_stored_in_lower_case() {
        let (_d, _s, ks) = ks().await;
        let mut upper = branded_json();
        upper["accentColor"] = json!("#1A2B3C");
        let stored = store_branding(&ks, &branding(upper)).await.unwrap();
        assert_eq!(
            stored.accent_color.as_deref().map(String::as_str),
            Some("#1a2b3c")
        );
        assert_eq!(wire(&load_branding(&ks).await.unwrap()), branded_json());
    }

    /// Refused on the way in by the generated member types, or by the
    /// manifest schema when stored — never stored either way.
    #[tokio::test]
    async fn out_of_bounds_branding_is_refused_and_not_stored() {
        let (_d, _s, ks) = ks().await;
        for (member, value) in [
            ("accentColor", json!("red")),
            ("accentColor", json!("#12345g")),
            ("logoUrl", json!("http://kernel.example.org/logo.svg")),
            ("displayName", json!("x".repeat(129))),
            ("displayName", json!("")),
            ("tagline", json!("x")),
        ] {
            let mut bad = branded_json();
            bad[member] = value;
            if let Ok(parsed) = serde_json::from_value::<CommunityBranding>(bad) {
                assert!(
                    matches!(
                        store_branding(&ks, &parsed).await,
                        Err(AppError::Validation(_))
                    ),
                    "{member}"
                );
            }
        }
        assert!(is_empty(&load_branding(&ks).await.unwrap()));
    }

    #[test]
    fn changed_fields_are_named_as_on_the_wire() {
        let mut after = branded_json();
        after["accentColor"] = json!("#000000");
        after["ext"] = json!({ "org.example.console": { "theme": "dark" } });
        assert_eq!(
            fields_changed(&branding(branded_json()), &branding(after)),
            vec!["accentColor", "ext"]
        );
    }
}
