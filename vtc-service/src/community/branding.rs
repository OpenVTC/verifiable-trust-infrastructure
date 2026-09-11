//! Community branding — how the community presents itself to an applicant's
//! client.
//!
//! One row in the `community` keyspace at [`BRANDING_STORAGE_KEY`]. Published
//! as `branding` on `join-requests/manifest/0.2`, and managed by an admin with
//! `GET`/`PUT /v1/community/branding`. The shape is
//! [`vta_sdk::protocols::join_requests::CommunityBranding`]; every member is
//! optional, and a community that has set none publishes no `branding` at all.

use vta_sdk::protocols::join_requests::CommunityBranding;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Storage key in the `community` keyspace. Beside
/// [`super::PROFILE_STORAGE_KEY`], and backed up with it.
pub const BRANDING_STORAGE_KEY: &[u8] = b"community/branding";

/// The stored branding, or the empty branding when none has been set.
pub async fn load_branding(ks: &KeyspaceHandle) -> Result<CommunityBranding, AppError> {
    match ks.get_raw(BRANDING_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("community branding decode: {e}"))),
        None => Ok(CommunityBranding::default()),
    }
}

/// Replace the branding, and return what was stored. Checks the bounds first,
/// and writes `accentColor` in lower case, as the manifest specification asks
/// (the colour is compared case-insensitively). An empty branding removes the
/// row, so the manifest publishes none.
pub async fn store_branding(
    ks: &KeyspaceHandle,
    branding: &CommunityBranding,
) -> Result<CommunityBranding, AppError> {
    branding
        .check_shape()
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let mut stored = branding.clone();
    stored.accent_color = stored.accent_color.map(|c| c.to_ascii_lowercase());
    if stored.is_empty() {
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
    if before.ext != after.ext {
        changed.push("ext".to_string());
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn branded() -> CommunityBranding {
        CommunityBranding {
            display_name: Some("Linux Kernel".into()),
            accent_color: Some("#1a2b3c".into()),
            logo_url: Some("https://kernel.example.org/logo.svg".into()),
            ext: None,
        }
    }

    #[tokio::test]
    async fn branding_round_trips_and_clearing_it_removes_the_row() {
        let (_d, _s, ks) = ks().await;
        assert!(load_branding(&ks).await.unwrap().is_empty());
        store_branding(&ks, &branded()).await.unwrap();
        assert_eq!(load_branding(&ks).await.unwrap(), branded());
        store_branding(&ks, &CommunityBranding::default())
            .await
            .unwrap();
        assert!(ks.get_raw(BRANDING_STORAGE_KEY).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_accent_color_is_stored_in_lower_case() {
        let (_d, _s, ks) = ks().await;
        let stored = store_branding(
            &ks,
            &CommunityBranding {
                accent_color: Some("#1A2B3C".into()),
                ..branded()
            },
        )
        .await
        .unwrap();
        assert_eq!(stored.accent_color.as_deref(), Some("#1a2b3c"));
        assert_eq!(load_branding(&ks).await.unwrap(), branded());
    }

    #[tokio::test]
    async fn out_of_bounds_branding_is_refused_and_not_stored() {
        let (_d, _s, ks) = ks().await;
        for bad in [
            CommunityBranding {
                accent_color: Some("red".into()),
                ..branded()
            },
            CommunityBranding {
                accent_color: Some("#12345g".into()),
                ..branded()
            },
            CommunityBranding {
                logo_url: Some("http://kernel.example.org/logo.svg".into()),
                ..branded()
            },
            CommunityBranding {
                display_name: Some("x".repeat(129)),
                ..branded()
            },
            CommunityBranding {
                display_name: Some(String::new()),
                ..branded()
            },
        ] {
            assert!(matches!(
                store_branding(&ks, &bad).await,
                Err(AppError::Validation(_))
            ));
        }
        assert!(load_branding(&ks).await.unwrap().is_empty());
    }

    #[test]
    fn changed_fields_are_named_as_on_the_wire() {
        let mut after = branded();
        after.accent_color = Some("#000000".into());
        after.ext = Some(serde_json::json!({ "x": 1 }));
        assert_eq!(
            fields_changed(&branded(), &after),
            vec!["accentColor", "ext"]
        );
    }
}
