//! Whether this community answers "what do you require of people who join?"
//! to a caller it cannot identify.
//!
//! One row in the `community` keyspace at [`JOIN_DISCOVERY_STORAGE_KEY`],
//! beside [`super::PROFILE_STORAGE_KEY`] and [`super::branding`], and managed
//! by an admin with `GET`/`PUT /v1/community/join-discovery`.
//!
//! # Why its own row rather than a member of the profile
//!
//! `vtc/community/profile/show/0.1` is a published schema with
//! `additionalProperties: false`, and `ProfileWithStatus` flattens
//! [`CommunityProfile`](super::profile::CommunityProfile) into its response —
//! so a new member of the profile is a new member of that canonical answer,
//! which this service is not the place to add. The conformance witness says so
//! directly, and it is right to: the profile is a *published* description of
//! the community, and this is an operational choice about how one endpoint
//! behaves. They are different things that happen to be edited on the same
//! console page.
//!
//! # What "off" means
//!
//! Not secrecy. The join manifest is a public read by design — an applicant
//! has to know what is asked of them *before* they disclose anything, which is
//! the whole of "informed non-application" — and an identified caller is
//! answered either way. Off makes the answer *attributable*: a signed Trust
//! Task document over REST, or an authcrypt DIDComm sender, still gets it.
//! Refusing those would break the join ceremony rather than close anything.
//!
//! A closed or invite-only community is the case this exists for: it
//! reasonably treats its admission criteria as something you learn once you
//! are talking to it, rather than something a crawler enumerates.

use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Storage key in the `community` keyspace.
pub const JOIN_DISCOVERY_STORAGE_KEY: &[u8] = b"community/join-discovery";

/// Whether the join manifest answers an unidentified caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct JoinDiscovery {
    /// Answer the manifest to a caller this community cannot identify.
    ///
    /// Defaults to **true**, which is what every community did before this
    /// setting existed. A default of `false` would stop answering applicants
    /// that were being answered yesterday, for operators who never chose it —
    /// a setting that changes behaviour nobody opted into is not a setting,
    /// it is a regression with a checkbox.
    #[serde(default = "yes")]
    pub public: bool,
}

/// `true`, as a `serde(default)` path.
fn yes() -> bool {
    true
}

impl Default for JoinDiscovery {
    fn default() -> Self {
        Self { public: true }
    }
}

/// The stored setting, or the answering default when none has been set.
///
/// An absent row is a community that never chose, which is every community
/// that predates this setting — and they were all answering.
pub async fn load_join_discovery(ks: &KeyspaceHandle) -> Result<JoinDiscovery, AppError> {
    match ks.get_raw(JOIN_DISCOVERY_STORAGE_KEY).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("community join discovery decode: {e}"))),
        None => Ok(JoinDiscovery::default()),
    }
}

/// Replace the setting, and return what was stored.
pub async fn store_join_discovery(
    ks: &KeyspaceHandle,
    setting: &JoinDiscovery,
) -> Result<JoinDiscovery, AppError> {
    let key = String::from_utf8(JOIN_DISCOVERY_STORAGE_KEY.to_vec()).expect("key is ASCII");
    ks.insert(key, setting).await?;
    Ok(setting.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The default is the behaviour every community had before the setting
    /// existed, and an absent row must read as that rather than as "off".
    #[test]
    fn a_community_that_never_chose_publishes() {
        assert!(JoinDiscovery::default().public);
        let absent: JoinDiscovery = serde_json::from_value(json!({})).expect("parse");
        assert!(
            absent.public,
            "a stored row missing the member reads as answering"
        );
    }

    /// `public` is the wire name the console and operators read.
    #[test]
    fn the_setting_travels_under_its_wire_name() {
        let off: JoinDiscovery = serde_json::from_value(json!({ "public": false })).expect("parse");
        assert!(!off.public);
        assert_eq!(
            serde_json::to_value(&off).expect("serialise"),
            json!({ "public": false })
        );
    }
}
