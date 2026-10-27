//! Where the identities this community mints are published: its groups'
//! (`vtc/groups/create`) and its own rooms' (`vtc/rooms/community/create`).
//!
//! Either this community serves each `did.jsonl` itself, at
//! `<public_url>/group-dids/<id>/did.jsonl` and `/room-dids/<id>/did.jsonl`, or
//! its VTA publishes it on a `did:webvh` hosting server registered there, named
//! by its id at the VTA.
//!
//! The choice is the runtime key [`DIDS_WEBVH_SERVER`] (`config/patch`,
//! `vtc/config/import`, the console's Configuration page): a server id, or
//! [`LOCAL`]. Unset, each kind keeps its own `config.toml` setting
//! (`[groups] webvh_server`, `[rooms.community] webvh_server`), and absent
//! those, this community serves the identity itself — exactly as before the key
//! existed.
//!
//! A change applies to the next identity minted. An identity already minted
//! stays where it was published: its DID names its host, so moving it would be
//! a new DID.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;

use crate::config::AppConfig;
use crate::config_store::ConfigStore;

/// The runtime key.
pub const DIDS_WEBVH_SERVER: &str = "dids.webvh_server";
/// Its value for "this community serves the identities itself".
pub const LOCAL: &str = "local";
/// The environment variable that overrides it.
pub const ENV: &str = "VTC_DIDS_WEBVH_SERVER";
const MAX_LEN: usize = 128;

/// The runtime key for how the identities this community mints are presented:
/// `webvh` or `scid` (VTI-VTC-004).
pub const DIDS_DEFAULT_DID_METHOD: &str = "dids.default_did_method";
/// The runtime key for whether a new log lists its did:scid alias
/// (VTI-VTC-004, VTI-KEY-166).
pub const DIDS_SCID_ALSO_KNOWN_AS: &str = "dids.scid_also_known_as";
/// The environment variables that override them.
pub const ENV_DID_METHOD: &str = "VTC_DIDS_DEFAULT_DID_METHOD";
pub const ENV_SCID_ALSO_KNOWN_AS: &str = "VTC_DIDS_SCID_ALSO_KNOWN_AS";

/// `[dids]` in `config.toml`: the file layer of [`DIDS_WEBVH_SERVER`],
/// [`DIDS_DEFAULT_DID_METHOD`] and [`DIDS_SCID_ALSO_KNOWN_AS`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DidsConfig {
    /// A `did:webvh` hosting server registered at the community's VTA, by its
    /// id there, or `"local"`. Absent: each kind's own setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_server: Option<String>,
    /// How the community's identities are presented: `webvh` or `scid`.
    /// Absent: the VTA's `[dids]` decides (VTI-VTC-004, VTI-VTA-036).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_did_method: Option<vta_sdk::did_scid::DidMethod>,
    /// Whether a new log lists its did:scid alias. Absent: the VTA's `[dids]`
    /// decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scid_also_known_as: Option<bool>,
}

impl DidsConfig {
    pub fn is_empty(&self) -> bool {
        self.webvh_server.is_none()
            && self.default_did_method.is_none()
            && self.scid_also_known_as.is_none()
    }
}

/// A value [`DIDS_DEFAULT_DID_METHOD`] may hold: `webvh` or `scid`.
pub fn validate_did_method(value: &Value) -> Result<vta_sdk::did_scid::DidMethod, AppError> {
    value
        .as_str()
        .ok_or_else(|| "not a string".to_string())
        .and_then(|s| s.parse())
        .map_err(|e| AppError::Validation(format!("{DIDS_DEFAULT_DID_METHOD}: {e}")))
}

/// What the community states, in its create requests to its VTA, about how a
/// new identity is presented (VTI-VTC-004): the environment, then the stored
/// override, then `[dids]`. `None` for a member none of them states — the VTA's
/// own `[dids]` then applies (VTI-VTA-036). A malformed value in any layer is
/// ignored, never acted on.
pub async fn live_presentation(
    cfg: &AppConfig,
    db: &ConfigStore,
) -> Result<(Option<vta_sdk::did_scid::DidMethod>, Option<bool>), AppError> {
    let method = match std::env::var(ENV_DID_METHOD).ok() {
        Some(v) => Some(Value::String(v)),
        None => db.get(DIDS_DEFAULT_DID_METHOD).await?,
    }
    .and_then(|v| validate_did_method(&v).ok())
    .or(cfg.dids.default_did_method);
    let alias = match std::env::var(ENV_SCID_ALSO_KNOWN_AS).ok() {
        Some(v) => v.parse::<bool>().ok(),
        None => db
            .get(DIDS_SCID_ALSO_KNOWN_AS)
            .await?
            .and_then(|v| v.as_bool()),
    }
    .or(cfg.dids.scid_also_known_as);
    Ok((method, alias))
}

/// What the community states about a new identity's presentation, as the
/// layers say — see [`live_presentation`].
pub type Presentation = (Option<vta_sdk::did_scid::DidMethod>, Option<bool>);

/// The identity a minted DID is given out as: the did:webvh DID, or for one
/// presented as its did:scid, the did:scid DID URL with the `src` a recipient
/// needs to resolve it (VTI-KEY-163).
pub fn presented_did(
    minted: &vta_sdk::protocols::did_management::create::CreateDidWebvhResultBody,
) -> String {
    match (&minted.did_method, &minted.scid_did_url) {
        (Some(vta_sdk::did_scid::DidMethod::Scid), Some(url)) => url.clone(),
        _ => minted.did.clone(),
    }
}

/// Add what the community states to a `vta/webvh/dids/create` payload, and the
/// type URI to send it as: 1.2 when it states anything, so a community that
/// states nothing sends exactly what it did before.
pub fn with_presentation(
    payload: &mut Value,
    presentation: (Option<vta_sdk::did_scid::DidMethod>, Option<bool>),
) -> &'static str {
    let (method, alias) = presentation;
    if let Some(method) = method {
        payload["didMethod"] = Value::String(method.as_str().to_string());
    }
    if let Some(alias) = alias {
        payload["scidAlsoKnownAs"] = Value::Bool(alias);
    }
    if method.is_some() || alias.is_some() {
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_2
    } else {
        vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_1
    }
}

/// A value [`DIDS_WEBVH_SERVER`] may hold: `"local"`, or a server id —
/// letters, digits and `.`, `_`, `:`, `-`, at most 128.
pub fn validate(value: &Value) -> Result<(), AppError> {
    let Some(s) = value.as_str() else {
        return Err(AppError::Validation(format!(
            "{DIDS_WEBVH_SERVER} is a string: a hosting server's id at the community's VTA, or \
             \"{LOCAL}\""
        )));
    };
    if s == LOCAL {
        return Ok(());
    }
    let well_formed = !s.is_empty()
        && s.len() <= MAX_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if !well_formed {
        return Err(AppError::Validation(format!(
            "{DIDS_WEBVH_SERVER} names a hosting server by its id at the community's VTA \
             (letters, digits, `.`, `_`, `:`, `-`, at most {MAX_LEN}), or is \"{LOCAL}\""
        )));
    }
    Ok(())
}

/// Where the community's identities go now, as the layers say: the
/// environment, then the stored override, then `[dids]` — `None` when none of
/// them says. A malformed value in any layer is ignored, never acted on.
pub async fn live(cfg: &AppConfig, db: &ConfigStore) -> Result<Option<String>, AppError> {
    let layered = match std::env::var(ENV).ok() {
        Some(v) => Some(Value::String(v)),
        None => db.get(DIDS_WEBVH_SERVER).await?,
    };
    let value = layered
        .filter(|v| validate(v).is_ok())
        .and_then(|v| v.as_str().map(str::to_string))
        .or_else(|| {
            cfg.dids
                .webvh_server
                .clone()
                .filter(|s| validate(&Value::String(s.clone())).is_ok())
        });
    Ok(value)
}

/// The hosting server an identity of one kind is published on — `None` for
/// "this community serves it" — given the [`live`] choice and that kind's own
/// `config.toml` setting.
pub fn server_for(live: Option<&str>, own: Option<&str>) -> Option<String> {
    match live {
        Some(LOCAL) => None,
        Some(server) => Some(server.to_string()),
        None => own.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_runtime_choice_wins_and_local_means_served_here() {
        assert_eq!(server_for(None, None), None);
        assert_eq!(server_for(None, Some("hosting")), Some("hosting".into()));
        assert_eq!(server_for(Some(LOCAL), Some("hosting")), None);
        assert_eq!(
            server_for(Some("other"), Some("hosting")),
            Some("other".into())
        );
    }

    #[test]
    fn a_stated_presentation_takes_the_create_to_1_2() {
        let mut payload = json!({ "contextId": "c" });
        assert_eq!(
            with_presentation(&mut payload, (None, None)),
            vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_1
        );
        assert_eq!(payload, json!({ "contextId": "c" }));
        assert_eq!(
            with_presentation(
                &mut payload,
                (Some(vta_sdk::did_scid::DidMethod::Scid), Some(true))
            ),
            vta_sdk::trust_tasks::TASK_WEBVH_DIDS_CREATE_1_2
        );
        assert_eq!(
            payload,
            json!({ "contextId": "c", "didMethod": "scid", "scidAlsoKnownAs": true })
        );
        assert!(validate_did_method(&json!("webvh")).is_ok());
        assert!(validate_did_method(&json!("key")).is_err());
    }

    #[test]
    fn only_local_or_a_server_id_is_accepted() {
        assert!(validate(&json!("local")).is_ok());
        assert!(validate(&json!("hosting-eu.1")).is_ok());
        assert!(validate(&json!("")).is_err());
        assert!(validate(&json!("has space")).is_err());
        assert!(validate(&json!("x".repeat(129))).is_err());
        assert!(validate(&json!(7)).is_err());
    }
}
