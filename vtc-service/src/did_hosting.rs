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

/// `[dids]` in `config.toml`: the file layer of [`DIDS_WEBVH_SERVER`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DidsConfig {
    /// A `did:webvh` hosting server registered at the community's VTA, by its
    /// id there, or `"local"`. Absent: each kind's own setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webvh_server: Option<String>,
}

impl DidsConfig {
    pub fn is_empty(&self) -> bool {
        self.webvh_server.is_none()
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
    fn only_local_or_a_server_id_is_accepted() {
        assert!(validate(&json!("local")).is_ok());
        assert!(validate(&json!("hosting-eu.1")).is_ok());
        assert!(validate(&json!("")).is_err());
        assert!(validate(&json!("has space")).is_err());
        assert!(validate(&json!("x".repeat(129))).is_err());
        assert!(validate(&json!(7)).is_err());
    }
}
