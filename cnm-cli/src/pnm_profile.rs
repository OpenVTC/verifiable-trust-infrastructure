//! Reading a `pnm` profile on this machine — read-only — so `cnm setup` can
//! offer to bootstrap its personal-VTA identity from an operator's existing
//! `pnm` session instead of a second out-of-band grant.
//!
//! Nothing here writes to `pnm`'s config or session store. In particular the
//! `pnm` session is never handed to a [`vta_sdk::session::SessionStore`] that
//! could cache a token into it or rotate it: the shortcut authenticates with
//! the session's key in memory, once, to create an ACL entry for a *different*
//! key that `cnm` minted itself. `pnm`'s private key is never written anywhere
//! by `cnm`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use vta_sdk::session::{SessionInfo, SessionStore};

/// The part of `pnm`'s `config.toml` this reads. Deliberately not `pnm-cli`'s
/// own type: `pnm`'s loader migrates legacy configs and saves them, and a read
/// from `cnm` must never rewrite `pnm`'s file.
#[derive(Debug, Default, Deserialize)]
struct PnmConfigView {
    #[serde(default)]
    vtas: BTreeMap<String, PnmVtaView>,
}

#[derive(Debug, Deserialize)]
struct PnmVtaView {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    vta_did: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// A `pnm` profile entry that administers the VTA `cnm` is being set up for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnmMatch {
    /// `pnm`'s slug for the VTA (`pnm --vta <slug>`).
    pub slug: String,
    pub name: String,
    /// The explicit REST URL `pnm` holds for a VTA whose DID cannot advertise
    /// one (`did:key`), if any.
    pub url: Option<String>,
}

/// The `pnm` profile entries bound to `vta_did`, read from `config_toml`.
///
/// A pending `pnm` setup (no VTA DID yet) never matches: it has no grant to
/// lend.
pub fn matches_in(config_toml: &str, vta_did: &str) -> Vec<PnmMatch> {
    let Ok(view) = toml::from_str::<PnmConfigView>(config_toml) else {
        return Vec::new();
    };
    view.vtas
        .into_iter()
        .filter(|(_, v)| v.vta_did.as_deref().map(str::trim) == Some(vta_did.trim()))
        .map(|(slug, v)| PnmMatch {
            name: v.name.unwrap_or_else(|| slug.clone()),
            slug,
            url: v.url,
        })
        .collect()
}

/// The `pnm` profile entries on this machine bound to `vta_did`.
///
/// `$PNM_HOME` is honoured, as `pnm` honours it. A missing or unreadable
/// profile is simply "none" — this is an offer, not a requirement.
pub fn find(vta_did: &str) -> Vec<PnmMatch> {
    let Ok(dir) = vta_sdk::agent_connect::pnm_profile_dir() else {
        return Vec::new();
    };
    find_in(&dir, vta_did)
}

fn find_in(dir: &Path, vta_did: &str) -> Vec<PnmMatch> {
    match std::fs::read_to_string(dir.join("config.toml")) {
        Ok(s) => matches_in(&s, vta_did),
        Err(_) => Vec::new(),
    }
}

/// `pnm`'s session store — the same service name and directory `pnm` uses, so
/// a `PNM_HOME` profile reads its own keyring entries. Only ever read.
pub fn store() -> Option<SessionStore> {
    let dir = vta_sdk::agent_connect::pnm_profile_dir().ok()?;
    Some(SessionStore::new(
        &vta_sdk::agent_connect::pnm_service_name(),
        dir,
    ))
}

/// The `pnm` session for `slug`, if it is bound to `vta_did`.
///
/// A session still waiting for its VTA DID, or bound to another VTA, is not
/// returned: its key holds no grant on this one.
pub fn session_for(store: &SessionStore, slug: &str, vta_did: &str) -> Option<SessionInfo> {
    let info = store.loaded_session(&vta_sdk::agent_connect::pnm_session_key(slug))?;
    (info.vta_did.as_deref() == Some(vta_did)).then_some(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::session::testing::InMemorySessionBackend;

    const PNM_TOML: &str = r#"
default_vta = "home"

[vtas.home]
name = "Home VTA"
vta_did = "did:webvh:QmHome:vta.example.com"

[vtas.work]
name = "Work VTA"
vta_did = "did:webvh:QmWork:work.example.com"

[vtas.pending]
name = "Not yet"

[vtas.local]
name = "Local"
vta_did = "did:key:z6MkLocal"
url = "http://localhost:7001"
"#;

    #[test]
    fn a_pnm_profile_for_the_same_vta_is_found() {
        let found = matches_in(PNM_TOML, "did:webvh:QmHome:vta.example.com");
        assert_eq!(
            found,
            vec![PnmMatch {
                slug: "home".into(),
                name: "Home VTA".into(),
                url: None,
            }]
        );
    }

    #[test]
    fn another_vta_or_a_pending_pnm_setup_is_not_offered() {
        assert!(matches_in(PNM_TOML, "did:webvh:QmOther:x.example.com").is_empty());
        // `pending` has no VTA DID and so no grant to lend.
        assert!(matches_in(PNM_TOML, "").is_empty());
    }

    #[test]
    fn the_explicit_url_pnm_holds_for_a_did_key_vta_is_kept() {
        let found = matches_in(PNM_TOML, "did:key:z6MkLocal");
        assert_eq!(found[0].url.as_deref(), Some("http://localhost:7001"));
    }

    #[test]
    fn an_unparseable_or_missing_profile_is_none() {
        assert!(matches_in("this is [not toml", "did:key:z").is_empty());
        let dir = tempfile::tempdir().unwrap();
        assert!(find_in(dir.path(), "did:key:z").is_empty());
        std::fs::write(dir.path().join("config.toml"), PNM_TOML).unwrap();
        assert_eq!(
            find_in(dir.path(), "did:webvh:QmWork:work.example.com")[0].slug,
            "work"
        );
    }

    #[test]
    fn only_a_session_bound_to_the_same_vta_is_lent() {
        let store = SessionStore::with_backend(Box::new(InMemorySessionBackend::new()));
        store
            .store_direct("vta:home", "did:key:z6MkPnm", "zKey", "did:webvh:QmHome")
            .unwrap();
        store
            .store_pending_vta_binding("vta:pending", "did:key:z6MkTemp", "zKey")
            .unwrap();
        assert_eq!(
            session_for(&store, "home", "did:webvh:QmHome")
                .unwrap()
                .client_did,
            "did:key:z6MkPnm"
        );
        assert!(session_for(&store, "home", "did:webvh:QmOther").is_none());
        assert!(session_for(&store, "pending", "did:webvh:QmHome").is_none());
        assert!(session_for(&store, "absent", "did:webvh:QmHome").is_none());
    }
}
