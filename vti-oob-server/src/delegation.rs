//! Delegated signing (`auth/oob/grant/0.3`, consumer item 4): reading a
//! document `K_b` signs as its approver's.
//!
//! An approver who signs a grant carrying `signingScope` lets the browser's
//! sign-in key `K_b` sign documents of those task families as them, for a
//! bounded time. At `redeem` the host records the delegation, keyed by `K_b`
//! ([`record`]); a document `K_b` signs is then read as the approver's while
//! all of these hold ([`armed`]):
//!
//! 1. the task's slug is a family the scope lists, or lies under one, matched
//!    on whole segments ([`covers`]);
//! 2. the delegation has not passed its `notAfter`;
//! 3. whatever else the host binds it to is live ([`DelegationLiveness`]) —
//!    for the VTC, the member session `redeem` created; for a host with no
//!    sessions, nothing ([`AlwaysLive`]);
//! 4. the task is not excluded (item 6): nothing under `auth`, `acl`,
//!    `consent`, `task-consent` or `confirm`, whatever the scope says
//!    ([`EXCLUDED_FAMILIES`]).
//!
//! The delegation confers no standing of its own: every caller still reads
//! the approver's standing at execution time, and audits what it accepts
//! (item 7) — that is the host's.
//!
//! The row is the host's type ([`DelegatedKey`]), so a host's existing rows
//! keep their shape. [`Delegation`] is the plain one, for a host with nothing
//! more to record.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use vti_common::auth::session::now_epoch;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// The keyspace key of the delegation `start_key` holds.
pub fn delegation_key(start_key: &str) -> Vec<u8> {
    format!("delegation:{start_key}").into_bytes()
}

/// Families a delegated key never signs for (grant 0.2 consumer item 6 and
/// wallet item 5): authentication, access control and consent.
pub const EXCLUDED_FAMILIES: &[&str] = &["auth", "acl", "consent", "task-consent", "confirm"];

/// `https://trusttasks.org/spec/vtc/directory/card/update/0.1` → `vtc/directory/card/update`.
fn slug_of(type_uri: &str) -> Option<&str> {
    let path = type_uri.split('#').next()?;
    let path = path.split_once("/spec/")?.1;
    Some(path.rsplit_once('/')?.0)
}

fn under(slug: &str, family: &str) -> bool {
    slug == family || slug.starts_with(&format!("{family}/"))
}

/// Whether `scope` lets the key sign `type_uri`, exclusions applied.
pub fn covers(scope: &[String], type_uri: &str) -> bool {
    let Some(slug) = slug_of(type_uri) else {
        return false;
    };
    !EXCLUDED_FAMILIES.iter().any(|f| under(slug, f)) && scope.iter().any(|f| under(slug, f))
}

/// A stored delegation, in the host's own shape.
pub trait DelegatedKey: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The DID the key signs as.
    fn approver(&self) -> &str;
    /// The families the approver signed, as slug prefixes.
    fn scope(&self) -> &[String];
    /// The end of the delegation, epoch seconds.
    fn not_after(&self) -> u64;
}

/// The plain delegation: who, which families, until when, under which grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delegation {
    /// The DID the key signs as.
    pub approver_did: String,
    /// The families the approver signed, as slug prefixes.
    pub scope: Vec<String>,
    /// The grant's `sessionEndsAt` (or earlier), epoch seconds.
    pub not_after: u64,
    /// The grant's `id`: the authority each delegated document is audited
    /// under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

impl DelegatedKey for Delegation {
    fn approver(&self) -> &str {
        &self.approver_did
    }
    fn scope(&self) -> &[String] {
        &self.scope
    }
    fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// Whether what a delegation is bound to still stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// It stands: the key signs as its approver.
    Live,
    /// Not now, but it may again: the key signs as no one, and the row stays.
    Paused,
    /// Gone for good: the row is dropped.
    Gone,
}

/// What a host binds a delegation to beyond its `notAfter`.
#[async_trait::async_trait]
pub trait DelegationLiveness<D: DelegatedKey>: Send + Sync {
    /// Whether `delegation`, held by `signer`, still stands.
    async fn liveness(&self, signer: &str, delegation: &D) -> Result<Liveness, AppError>;
}

/// Bound to nothing but its `notAfter`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysLive;

#[async_trait::async_trait]
impl<D: DelegatedKey> DelegationLiveness<D> for AlwaysLive {
    async fn liveness(&self, _: &str, _: &D) -> Result<Liveness, AppError> {
        Ok(Liveness::Live)
    }
}

/// Arm the delegation `redeem` just issued for `start_key`.
pub async fn record<D: DelegatedKey>(
    ks: &KeyspaceHandle,
    start_key: &str,
    delegation: &D,
) -> Result<(), AppError> {
    ks.insert(delegation_key(start_key), delegation).await
}

/// The live delegation `signer` holds for `type_uri`, if any. `None` exactly
/// as for a key the service does not know (item 4). A delegation past its
/// `notAfter`, or whose binding is [`Liveness::Gone`], is disarmed for good.
pub async fn armed<D: DelegatedKey, L: DelegationLiveness<D> + ?Sized>(
    ks: &KeyspaceHandle,
    signer: &str,
    type_uri: &str,
    liveness: &L,
) -> Result<Option<D>, AppError> {
    let Some(d): Option<D> = ks.get(delegation_key(signer)).await? else {
        return Ok(None);
    };
    let now = now_epoch();
    let live = liveness.liveness(signer, &d).await?;
    if live != Liveness::Live || d.not_after() <= now {
        // Disarmed for good once its binding has gone.
        if live == Liveness::Gone || d.not_after() <= now {
            ks.remove(delegation_key(signer)).await?;
        }
        return Ok(None);
    }
    Ok(covers(d.scope(), type_uri).then_some(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "https://trusttasks.org/spec";

    #[test]
    fn a_scope_covers_whole_segments_only() {
        let scope = vec!["vtc/directory".to_string()];
        assert!(covers(
            &scope,
            &format!("{S}/vtc/directory/card/update/0.1")
        ));
        assert!(covers(&scope, &format!("{S}/vtc/directory/query/0.1")));
        assert!(!covers(
            &scope,
            &format!("{S}/vtc/directoryx/card/update/0.1")
        ));
        assert!(!covers(&scope, &format!("{S}/vtc/groups/join/0.1")));
    }

    #[test]
    fn exclusions_hold_whatever_the_scope_says() {
        let scope = vec![
            "auth".to_string(),
            "acl".to_string(),
            "task-consent".to_string(),
        ];
        assert!(!covers(&scope, &format!("{S}/auth/oob/grant/0.3")));
        assert!(!covers(&scope, &format!("{S}/acl/grant/0.2")));
        assert!(!covers(&scope, &format!("{S}/task-consent/decision/0.2")));
    }

    struct Fixed(Liveness);

    #[async_trait::async_trait]
    impl DelegationLiveness<Delegation> for Fixed {
        async fn liveness(&self, _: &str, _: &Delegation) -> Result<Liveness, AppError> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn a_delegation_is_armed_while_live_and_dropped_once_gone() {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("delegations").unwrap();
        let groups = format!("{S}/vtn/groups/register/0.1");
        let d = Delegation {
            approver_did: "did:webvh:x:alice.example".into(),
            scope: vec!["vtn/groups".into()],
            not_after: now_epoch() + 60,
            grant_id: Some("urn:uuid:g".into()),
        };
        record(&ks, "did:key:z6MkKb", &d).await.unwrap();
        assert_eq!(
            armed::<Delegation, _>(&ks, "did:key:z6MkKb", &groups, &AlwaysLive)
                .await
                .unwrap(),
            Some(d.clone())
        );
        // Out of scope, and an excluded family: no one.
        let auth = format!("{S}/auth/oob/redeem/0.2");
        assert_eq!(
            armed::<Delegation, _>(&ks, "did:key:z6MkKb", &auth, &AlwaysLive)
                .await
                .unwrap(),
            None
        );
        // Paused: no one, and the row stays.
        assert_eq!(
            armed(&ks, "did:key:z6MkKb", &groups, &Fixed(Liveness::Paused))
                .await
                .unwrap(),
            None
        );
        assert!(
            armed::<Delegation, _>(&ks, "did:key:z6MkKb", &groups, &AlwaysLive)
                .await
                .unwrap()
                .is_some()
        );
        // Gone: dropped for good.
        assert_eq!(
            armed(&ks, "did:key:z6MkKb", &groups, &Fixed(Liveness::Gone))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            armed::<Delegation, _>(&ks, "did:key:z6MkKb", &groups, &AlwaysLive)
                .await
                .unwrap(),
            None
        );
        // Past its end: dropped, whatever the binding says.
        let ended = Delegation {
            not_after: now_epoch() - 1,
            ..d
        };
        record(&ks, "did:key:z6MkKc", &ended).await.unwrap();
        assert_eq!(
            armed::<Delegation, _>(&ks, "did:key:z6MkKc", &groups, &AlwaysLive)
                .await
                .unwrap(),
            None
        );
        assert!(
            ks.get::<Delegation>(delegation_key("did:key:z6MkKc"))
                .await
                .unwrap()
                .is_none()
        );
    }
}
