//! Console signing keys — a *delegation*, not an identity.
//!
//! The admin console cannot author a signed Trust Task document, which is why
//! every bearer route the #1641 migration would retire has had to stay
//! ([#1684](https://github.com/OpenVTC/verifiable-trust-infrastructure/issues/1684)).
//! `docs/05-design-notes/vtc-console-signing.md` §5A is the design this
//! implements: the browser generates a **non-extractable** Ed25519 key, derives
//! a `did:key` from its public half, and the VTC records one sentence about it —
//!
//! > console key `K` may act as admin DID `D`
//!
//! — and nothing else. The record is a *credential of `D`*, exactly the way a
//! registered passkey is ([`super::admin::RegisteredPasskey`]), enrolled by `D`
//! behind the step-up the console already runs, listed beside the passkeys, and
//! individually revocable.
//!
//! ## What a delegation confers: nothing
//!
//! This is the whole security argument and it is worth stating before the code.
//! A [`ConsoleKeyDelegation`] carries **no role, no scopes and no
//! capabilities**. It names an identity that already holds whatever it holds,
//! and it can never reach further than that identity's own ACL row — which is
//! read fresh, from the ACL keyspace, on every document
//! ([`resolve_delegated_admin`]). So:
//!
//! - It is not self-promotion. `Invariant::SelfPromotion` (VTI-OPS-050, #1658)
//!   is about *conferring a role*; a delegation confers none, and the console
//!   key never appears in `acl list`. That is precisely why the console key
//!   does **not** get its own ACL row — see §5F of the design note for the
//!   option that does, and why an XSS that wins a step-up window would be able
//!   to leave a durable admin row behind under it.
//! - It does not reinstate the session as an authority chain. #1681's stated
//!   property — `admin_signer` never consults `sessions_ks` — survives, because
//!   the delegation resolves to a DID and the DID resolves to an ACL row.
//! - Removing, demoting or expiring the delegating admin's ACL row kills every
//!   key delegated from it, at once, with no extra bookkeeping.
//!
//! ## Two refusals worth reading before changing anything
//!
//! 1. **A console DID that already holds an ACL row cannot be enrolled**
//!    ([`EnrolError::SubjectHoldsAclRow`]). Without it an admin could name
//!    *another admin's* DID as their "console key": the record would be inert
//!    while that DID's own row answered for it, and would silently start
//!    acting-as the delegator the moment the row was demoted or removed —
//!    turning a de-escalation into a hand-over.
//! 2. **A signer that holds an ACL row is answered by that row, full stop** —
//!    including when the row refuses. [`resolve_delegated_admin`] is consulted
//!    only for a signer with *no* row at all. The design note's sketch falls
//!    through on `Forbidden` as well; this is deliberately tighter, and the
//!    reason is the same as (1): a row that has been demoted or expired must
//!    not be routed around by a delegation enrolled while it was live. The
//!    authority is the row.
//!
//! ## Storage
//!
//! One row per console DID in the [`CONSOLE_KEYS`](crate::store::keyspaces)
//! keyspace, keyed `console_key:<consoleDid>`, because the hot-path lookup is
//! *by console DID* — the signer of a document is what we hold, and the admin
//! it acts for is what we want. The keyspace is **excluded from backup**: a
//! restored VTC must not resurrect signing authority for a browser profile that
//! may no longer exist, on a machine that may no longer be the operator's.
//!
//! A revocation leaves a **tombstone** rather than deleting the row, so that a
//! burned key can never be re-enrolled by mistake and the list can say why a
//! browser stopped working.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// The stored delegation: "this console key may act as this admin DID".
///
/// Field names are the on-disk format. `camelCase` because every VTC wire and
/// storage shape is (R3.1), and because the list endpoint serves this type's
/// projection straight to the console.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConsoleKeyDelegation {
    /// The console key's own `did:key` — an Ed25519 multikey, the DID the
    /// browser derives from the public half of its non-extractable keypair.
    /// This is the document `issuer` and the DID the proof's
    /// `verificationMethod` names, so it is what a signed document presents.
    pub console_did: String,
    /// The admin DID this key acts as. **Always the enrolling caller's own
    /// DID** — never a request field; see
    /// [`enrol`](crate::routes::admin::console_keys::enrol).
    pub admin_did: String,
    /// Operator-supplied, e.g. `"Work laptop — Chrome"`. Absent rather than
    /// empty when nobody chose one: an invented label is indistinguishable
    /// from a chosen one to somebody deciding which key to revoke — the same
    /// rule `auth/passkey/list/0.1` states for `deviceLabel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Optional finite lifetime. `None` — the default — means the delegation
    /// lasts until it is revoked or the browser profile is cleared, which is
    /// the decision taken on #1684. An expired delegation refuses on the
    /// verification path; it is not swept, because a row nobody can use costs
    /// a few hundred bytes and revocation is the lever operators actually
    /// reach for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Stamped by [`touch_last_used`] when the delegation authorizes a
    /// document. Best-effort: a failed write never fails the request, because
    /// this is a usability signal ("which of these browsers is still in use")
    /// and not a security one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// The tombstone. `Some` means revoked, and a revoked row authorizes
    /// nothing and cannot be re-enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Who revoked it — the owner, or a super-admin doing incident response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
}

impl ConsoleKeyDelegation {
    /// Live *right now*: not revoked, and not past its expiry.
    ///
    /// Takes the instant rather than reading the clock so a test can pin it.
    #[must_use]
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|exp| exp > now)
    }
}

const PREFIX: &[u8] = b"console_key:";

fn key(console_did: &str) -> Vec<u8> {
    let mut k = PREFIX.to_vec();
    k.extend_from_slice(console_did.as_bytes());
    k
}

/// Read one delegation by console DID. `Ok(None)` if never enrolled.
pub async fn get_delegation(
    ks: &KeyspaceHandle,
    console_did: &str,
) -> Result<Option<ConsoleKeyDelegation>, AppError> {
    ks.get(key(console_did)).await
}

/// Create or overwrite a delegation row.
pub async fn store_delegation(
    ks: &KeyspaceHandle,
    delegation: &ConsoleKeyDelegation,
) -> Result<(), AppError> {
    ks.insert(key(&delegation.console_did), delegation).await
}

/// Every delegation enrolled by `admin_did`, newest first, tombstones included
/// — the list an operator uses to decide which browser to disown.
pub async fn list_delegations_for_admin(
    ks: &KeyspaceHandle,
    admin_did: &str,
) -> Result<Vec<ConsoleKeyDelegation>, AppError> {
    let raw = ks.prefix_iter_raw(PREFIX.to_vec()).await?;
    let mut out: Vec<ConsoleKeyDelegation> = Vec::new();
    for (_k, v) in raw {
        match serde_json::from_slice::<ConsoleKeyDelegation>(&v) {
            Ok(d) if d.admin_did == admin_did => out.push(d),
            Ok(_) => {}
            // A row this build cannot parse is one it must not authorize
            // either, and `resolve_delegated_admin` refuses it for the same
            // reason. Warn rather than fail the whole listing: one unreadable
            // row should not hide the others an operator is trying to revoke.
            Err(err) => tracing::warn!(error = %err, "skipping unparseable console-key row"),
        }
    }
    out.sort_by_key(|d| std::cmp::Reverse(d.created_at));
    Ok(out)
}

/// Why an enrolment was refused. Each variant is a rule the module header
/// explains; the route maps them onto status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolError {
    /// The console DID is not a `did:key`. A delegation exists so the console
    /// can sign without network resolution — `TrustTaskVmResolver` resolves
    /// `did:key` locally — and a DID whose document can be *rewritten* is a
    /// key the enroller did not enrol.
    NotADidKey,
    /// `consoleDid == adminDid`. A self-delegation is a loop that says nothing:
    /// the signer already has the row.
    SelfDelegation,
    /// The console DID already holds an ACL row of its own. Refusal (1) in the
    /// module header — this is what stops "delegate my authority to that other
    /// admin, to take effect when they are demoted".
    SubjectHoldsAclRow,
    /// Already delegated — to this admin or another one. Re-pointing a console
    /// key at a different admin is not an edit, it is a hand-over, and it would
    /// let a second admin claim a key the first enrolled. Revoke and re-enrol.
    AlreadyDelegated,
    /// Already delegated *and revoked*. A burned key is not re-usable.
    Revoked,
}

impl EnrolError {
    /// The operator-facing refusal, typed so the route need not restate it.
    #[must_use]
    pub fn into_app_error(self, console_did: &str) -> AppError {
        match self {
            Self::NotADidKey => AppError::Validation(format!(
                "consoleDid must be a did:key (the console derives it from its own \
                 non-extractable Ed25519 key); got {console_did}"
            )),
            Self::SelfDelegation => AppError::Validation(
                "consoleDid must not be your own admin DID — a delegation names a \
                 *separate* key that may act as it"
                    .into(),
            ),
            Self::SubjectHoldsAclRow => AppError::Conflict(format!(
                "{console_did} already holds an ACL row of its own, so it is an identity \
                 rather than a console key; delegating to it would take effect only once \
                 that row was removed"
            )),
            Self::AlreadyDelegated => AppError::Conflict(format!(
                "{console_did} is already enrolled as a console key; revoke it before \
                 enrolling it again"
            )),
            Self::Revoked => AppError::Conflict(format!(
                "{console_did} was revoked and cannot be re-enrolled; generate a new \
                 console key in the browser"
            )),
        }
    }
}

/// Check every enrolment rule and, if they all hold, write the delegation.
///
/// `admin_did` is the **caller's own** DID. The caller cannot name it, so
/// "enrol a delegation for somebody else" is not a request this surface can
/// express — see the route for why that is the opposite of the promotion rule
/// and still correct.
pub async fn enrol_delegation(
    console_keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    console_did: &str,
    admin_did: &str,
    label: Option<String>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<ConsoleKeyDelegation, AppError> {
    if !console_did.starts_with("did:key:") {
        return Err(EnrolError::NotADidKey.into_app_error(console_did));
    }
    if console_did == admin_did {
        return Err(EnrolError::SelfDelegation.into_app_error(console_did));
    }
    if let Some(existing) = get_delegation(console_keys_ks, console_did).await? {
        return Err(if existing.revoked_at.is_some() {
            EnrolError::Revoked.into_app_error(console_did)
        } else {
            EnrolError::AlreadyDelegated.into_app_error(console_did)
        });
    }
    if crate::acl::get_acl_entry(acl_ks, console_did)
        .await?
        .is_some()
    {
        return Err(EnrolError::SubjectHoldsAclRow.into_app_error(console_did));
    }

    let delegation = ConsoleKeyDelegation {
        console_did: console_did.to_string(),
        admin_did: admin_did.to_string(),
        label: label.filter(|l| !l.trim().is_empty()),
        created_at: Utc::now(),
        expires_at,
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
    };
    store_delegation(console_keys_ks, &delegation).await?;
    Ok(delegation)
}

/// Mark a delegation revoked. Idempotent on an already-revoked row: the caller
/// wanted it gone and it is gone, so answering 404 would be a lie.
///
/// Returns the tombstoned row, or `Ok(None)` when no such delegation exists.
pub async fn revoke_delegation(
    ks: &KeyspaceHandle,
    console_did: &str,
    revoked_by: &str,
) -> Result<Option<ConsoleKeyDelegation>, AppError> {
    let Some(mut delegation) = get_delegation(ks, console_did).await? else {
        return Ok(None);
    };
    if delegation.revoked_at.is_none() {
        delegation.revoked_at = Some(Utc::now());
        delegation.revoked_by = Some(revoked_by.to_string());
        store_delegation(ks, &delegation).await?;
    }
    Ok(Some(delegation))
}

/// The admin DID a signed document's signer may act as, or `None`.
///
/// **This is the whole verification-side surface.** It answers only "which DID
/// does this key stand in for"; the caller then resolves *that* DID's ACL row,
/// at execution time, exactly as it does for a signer who signed with their own
/// key. A revoked delegation, an expired one, an unknown signer and an
/// unreadable row all answer `None`, and `None` means the caller refuses.
pub async fn resolve_delegated_admin(
    ks: &KeyspaceHandle,
    signer_did: &str,
) -> Result<Option<ConsoleKeyDelegation>, AppError> {
    Ok(get_delegation(ks, signer_did)
        .await?
        .filter(|d| d.is_active_at(Utc::now())))
}

/// Stamp `last_used_at`. Best-effort by contract: errors are logged, never
/// returned, because a storage hiccup must not turn an authorized operation
/// into a refusal.
pub async fn touch_last_used(ks: &KeyspaceHandle, delegation: &ConsoleKeyDelegation) {
    let mut updated = delegation.clone();
    updated.last_used_at = Some(Utc::now());
    if let Err(err) = store_delegation(ks, &updated).await {
        tracing::warn!(
            console_did = %delegation.console_did,
            error = %err,
            "could not stamp console-key last-used"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{VtcAclEntry, VtcRole, store_acl_entry};
    use chrono::Duration;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const CONSOLE: &str = "did:key:z6MkConsoleBrowserOne";
    const ADMIN: &str = "did:key:z6MkAdminOperator";

    fn temp_store() -> (KeyspaceHandle, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = StoreConfig {
            data_dir: dir.path().to_path_buf(),
        };
        let store = Store::open(&cfg).expect("store");
        let console = store.keyspace("console-keys-test").expect("ks");
        let acl = store.keyspace("console-keys-acl-test").expect("ks");
        (console, acl, dir)
    }

    async fn seed_acl(acl: &KeyspaceHandle, did: &str, role: VtcRole) {
        store_acl_entry(
            acl,
            &VtcAclEntry {
                did: did.into(),
                role,
                label: None,
                allowed_contexts: vec![],
                created_at: 0,
                created_by: "did:key:vtc-install".into(),
                updated_at: None,
                updated_by: None,
                expires_at: None,
            },
        )
        .await
        .expect("seed ACL row");
    }

    #[tokio::test]
    async fn a_delegation_round_trips_and_resolves() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;

        let d = enrol_delegation(
            &console_ks,
            &acl_ks,
            CONSOLE,
            ADMIN,
            Some("Work laptop".into()),
            None,
        )
        .await
        .expect("enrol");
        assert_eq!(d.admin_did, ADMIN);
        assert_eq!(d.label.as_deref(), Some("Work laptop"));

        let resolved = resolve_delegated_admin(&console_ks, CONSOLE)
            .await
            .expect("resolve")
            .expect("active");
        assert_eq!(resolved.admin_did, ADMIN);
    }

    /// The property the whole design rests on: a delegation is a *credential*,
    /// so it must never outlive its own revocation by even one request.
    #[tokio::test]
    async fn a_revoked_delegation_stops_resolving_immediately() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        enrol_delegation(&console_ks, &acl_ks, CONSOLE, ADMIN, None, None)
            .await
            .expect("enrol");

        revoke_delegation(&console_ks, CONSOLE, ADMIN)
            .await
            .expect("revoke")
            .expect("existed");

        assert!(
            resolve_delegated_admin(&console_ks, CONSOLE)
                .await
                .expect("resolve")
                .is_none(),
            "a revoked delegation must resolve to nothing"
        );
    }

    #[tokio::test]
    async fn an_expired_delegation_stops_resolving() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        enrol_delegation(
            &console_ks,
            &acl_ks,
            CONSOLE,
            ADMIN,
            None,
            Some(Utc::now() - Duration::seconds(1)),
        )
        .await
        .expect("enrol");

        assert!(
            resolve_delegated_admin(&console_ks, CONSOLE)
                .await
                .expect("resolve")
                .is_none()
        );
    }

    /// Refusal (1). Delegating to a DID that has its own ACL row would be inert
    /// until that row went away and would then hand over the delegator's
    /// authority — a demotion that silently promotes.
    #[tokio::test]
    async fn a_did_with_its_own_acl_row_cannot_be_enrolled() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        let other_admin = "did:key:z6MkAnotherAdmin";
        seed_acl(&acl_ks, other_admin, VtcRole::Admin).await;

        let err = enrol_delegation(&console_ks, &acl_ks, other_admin, ADMIN, None, None)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_second_admin_cannot_repoint_an_enrolled_console_key() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        let rival = "did:key:z6MkRivalAdmin";
        seed_acl(&acl_ks, rival, VtcRole::Admin).await;
        enrol_delegation(&console_ks, &acl_ks, CONSOLE, ADMIN, None, None)
            .await
            .expect("enrol");

        let err = enrol_delegation(&console_ks, &acl_ks, CONSOLE, rival, None, None)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
        assert_eq!(
            get_delegation(&console_ks, CONSOLE)
                .await
                .expect("read")
                .expect("present")
                .admin_did,
            ADMIN,
            "the first enrolment stands"
        );
    }

    #[tokio::test]
    async fn a_revoked_console_key_cannot_be_re_enrolled() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        enrol_delegation(&console_ks, &acl_ks, CONSOLE, ADMIN, None, None)
            .await
            .expect("enrol");
        revoke_delegation(&console_ks, CONSOLE, ADMIN)
            .await
            .expect("revoke");

        let err = enrol_delegation(&console_ks, &acl_ks, CONSOLE, ADMIN, None, None)
            .await
            .expect_err("must refuse");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_non_did_key_and_a_self_delegation_are_refused() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;

        assert!(matches!(
            enrol_delegation(
                &console_ks,
                &acl_ks,
                "did:web:console.example.com",
                ADMIN,
                None,
                None
            )
            .await
            .expect_err("must refuse"),
            AppError::Validation(_)
        ));
        assert!(matches!(
            enrol_delegation(&console_ks, &acl_ks, ADMIN, ADMIN, None, None)
                .await
                .expect_err("must refuse"),
            AppError::Validation(_)
        ));
    }

    #[tokio::test]
    async fn listing_is_scoped_to_the_enrolling_admin() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        let other = "did:key:z6MkOtherOperator";
        seed_acl(&acl_ks, other, VtcRole::Admin).await;

        enrol_delegation(&console_ks, &acl_ks, CONSOLE, ADMIN, None, None)
            .await
            .expect("enrol");
        enrol_delegation(
            &console_ks,
            &acl_ks,
            "did:key:z6MkTheirBrowser",
            other,
            None,
            None,
        )
        .await
        .expect("enrol");

        let mine = list_delegations_for_admin(&console_ks, ADMIN)
            .await
            .expect("list");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].console_did, CONSOLE);
    }

    #[tokio::test]
    async fn revoking_is_idempotent_and_keeps_the_first_revoker() {
        let (console_ks, acl_ks, _dir) = temp_store();
        seed_acl(&acl_ks, ADMIN, VtcRole::Admin).await;
        enrol_delegation(&console_ks, &acl_ks, CONSOLE, ADMIN, None, None)
            .await
            .expect("enrol");

        let first = revoke_delegation(&console_ks, CONSOLE, ADMIN)
            .await
            .expect("revoke")
            .expect("existed");
        let second = revoke_delegation(&console_ks, CONSOLE, "did:key:z6MkSomeoneElse")
            .await
            .expect("revoke again")
            .expect("existed");
        assert_eq!(first.revoked_at, second.revoked_at);
        assert_eq!(second.revoked_by.as_deref(), Some(ADMIN));
    }

    #[tokio::test]
    async fn an_unknown_signer_resolves_to_nothing() {
        let (console_ks, _acl_ks, _dir) = temp_store();
        assert!(
            resolve_delegated_admin(&console_ks, "did:key:z6MkNeverSeen")
                .await
                .expect("resolve")
                .is_none()
        );
    }
}
