//! Key custody gates for the operations layer.
//!
//! **The rules live in [`vta_keys::custody`]. Read its module documentation
//! first.** This module applies them where the VTA has what the pure checks
//! lack: the caller's claims, the context store, and the audit sink. Every
//! refusal here is:
//!
//! - **audited** (VTI-AUD-003: refusals as well as successes), as
//!   `key.custody_violation` or `authority.instance_required`, with the reason
//!   in `detail`;
//! - **logged at `error!` with `security_alert = true`**, so a pipeline can
//!   route it without matching on message text. A refusal here is never a
//!   routine mistake: an honest client does not choose a foreign derivation
//!   path, and the CLI never sends a scoped admin to a seed operation.
//!
//! Any operation that loads the seed, derives a key or chooses a path on a
//! network caller's behalf goes through one of these functions. The
//! `key_custody_census` test pins the raw call sites that do not.

use tracing::error;

use vti_common::store::KeyspaceHandle;

use crate::audit;
use crate::auth::AuthClaims;
use crate::contexts::{get_context, list_contexts};
use crate::error::AppError;
use crate::keys::KeyRecord;
use crate::keys::custody::{self, CustodyViolation, RecordKey};
use crate::keys::seed_store::SeedStore;
use vta_sdk::keys::KeyOrigin;

/// Audit action for a refused derivation or path.
pub const CUSTODY_VIOLATION_ACTION: &str = "key.custody_violation";
/// Audit action for a caller refused an instance-wide operation.
pub const INSTANCE_AUTHORITY_ACTION: &str = "authority.instance_required";

/// Require unrestricted act authority (a super-admin, VTI-ACL-022) for an
/// instance-wide operation, auditing a refusal.
///
/// Use this in the **operation**, not only at a transport. The operation is
/// what every transport (REST, Trust Task, DIDComm) shares. A gate that lives
/// only on routes is how `keys/seeds` stayed open on DIDComm, and how a
/// transport-level refusal went unaudited.
///
/// `action` is the operation's own audit action (e.g. `seed.rotate`); it is
/// recorded as the refused resource so the audit row says what was attempted.
pub async fn require_instance_authority(
    auth: &AuthClaims,
    action: &str,
    audit_sink: &vta_audit::SharedAuditSink,
    channel: &str,
) -> Result<(), AppError> {
    if auth.is_super_admin() {
        return Ok(());
    }
    error!(
        audit = true,
        security_alert = true,
        did = %auth.did,
        role = %auth.role,
        action,
        channel,
        "instance-wide operation refused: caller is not a super-admin",
    );
    audit::record_with_detail_best_effort(
        audit_sink,
        INSTANCE_AUTHORITY_ACTION,
        &auth.did,
        Some(action),
        "denied",
        Some(channel),
        None,
        Some("requires unrestricted act authority (super-admin)"),
    )
    .await;
    Err(AppError::Forbidden(format!(
        "`{action}` is an instance-wide operation and requires a super-admin \
         (an admin ACL entry with unrestricted context scope). A context-scoped \
         admin cannot perform it"
    )))
}

/// Derive the key a stored record names, through the custody check (rule 6).
///
/// The **only** way network-reachable code should obtain derived key material
/// for a [`KeyRecord`]. The caller must already have authorized `actor` for
/// the record (its context, or super-admin for a context-less record). This
/// adds the check that the record's path really belongs to that context, so a
/// record carrying a foreign path cannot be used or exported. `actor` is used
/// only for the audit row of a refusal.
#[allow(clippy::too_many_arguments)]
pub async fn derive_record_key(
    contexts_ks: &KeyspaceHandle,
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit_sink: &vta_audit::SharedAuditSink,
    actor: &str,
    record: &KeyRecord,
    channel: &str,
) -> Result<RecordKey, AppError> {
    let base = match record.context_id.as_deref() {
        Some(ctx) => get_context(contexts_ks, ctx).await?.map(|c| c.base_path),
        None => None,
    };
    let authorized = match custody::authorize_record_derivation(record, base.as_deref()) {
        Ok(a) => a,
        Err(v) => {
            report(
                audit_sink,
                actor,
                &v,
                Some(&record.key_id),
                record.context_id.as_deref(),
                channel,
            )
            .await;
            return Err(v.into());
        }
    };
    authorized.load(keys_ks, seed_store).await
}

/// Rule 7: require that `key_id`, referenced from a resource in
/// `scope_context`, is a key in that context's subtree. Audits a refusal.
///
/// Call this **before** loading a key under `InternalAuthority` whenever the key
/// id came from data a caller wrote (a vault entry's `signingKeyId`). A
/// missing key is `NotFound`, not a violation. Nothing was attempted against
/// a key that does not exist.
pub async fn require_referenced_key_in_scope(
    keys_ks: &KeyspaceHandle,
    key_id: &str,
    scope_context: &str,
    audit_sink: &vta_audit::SharedAuditSink,
    actor: &str,
    channel: &str,
) -> Result<(), AppError> {
    let record: KeyRecord = keys_ks
        .get(crate::keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;
    if let Err(v) = custody::check_key_in_scope(&record, scope_context) {
        report(
            audit_sink,
            actor,
            &v,
            Some(key_id),
            Some(scope_context),
            channel,
        )
        .await;
        return Err(v.into());
    }
    Ok(())
}

/// Authorize a caller-chosen derivation path for a new key record (rules 3–5).
///
/// Only a super-admin may choose a path at all. Everyone else is allocated one
/// under the context's base. The chosen path must then belong to the context
/// the record will carry (or to none, for a context-less record) and must not
/// lie in the sign-only delegated subtree.
pub async fn authorize_explicit_key_path(
    contexts_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    path: &str,
    context_id: Option<&str>,
    audit_sink: &vta_audit::SharedAuditSink,
    channel: &str,
) -> Result<(), AppError> {
    if !auth.is_super_admin() {
        let v = CustodyViolation::ForeignPath {
            path: path.to_string(),
            requested_context: context_id.map(str::to_string),
            owning_context: None,
        };
        report(audit_sink, &auth.did, &v, None, context_id, channel).await;
        return Err(AppError::Forbidden(format!(
            "only a super-admin may choose a derivation path (`{path}`); omit \
             `derivationPath` and the VTA allocates one under the context's base"
        )));
    }
    let contexts = list_contexts(contexts_ks).await?;
    let pairs = contexts
        .iter()
        .map(|c| (c.id.as_str(), c.base_path.as_str()));
    if let Err(v) = custody::check_explicit_key_path(path, context_id, pairs) {
        report(audit_sink, &auth.did, &v, None, context_id, channel).await;
        return Err(v.into());
    }
    Ok(())
}

/// Authorize a delegated-identity signature (`keys/derive-and-sign*`): a
/// super-admin, at a path inside [`custody::DELEGATED_IDENTITY_ROOT`].
///
/// Super-admin because the caller chooses the identity it signs as. The
/// subtree, because the delegated-identity oracle must never sign as a key a
/// record exists for, including the VTA's own. A super-admin with a stolen
/// token would otherwise gain a signature as the VTA's `did:webvh` update key
/// with no export, backup or audit trail.
pub async fn authorize_delegated_identity_path(
    auth: &AuthClaims,
    path: &str,
    action: &str,
    audit_sink: &vta_audit::SharedAuditSink,
    channel: &str,
) -> Result<(), AppError> {
    require_instance_authority(auth, action, audit_sink, channel).await?;
    if let Err(v) = custody::check_delegated_identity_path(path) {
        report(audit_sink, &auth.did, &v, None, None, channel).await;
        return Err(v.into());
    }
    Ok(())
}

/// Authorize and derive a delegated identity's Ed25519 signing key (seed form).
///
/// The one door for `keys/derive-and-sign*`: [`authorize_delegated_identity_path`]
/// then a derivation at exactly that path. The seed and root are dropped
/// before this returns. Only the key at `path` leaves this function.
#[allow(clippy::too_many_arguments)]
pub async fn derive_delegated_identity(
    keys_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    auth: &AuthClaims,
    path: &str,
    action: &str,
    audit_sink: &vta_audit::SharedAuditSink,
    channel: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, AppError> {
    authorize_delegated_identity_path(auth, path, action, audit_sink, channel).await?;
    let parsed = custody::parse_path(path)?;
    let seed = crate::keys::seeds::load_seed_bytes(keys_ks, seed_store, None)
        .await
        .map_err(|e| AppError::Internal(format!("{e}")))?;
    let root = vti_common::slip10::ExtendedSigningKey::from_seed(&seed).map_err(|e| {
        crate::error::key_derivation_error(format!("failed to create BIP-32 root key: {e}"))
    })?;
    let node = root
        .derive(&parsed)
        .map_err(|e| crate::error::key_derivation_error(format!("derivation failed: {e}")))?;
    Ok(zeroize::Zeroizing::new(*node.signing_key.as_bytes()))
}

/// What [`scan_key_custody`] found.
#[derive(Debug, Default)]
pub struct CustodyScanReport {
    /// Derived records inspected.
    pub checked: usize,
    /// `(key_id, reason)` for each record whose path its context does not own.
    pub violations: Vec<(String, String)>,
}

/// Inspect every derived key record against rule 3 and report violations.
///
/// Runs at boot. It **does not** change or revoke anything, because a record
/// here may be a key someone depends on and deleting it is not this scan's
/// call. It makes the record visible (audit row plus `security_alert`) so an
/// operator can decide. The use-time check in [`derive_record_key`] already
/// makes such a record unusable for any key its context does not own.
///
/// This is also how a VTA finds out it was exploited before the fix: a record
/// created through the old unchecked `keys/create` path shows up here.
pub async fn scan_key_custody(
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    audit_sink: &vta_audit::SharedAuditSink,
) -> Result<CustodyScanReport, AppError> {
    let contexts = list_contexts(contexts_ks).await?;
    let pairs: Vec<(&str, &str)> = contexts
        .iter()
        .map(|c| (c.id.as_str(), c.base_path.as_str()))
        .collect();

    let mut report_out = CustodyScanReport::default();
    for (_, raw) in keys_ks.prefix_iter_raw("key:").await? {
        let Ok(record) = serde_json::from_slice::<KeyRecord>(&raw) else {
            continue;
        };
        if record.origin != KeyOrigin::Derived {
            continue;
        }
        report_out.checked += 1;
        let violation = match custody::parse_path(&record.derivation_path) {
            Err(v) => Some(v),
            Ok(path) => {
                let owner = custody::owning_context(&path, pairs.iter().copied());
                // A context-less record inside a context's subtree is a second
                // handle on that context's key, outside its policy and audit.
                (owner != record.context_id.as_deref()).then(|| CustodyViolation::ForeignPath {
                    path: record.derivation_path.clone(),
                    requested_context: record.context_id.clone(),
                    owning_context: owner.map(str::to_string),
                })
            }
        };
        if let Some(v) = violation {
            report(
                audit_sink,
                "internal:key-custody-scan",
                &v,
                Some(&record.key_id),
                record.context_id.as_deref(),
                "boot",
            )
            .await;
            report_out
                .violations
                .push((record.key_id.clone(), v.to_string()));
        }
    }
    Ok(report_out)
}

async fn report(
    audit_sink: &vta_audit::SharedAuditSink,
    actor: &str,
    violation: &CustodyViolation,
    key_id: Option<&str>,
    context_id: Option<&str>,
    channel: &str,
) {
    let reason = violation.to_string();
    error!(
        audit = true,
        security_alert = true,
        actor,
        key_id = key_id.unwrap_or("-"),
        context_id = context_id.unwrap_or("-"),
        channel,
        reason = %reason,
        "key custody violation refused",
    );
    audit::record_with_detail_best_effort(
        audit_sink,
        CUSTODY_VIOLATION_ACTION,
        actor,
        key_id,
        "denied",
        Some(channel),
        context_id,
        Some(&reason),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use chrono::Utc;
    use vta_sdk::keys::{KeyStatus, KeyType};
    use vta_sdk::protocols::audit_management::list::AuditLogEntry;
    use vti_common::acl::Role;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    use crate::contexts::{ContextRecord, store_context};

    const VTA_KEY: &str = "did:webvh:vta.example#key-0";

    struct H {
        _dir: tempfile::TempDir,
        keys_ks: KeyspaceHandle,
        imported_ks: KeyspaceHandle,
        contexts_ks: KeyspaceHandle,
        audit_ks: KeyspaceHandle,
        audit: vta_audit::SharedAuditSink,
        seed_store: Arc<dyn SeedStore>,
    }

    fn record(key_id: &str, ctx: Option<&str>, path: &str) -> KeyRecord {
        KeyRecord {
            key_id: key_id.into(),
            derivation_path: path.into(),
            key_type: KeyType::Ed25519,
            status: KeyStatus::Active,
            public_key: String::new(),
            label: None,
            context_id: ctx.map(str::to_string),
            exportable: None,
            seed_id: None,
            origin: KeyOrigin::Derived,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn harness() -> H {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let contexts_ks = store.keyspace(crate::keyspaces::CONTEXTS).unwrap();
        for (id, base, index) in [("vta", "m/26'/2'/0'", 0), ("tenant-a", "m/26'/2'/1'", 1)] {
            store_context(
                &contexts_ks,
                &ContextRecord {
                    id: id.into(),
                    name: id.into(),
                    did: None,
                    description: None,
                    parent: None,
                    base_path: base.into(),
                    index,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    context_policy: None,
                },
            )
            .await
            .unwrap();
        }
        let keys_ks = store.keyspace(crate::keyspaces::KEYS).unwrap();
        // The VTA's own key: context-less, outside every context's base.
        let vta_key = record(VTA_KEY, None, "m/26'/0'/0'/0'");
        keys_ks
            .insert(crate::keys::store_key(VTA_KEY), &vta_key)
            .await
            .unwrap();
        let audit_ks = store.keyspace(crate::keyspaces::AUDIT).unwrap();
        H {
            keys_ks,
            imported_ks: store.keyspace(crate::keyspaces::IMPORTED_SECRETS).unwrap(),
            contexts_ks,
            audit: vta_audit::shared_keyspace_sink(audit_ks.clone()),
            audit_ks,
            seed_store: Arc::new(crate::test_support::TestSeedStore(vec![7u8; 64])),
            _dir: dir,
        }
    }

    fn claims(contexts: &[&str]) -> AuthClaims {
        AuthClaims {
            did: if contexts.is_empty() {
                "did:key:z6MkSuper".into()
            } else {
                "did:key:z6MkTenant".into()
            },
            role: Role::Admin,
            allowed_contexts: contexts.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        }
    }

    async fn denied_rows(h: &H, action: &str) -> Vec<AuditLogEntry> {
        h.audit_ks
            .prefix_iter_raw("log:")
            .await
            .unwrap()
            .iter()
            .filter_map(|(_, v)| serde_json::from_slice::<AuditLogEntry>(v).ok())
            .filter(|r| r.action == action && r.outcome == "denied")
            .collect()
    }

    #[tokio::test]
    async fn instance_authority_refuses_and_audits_a_scoped_admin() {
        let h = harness().await;
        assert!(
            require_instance_authority(&claims(&[]), "seed.rotate", &h.audit, "t")
                .await
                .is_ok()
        );
        let err = require_instance_authority(&claims(&["tenant-a"]), "seed.rotate", &h.audit, "t")
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
        let denied = denied_rows(&h, INSTANCE_AUTHORITY_ACTION).await;
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].resource.as_deref(), Some("seed.rotate"));
    }

    /// VTI-KEY-032 at creation: only a super-admin chooses a path, and only
    /// one its context owns.
    #[tokio::test]
    async fn explicit_paths_are_super_admin_only_and_must_be_owned() {
        let h = harness().await;
        let (tenant, sup) = (claims(&["tenant-a"]), claims(&[]));
        let check = async |auth: &AuthClaims, path: &str, ctx: Option<&str>| {
            authorize_explicit_key_path(&h.contexts_ks, auth, path, ctx, &h.audit, "t").await
        };
        // A tenant may not choose a path at all, not even one in its own context.
        assert!(
            check(&tenant, "m/26'/2'/1'/9'", Some("tenant-a"))
                .await
                .is_err()
        );
        // The FTL-29904 exploit: the VTA's own path, recorded under tenant-a.
        assert!(
            check(&tenant, "m/26'/0'/0'/0'", Some("tenant-a"))
                .await
                .is_err()
        );
        // A super-admin may, inside the context that owns the path...
        assert!(
            check(&sup, "m/26'/2'/1'/9'", Some("tenant-a"))
                .await
                .is_ok()
        );
        // ...but may not mislabel another context's path...
        assert!(
            check(&sup, "m/26'/2'/0'/0'", Some("tenant-a"))
                .await
                .is_err()
        );
        // ...nor create a record in the sign-only delegated subtree.
        assert!(check(&sup, "m/26'/9'/0'", None).await.is_err());
        assert_eq!(denied_rows(&h, CUSTODY_VIOLATION_ACTION).await.len(), 4);
    }

    #[tokio::test]
    async fn delegated_signing_is_super_admin_only_and_confined() {
        let h = harness().await;
        let (tenant, sup) = (claims(&["tenant-a"]), claims(&[]));
        let derive = async |auth: &AuthClaims, path: &str| {
            derive_delegated_identity(
                &h.keys_ks,
                &*h.seed_store,
                auth,
                path,
                "keys.derive-and-sign",
                &h.audit,
                "t",
            )
            .await
        };
        assert!(derive(&sup, "m/26'/9'/0'").await.is_ok());
        // A tenant cannot sign as a fleet identity...
        assert!(matches!(
            derive(&tenant, "m/26'/9'/0'").await,
            Err(AppError::Forbidden(_))
        ));
        // ...and nobody signs through this oracle as a key a record exists for.
        for path in ["m/26'/0'/0'/0'", "m/26'/2'/1'/0'"] {
            assert!(
                matches!(derive(&sup, path).await, Err(AppError::Forbidden(_))),
                "{path}"
            );
        }
    }

    /// Rule 6: a record planted under tenant-a carrying the VTA's path is
    /// refused at derivation, whoever asks, and the refusal is audited.
    #[tokio::test]
    async fn a_planted_record_is_refused_at_use() {
        let h = harness().await;
        let derive = async |r: &KeyRecord| {
            derive_record_key(
                &h.contexts_ks,
                &h.keys_ks,
                &*h.seed_store,
                &h.audit,
                "did:key:z6MkTenant",
                r,
                "t",
            )
            .await
        };
        let planted = record("innocuous", Some("tenant-a"), "m/26'/0'/0'/0'");
        let err = derive(&planted).await.unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
        assert_eq!(denied_rows(&h, CUSTODY_VIOLATION_ACTION).await.len(), 1);

        let honest = record("fine", Some("tenant-a"), "m/26'/2'/1'/3'");
        assert!(derive(&honest).await.is_ok());
    }

    /// Rule 7, end to end through the vault loader: a vault entry in tenant-a
    /// naming the VTA's own key is refused before the key is loaded.
    #[tokio::test]
    async fn a_vault_entry_cannot_sign_with_the_vtas_key() {
        let h = harness().await;
        let Err(err) = crate::operations::vault::load_signing_secret_by_id(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
            VTA_KEY,
            "tenant-a",
        )
        .await
        else {
            panic!("a vault entry naming the VTA's key must be refused");
        };
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
        assert_eq!(denied_rows(&h, CUSTODY_VIOLATION_ACTION).await.len(), 1);
    }

    #[tokio::test]
    async fn the_boot_scan_reports_only_foreign_records() {
        let h = harness().await;
        for r in [
            record("honest", Some("tenant-a"), "m/26'/2'/1'/0'"),
            record("planted", Some("tenant-a"), "m/26'/0'/0'/5'"),
            record("shadow", None, "m/26'/2'/1'/1'"),
        ] {
            h.keys_ks
                .insert(crate::keys::store_key(&r.key_id), &r)
                .await
                .unwrap();
        }
        let report = scan_key_custody(&h.keys_ks, &h.contexts_ks, &h.audit)
            .await
            .unwrap();
        let mut flagged: Vec<_> = report.violations.iter().map(|(k, _)| k.as_str()).collect();
        flagged.sort();
        assert_eq!(flagged, ["planted", "shadow"]);
        // Three inserted here, plus the VTA's own key from the harness.
        assert_eq!(report.checked, 4);
    }
}
