//! Releasing a private key: the export channels and refusals, the user-facing
//! export, internal use under an [`InternalAuthority`], and exportability.
//!
//! [`InternalAuthority`]: crate::operations::internal_authority::InternalAuthority

use super::*;

/// How the channel a released private key travels over protects it — stated
/// by the caller of [`get_key_secret`], because only the transport knows.
///
/// A type rather than a flag so that a new call site has to say which case it
/// is in. The `&str` is the audit `channel` the export is recorded under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportChannel<'a> {
    /// Encrypted by the transport to the requester alone: DIDComm authcrypt,
    /// or TSP. No intermediary — mediator included — holds the plaintext.
    EndToEnd(&'a str),
    /// Sealed to the recipient before it leaves the VTA
    /// (`vta_sdk::sealed_transfer`, HPKE), whatever carries the envelope.
    Sealed(&'a str),
    /// Never leaves this host: an on-host CLI running as the VTA's own OS user.
    Local(&'a str),
    /// Confidential in transit at best — REST, and Trust Tasks over HTTPS. TLS
    /// terminates wherever the operator terminates it, so the plaintext key
    /// would exist there. **Refused**: see [`get_key_secret`].
    HopByHop(&'a str),
}

impl<'a> ExportChannel<'a> {
    /// The audit `channel` this export is recorded under.
    pub fn audit_channel(self) -> &'a str {
        match self {
            Self::EndToEnd(c) | Self::Sealed(c) | Self::Local(c) | Self::HopByHop(c) => c,
        }
    }
}

/// Release a key's private material to the caller — `keys/export-secret`, over
/// every transport.
///
/// Every check a release needs, in the order the specification sets
/// (`keys/export-secret/0.1` § Authorization: entitlement first, then the two
/// refusals no authority satisfies, then the response):
///
/// 1. **`KeyExport`** ([`ensure_may_export`]), before the key is looked up;
/// 2. **a confidential channel** — an [`ExportChannel::HopByHop`] export is
///    refused. `keys/export-secret/0.1` requires the exchange to be "carried
///    over a channel confidential to the two parties", and the response is a
///    private key in the clear; over REST or HTTPS it would exist in plaintext
///    wherever TLS terminates. `keys/import` refuses the cleartext carrier over
///    the same transports for the same reason. Checked before the key is
///    looked up, so the refusal says nothing about which ids exist;
/// 3. **scope** — the key's context, or super-admin for an unscoped key;
/// 4. **never an internal key**, to anybody;
/// 5. **never a key marked non-exportable**;
/// 6. a **durable audit row**, written before the material is returned — see
///    [`release_key_secret`].
///
/// The transports are thin: `GET /keys/{id}/secret`, DIDComm `get-key-secret`
/// and the `keys/export-secret/0.1` handler all call this and nothing else, so
/// none of them carries a check the others lack.
#[allow(clippy::too_many_arguments)]
pub async fn get_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: ExportChannel<'_>,
) -> Result<GetKeySecretResultBody, AppError> {
    export_key_secret(
        keys_ks,
        imported_ks,
        contexts_ks,
        acl_ks,
        seed_store,
        audit,
        auth,
        key_id,
        channel,
    )
    .await
    .map_err(AppError::from)
}

/// Why a key's private half is refused **about the key rather than the
/// caller** — the two refusals `keys/export-secret/0.1` gives codes of their
/// own, because retrying with more authority changes neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyExportRefusal {
    /// An internal key: generated inside this VTA, reproducible nowhere, never
    /// released to anybody — `keys/export-secret:neverExportable`.
    NeverExportable,
    /// Marked non-exportable by `keys/set-exportability` — a decision that can
    /// be reversed, by more authority than imposed it —
    /// `keys/export-secret:notExportable`.
    NotExportable,
}

impl KeyExportRefusal {
    /// The local part of the task's extended error code.
    pub fn code(self) -> &'static str {
        match self {
            Self::NeverExportable => "neverExportable",
            Self::NotExportable => "notExportable",
        }
    }
}

/// The error [`export_key_secret`] returns: a refusal about the key, typed so a
/// transport that can name it (the Trust-Task spine) does, or any other error.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyExportError {
    Refused(KeyExportRefusal, String),
    Other(AppError),
}

impl From<AppError> for KeyExportError {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<KeyExportError> for AppError {
    /// For transports with no code to carry: a refusal about the key is a 403
    /// with the same message.
    fn from(e: KeyExportError) -> Self {
        match e {
            KeyExportError::Refused(_, message) => AppError::Forbidden(message),
            KeyExportError::Other(e) => e,
        }
    }
}

/// [`get_key_secret`] with the refusals about the key kept typed — what the
/// `keys/export-secret/0.1` handler calls so it can answer `notExportable` /
/// `neverExportable`. Same checks in the same order: the capability, the
/// channel and the caller's scope are all established first, so those codes
/// are only ever said to a caller already entitled to the key (the spec's
/// "after establishing entitlement and before assembling a response").
#[allow(clippy::too_many_arguments)]
pub async fn export_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: ExportChannel<'_>,
) -> Result<GetKeySecretResultBody, KeyExportError> {
    ensure_may_export(acl_ks, auth, "keys/export-secret").await?;
    if let ExportChannel::HopByHop(_) = channel {
        return Err(AppError::Forbidden(
            "keys/export-secret refused: a private key is released only over a channel \
             confidential end to end — DIDComm or TSP — or sealed to its recipient, and \
             this request arrived over REST/HTTPS, where TLS terminates wherever the \
             operator terminates it and the key would exist in plaintext there. Retry over \
             DIDComm or TSP, or run the export on the VTA host."
                .into(),
        )
        .into());
    }
    release_key_secret(
        keys_ks,
        imported_ks,
        contexts_ks,
        seed_store,
        audit,
        auth,
        key_id,
        channel.audit_channel(),
    )
    .await
}

/// Checks 3–6 of [`get_key_secret`]: scope, the internal-key and
/// non-exportable refusals, and the durable audit row. The one place a private
/// key leaves the VTA. Private: every caller goes through [`get_key_secret`]
/// and so through the capability and channel gates.
///
/// `get_key_secret_internal` is deliberately NOT gated by exportability: it is
/// the *use* surface, loading a key so the VTA can sign or decrypt with it, and
/// a key that may not leave may still be used.
///
/// # The audit row is a precondition of the release
///
/// VTI-VTA-003 requires an export to be audited, and elsewhere in this module
/// the row is best-effort, because a failed write must not fail an operation
/// that has already happened — refusing to revoke a key because the log is full
/// protects nobody. An export is the opposite case: nothing has happened until
/// the material is returned, and once it has, it cannot be taken back. So the
/// row is written first and a failed write **refuses the export**. The row
/// carries who (`actor`), which key (`resource`), its context, and the
/// transport (`channel`) — never the material.
#[allow(clippy::too_many_arguments)]
pub(super) async fn release_key_secret(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &Arc<dyn SeedStore>,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    channel: &str,
) -> Result<GetKeySecretResultBody, KeyExportError> {
    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;

    // A revoked key is refused like a missing one would be to its owner: its
    // record is kept for history (and a rotation's retired and staging records
    // are revoked by construction), not so its private half can still leave.
    if record.status != KeyStatus::Active {
        return Err(KeyExportError::Other(AppError::Forbidden(format!(
            "key `{key_id}` is not active and its private half is not released"
        ))));
    }

    // Internal keys are refused here too. `InternalAuthority` bypasses the ACL,
    // not the non-extractability guarantee — an internal key has no export
    // surface at all, and an internal caller wanting a signature must go
    // through the signing oracle like everyone else.
    if record.origin == KeyOrigin::Internal {
        return Err(KeyExportError::Refused(
            KeyExportRefusal::NeverExportable,
            format!(
                "key `{key_id}` is an internal key and is never exported, including \
                 under internal authority"
            ),
        ));
    }

    // The exportability restriction, enforced at the one place a private key
    // leaves the VTA — every export path (`keys/export-secret` on each
    // transport, `vta/contexts/secrets`, the offline CLI exports, and
    // provisioning's read-back) arrives here. `get_key_secret_internal` is
    // deliberately NOT gated: it is the *use* surface, and gating it would break
    // the VTA's own signing rather than protect anything, because nothing it
    // returns reaches a caller.
    //
    // `None` means exportable — see `KeyRecord::exportable`. Only an explicit
    // `Some(false)` refuses, so records written before the member existed are
    // unaffected.
    if record.exportable == Some(false) {
        return Err(KeyExportError::Refused(
            KeyExportRefusal::NotExportable,
            format!(
                "key `{key_id}` is marked non-exportable and its private half is never \
                 released; it can still be used for signing and key agreement. Changing \
                 that needs `keys/set-exportability` with authority beyond the one that \
                 set it"
            ),
        ));
    }

    let (public_key_multibase, private_key_multibase) = match record.origin {
        // Unreachable: the early return above refuses internal keys. Kept as a
        // second, local refusal so deleting that guard cannot quietly turn this
        // match into an export path for them.
        KeyOrigin::Internal => {
            return Err(KeyExportError::Refused(
                KeyExportRefusal::NeverExportable,
                format!("key `{key_id}` is an internal key and is never exported"),
            ));
        }
        KeyOrigin::Imported => {
            // Decrypt from imported_secrets keyspace
            let seed = load_seed_bytes(keys_ks, &**seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;
            let priv_mb = encode_private_multibase(&record.key_type, &secret_bytes);
            secret_bytes.zeroize();
            (record.public_key.clone(), priv_mb)
        }
        // Through key custody: the record's path must lie in its context's base,
        // so a record carrying a foreign path is refused here rather than
        // exported (VTI-KEY-032, `vta_keys::custody` rule 6).
        KeyOrigin::Derived => {
            let key = crate::operations::key_custody::derive_record_key(
                contexts_ks,
                keys_ks,
                &**seed_store,
                audit,
                &auth.did,
                &record,
                channel,
            )
            .await?;
            let (public, private) = key.multibase_pair()?;
            (public, (*private).clone())
        }
    };

    // Durable before the material is returned, and refusing on failure — see
    // "The audit row is a precondition of the release" above.
    if let Err(e) = audit::record(
        audit,
        "key.secret_export",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await
    {
        let mut private_key_multibase = private_key_multibase;
        private_key_multibase.zeroize();
        tracing::error!(
            target: vta_audit::AUDIT_WRITE_FAILURE_TARGET,
            error = %e, channel, key_id = %key_id, actor = %auth.did,
            "key export refused: its audit row could not be written"
        );
        return Err(KeyExportError::Other(AppError::Internal(format!(
            "key `{key_id}` was not released: the export could not be recorded in the \
             audit trail, and an unrecorded export is not permitted (VTI-VTA-003)"
        ))));
    }
    info!(channel, key_id = %key_id, "key secret retrieved");
    audit!(
        "key.secret_export",
        actor = &auth.did,
        resource = key_id,
        outcome = "success"
    );

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase,
        private_key_multibase,
    })
}

/// Set whether a key's private half may be released, and refuse to make that
/// decision cheaply reversible.
///
/// # The asymmetry is the feature
///
/// A restriction that whoever imposed it can lift again protects against
/// accident but not against a compromised caller holding that party's
/// credentials — which is the case the restriction exists for. So the two
/// directions do not carry the same entitlement:
///
/// - **Imposing it** (`exportable: false`) needs admin of the key's context.
///   Foreclosing something is the safe direction.
/// - **Lifting it** (`false` → `true`) needs that *and* one of two things
///   beyond it: super-admin, or a live step-up on this session. Either is
///   strictly more than the entitlement that imposed it, which is what
///   `keys/set-exportability/0.1` requires of a conforming consumer. The spec
///   deliberately does not name the mechanism — SPEC §7.3 item 13 forbids a
///   specification from mandating a step-up — so choosing these two is this
///   VTA's policy, and either satisfies the rule.
///
/// Offering both rather than only super-admin matters operationally: a
/// deployment with no super-admin session to hand can still recover a key it
/// locked down, by stepping up. One with no step-up policy configured can still
/// do it as super-admin. Requiring only one of them would strand somebody.
///
/// # Idempotent, and only the transition is gated
///
/// `exportable` is an absolute state, not a toggle, so a producer that retries
/// a request whose reply was lost lands where it asked. Setting `true` on a key
/// that is already exportable takes nothing away and so takes the ordinary
/// path — only a real `false` → `true` transition meets the stronger gate.
pub async fn set_key_exportability(
    keys_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
    audit: &vta_audit::SharedAuditSink,
    auth: &AuthClaims,
    key_id: &str,
    exportable: bool,
    channel: &str,
) -> Result<KeyRecord, AppError> {
    let mut record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    // Standing over the key's scope, exactly as the export path requires it.
    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
    } else if !auth.is_super_admin() {
        return Err(AppError::Forbidden(
            "only super admin can act on keys without a context".into(),
        ));
    }
    auth.require_admin()?;

    // An internal key has no export surface at all, so `exportable: true` is
    // asking for something no authority can grant. Refused as a precondition
    // rather than a permission failure — retrying as super-admin changes
    // nothing, and saying "forbidden" would send the operator to look for more
    // authority that does not exist.
    if record.origin == KeyOrigin::Internal && exportable {
        return Err(AppError::Validation(format!(
            "key `{key_id}` is an internal key: its private half is never released              regardless of this setting, so it cannot be made exportable"
        )));
    }

    let currently = record.exportable != Some(false);
    if !currently && exportable {
        // The one gated transition. Super-admin OR a live step-up; the error
        // names both, because a caller told only "forbidden" cannot tell which
        // of the two routes is open to it.
        if auth.require_super_admin().is_err() {
            auth.require_fresh_step_up(sessions_ks).await.map_err(|_| {
                AppError::Forbidden(format!(
                    "making `{key_id}` exportable again needs more authority than the                      admin that restricted it: either super-admin, or a fresh step-up                      on this session"
                ))
            })?;
        }
    }

    record.exportable = Some(exportable);
    record.updated_at = chrono::Utc::now();
    keys_ks.insert(keys::store_key(key_id), &record).await?;

    audit!(
        "key.set_exportability",
        actor = &auth.did,
        resource = key_id,
        outcome = "success"
    );
    audit::record_best_effort(
        audit,
        "key.set_exportability",
        &auth.did,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(record)
}

/// [`get_key_secret_internal`] for the test harness, which sits outside
/// `operations` and so cannot mint an [`InternalAuthority`](crate::operations::internal_authority::InternalAuthority).
#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn key_secret_for_test_support(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit: &vta_audit::SharedAuditSink,
    key_id: &str,
) -> Result<GetKeySecretResultBody, AppError> {
    get_key_secret_internal(
        keys_ks,
        imported_ks,
        contexts_ks,
        seed_store,
        audit,
        crate::operations::internal_authority::InternalAuthority::new("test-support"),
        key_id,
        "test-support",
    )
    .await
}

/// Internal-authority variant of [`get_key_secret`] — the **use** surface,
/// audited as `key.internal_use` — that bypasses the
/// `auth.require_context` / `auth.is_super_admin` gates.
///
/// Required because the provision-integration flow needs to load the
/// VTA's own signing material (`{vta_did}#key-0`,
/// `{vta_did}#sealed-transfer-0`) to issue VCs and sign producer
/// assertions; those keys are server-internal, not user-attributable.
/// The user-facing caller has already been authorised upstream as a
/// context admin at precondition time.
///
/// Construction of [`InternalAuthority`](crate::operations::internal_authority::InternalAuthority)
/// is `pub(super)` to the `operations` module — route handlers cannot
/// reach it. Each elevation
/// thus has to come from the operations layer with an explicit purpose
/// tag, which is logged as the audit actor.
pub async fn get_key_secret_internal(
    keys_ks: &KeyspaceHandle,
    imported_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    audit: &vta_audit::SharedAuditSink,
    authority: crate::operations::internal_authority::InternalAuthority,
    key_id: &str,
    channel: &str,
) -> Result<GetKeySecretResultBody, AppError> {
    let record: KeyRecord = keys_ks
        .get(keys::store_key(key_id))
        .await?
        .ok_or_else(|| AppError::NotFound(format!("key {key_id} not found")))?;

    // Deliberately no `auth.require_context` / `is_super_admin` gate —
    // possessing an `InternalAuthority` IS the gate.

    // Internal authority skips the ACL, not the key's lifecycle: a revoked key
    // (retired by a rotation, or revoked outright) must not keep signing or
    // decrypting for the VTA.
    if record.status != KeyStatus::Active {
        return Err(AppError::Forbidden(format!(
            "key `{key_id}` is not active and is not loaded for use"
        )));
    }

    let (public_key_multibase, private_key_multibase) = match record.origin {
        // Unreachable: the early return above refuses internal keys. Kept as a
        // second, local refusal so deleting that guard cannot quietly turn this
        // match into an export path for them.
        KeyOrigin::Internal => {
            return Err(AppError::Forbidden(format!(
                "key `{key_id}` is an internal key and is never exported"
            )));
        }
        KeyOrigin::Imported => {
            let seed = load_seed_bytes(keys_ks, seed_store, None)
                .await
                .map_err(|e| AppError::Internal(format!("{e}")))?;
            let mut secret_bytes = imported::load_secret(
                imported_ks,
                keys_ks,
                &seed,
                key_id,
                &record.key_type.to_string(),
            )
            .await?;
            let priv_mb = encode_private_multibase(&record.key_type, &secret_bytes);
            secret_bytes.zeroize();
            (record.public_key.clone(), priv_mb)
        }
        // Through key custody even under internal authority: `InternalAuthority`
        // bypasses the ACL, not the rule that a record's path belongs to its
        // context.
        KeyOrigin::Derived => {
            let key = crate::operations::key_custody::derive_record_key(
                contexts_ks,
                keys_ks,
                seed_store,
                audit,
                &authority.audit_actor(),
                &record,
                channel,
            )
            .await?;
            let (public, private) = key.multibase_pair()?;
            (public, (*private).clone())
        }
    };

    // `key.internal_use`, not `key.secret_export`: nothing here leaves the VTA
    // — the key is loaded so the VTA can sign or decrypt with it itself. Filed
    // under the export action, every VC the VTA issued and every webvh publish
    // it authenticated read as a key export, which buried the real exports an
    // incident review is looking for under the VTA's own routine use.
    let actor = authority.audit_actor();
    info!(channel, key_id = %key_id, actor = %actor, "key loaded for internal use");
    audit!(
        "key.internal_use",
        actor = &actor,
        resource = key_id,
        outcome = "success"
    );
    audit::record_best_effort(
        audit,
        "key.internal_use",
        &actor,
        Some(key_id),
        "success",
        Some(channel),
        record.context_id.as_deref(),
    )
    .await;

    Ok(GetKeySecretResultBody {
        key_id: record.key_id,
        key_type: record.key_type,
        public_key_multibase,
        private_key_multibase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contexts::create_context;
    use crate::operations::keys::test_support::*;

    /// The guarantee, stated as a test: no export surface returns an internal
    /// key, and admin is not a bypass — a super-admin is refused like anyone.
    #[tokio::test]
    async fn an_internal_key_is_never_exported_even_to_a_super_admin() {
        let h = TestHarness::new().await;
        mint_internal(&h, "k-internal").await;

        let err = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-internal",
            ExportChannel::Local("test"),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
            "a super-admin must still be refused; got {err:?}"
        );
    }

    // ── exportability ────────────────────────────────────────────────
    //
    // The member's whole value is that the two directions are not equally easy
    // to travel. These assert the relation, not just each end of it.

    /// A key created the ordinary way carries no opinion, and absence reads as
    /// exportable — the compatibility guarantee for every record written before
    /// the member existed.
    #[tokio::test]
    async fn a_key_is_exportable_until_someone_says_otherwise() {
        let h = TestHarness::new().await;
        let created = mint_derived(&h, "k-open").await;
        assert_eq!(
            created.exportable, None,
            "a new key records no decision; `Some(true)` would be a claim nobody made"
        );

        get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-open",
            ExportChannel::Local("test"),
        )
        .await
        .expect("absence must read as exportable");
    }

    /// The restriction bites at the one place a private key leaves the VTA.
    #[tokio::test]
    async fn a_restricted_key_is_never_exported() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-shut").await;

        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-shut",
            false,
            "test",
        )
        .await
        .expect("a context admin may impose the restriction");

        let err = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-shut",
            ExportChannel::Local("test"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("non-exportable")),
            "even a super-admin is refused the material; got {err:?}"
        );
    }

    /// The asymmetry itself. The same claim that imposed the restriction must
    /// not be able to lift it — otherwise the restriction protects against
    /// accident but not against a compromised caller holding that claim, which
    /// is the case it exists for.
    #[tokio::test]
    async fn the_admin_that_restricted_a_key_cannot_release_it_again() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-asym").await;
        let admin = h.context_admin_auth();

        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &admin,
            "k-asym",
            false,
            "test",
        )
        .await
        .expect("imposing is the cheap direction");

        let err = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &admin,
            "k-asym",
            true,
            "test",
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m)
                if m.contains("super-admin") && m.contains("step-up")),
            "the refusal must name both routes, or a caller cannot tell which is \
             open to it; got {err:?}"
        );
    }

    /// Super-admin is one of the two ways past that gate.
    #[tokio::test]
    async fn a_super_admin_can_release_a_restricted_key() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-reopen").await;

        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-reopen",
            false,
            "test",
        )
        .await
        .expect("restrict");

        let record = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.super_admin_auth(),
            "k-reopen",
            true,
            "test",
        )
        .await
        .expect("a super-admin holds strictly more than the context admin that restricted it");
        assert_eq!(record.exportable, Some(true));

        get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-reopen",
            ExportChannel::Local("test"),
        )
        .await
        .expect("and the key exports again");
    }

    /// Only a real `false` -> `true` transition meets the stronger gate.
    /// Setting `true` on an already-exportable key takes nothing away, so
    /// gating it would demand super-admin for a no-op — and would make a
    /// retried request harder to complete than the original.
    #[tokio::test]
    async fn re_asserting_exportable_on_an_open_key_is_not_gated() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-noop").await;

        let record = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-noop",
            true,
            "test",
        )
        .await
        .expect("a context admin may confirm what is already true");
        assert_eq!(record.exportable, Some(true));
    }

    /// Idempotent in the other direction too: `exportable` is an absolute
    /// state, so a producer retrying a lost `false` lands on `false` rather
    /// than toggling back.
    #[tokio::test]
    async fn restricting_twice_stays_restricted() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-twice").await;
        let admin = h.context_admin_auth();

        for _ in 0..2 {
            let record = set_key_exportability(
                &h.keys_ks,
                &h.sessions_ks,
                &h.audit,
                &admin,
                "k-twice",
                false,
                "test",
            )
            .await
            .expect("a repeat is a no-op, not a toggle");
            assert_eq!(record.exportable, Some(false));
        }
    }

    /// Scope still applies: an admin of another context reaches nothing here,
    /// the same rule the export path enforces.
    #[tokio::test]
    async fn an_admin_of_another_context_cannot_set_exportability() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-scope").await;
        let mut elsewhere = h.context_admin_auth();
        elsewhere.allowed_contexts = vec!["some-other-ctx".to_string()];

        let err = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &elsewhere,
            "k-scope",
            false,
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got: {err:?}");
    }

    /// An internal key can never be released, so asking for that is a
    /// precondition failure rather than a permission one — retrying with more
    /// authority changes nothing, and `Forbidden` would send the operator
    /// looking for authority that does not exist.
    #[tokio::test]
    async fn an_internal_key_cannot_be_made_exportable() {
        let h = TestHarness::new().await;
        mint_internal(&h, "k-internal").await;

        let err = set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.super_admin_auth(),
            "k-internal",
            true,
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("internal key")),
            "got: {err:?}"
        );
    }

    /// `InternalAuthority` bypasses the ACL, not the non-extractability
    /// guarantee. If this ever passes, the export surface has reopened through
    /// the back door rather than the front.
    #[tokio::test]
    async fn internal_authority_does_not_bypass_non_extractability() {
        let h = TestHarness::new().await;
        mint_internal(&h, "k-internal").await;

        let err = get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-internal",
            "test",
        )
        .await
        .unwrap_err();

        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
            "{err:?}"
        );
    }

    /// A revoked record — a key a rotation retired, or a rotation's inert
    /// staging record — is kept for history only: the VTA's own loads do not
    /// release its private half. (The export surface refuses it too; that half
    /// is tested with the export gate.)
    #[tokio::test]
    async fn a_revoked_key_is_not_loaded() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-retired").await;
        let mut record: KeyRecord = h
            .keys_ks
            .get(keys::store_key("k-retired"))
            .await
            .unwrap()
            .unwrap();
        record.status = KeyStatus::Revoked;
        h.keys_ks
            .insert(keys::store_key("k-retired"), &record)
            .await
            .unwrap();

        let err = get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-retired",
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not active")),
            "{err:?}"
        );
    }

    /// VTI-VTA-003: an admin narrowed without `key-export` is refused on every
    /// channel — REST and DIDComm included, which is where it used to pass —
    /// and the refusal names the capability and the fix. Nothing is recorded
    /// as exported.
    #[tokio::test]
    async fn vti_vta_003_export_without_key_export_is_refused_on_every_channel() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-gated").await;
        let auth = h.context_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::Sign, Capability::KeyMint]).await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();

        for channel in every_channel() {
            let err = export(&h, &audit, &auth, "k-gated", channel)
                .await
                .expect_err("narrowed away, key-export is gone on every transport");
            assert!(
                matches!(&err, AppError::Forbidden(m)
                    if m.contains("key-export")
                        && m.contains("--capabilities sign,key-mint,key-export")),
                "{channel:?}: {err:?}"
            );
        }
        assert!(
            sink.rows.lock().await.is_empty(),
            "a refused export must not be recorded as one"
        );
    }

    /// The gate runs before the lookup: a caller without `key-export` gets the
    /// same refusal for a key that exists and one that does not.
    #[tokio::test]
    async fn the_export_gate_does_not_reveal_which_keys_exist() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-real").await;
        let auth = h.context_admin_auth();
        store_narrowed(&h, &auth, vec![Capability::Sign]).await;
        let real = export(&h, &h.audit, &auth, "k-real", ExportChannel::Local("t"))
            .await
            .unwrap_err()
            .to_string();
        let imaginary = export(&h, &h.audit, &auth, "k-none", ExportChannel::Local("t"))
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(real, imaginary);
    }

    /// `keys/export-secret/0.1`: the exchange must be confidential to the two
    /// parties. An entitled caller asking over a hop-by-hop channel is refused,
    /// told how to succeed, and nothing is released or recorded.
    #[tokio::test]
    async fn an_export_over_a_hop_by_hop_channel_is_refused_even_when_entitled() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-tls").await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();

        let err = export(
            &h,
            &audit,
            &h.super_admin_auth(),
            "k-tls",
            ExportChannel::HopByHop("rest"),
        )
        .await
        .expect_err("REST never carries a private key");
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("DIDComm or TSP")),
            "the refusal must say which transports work: {err:?}"
        );
        assert!(sink.rows.lock().await.is_empty());

        export(
            &h,
            &audit,
            &h.super_admin_auth(),
            "k-tls",
            ExportChannel::EndToEnd("didcomm"),
        )
        .await
        .expect("the same caller succeeds end to end");
    }

    /// A key marked non-exportable, and an internal key, are refused on every
    /// channel that could otherwise release them — to a super-admin, with
    /// `key-export`.
    #[tokio::test]
    async fn non_exportable_and_internal_keys_are_refused_on_every_channel() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-locked").await;
        set_key_exportability(
            &h.keys_ks,
            &h.sessions_ks,
            &h.audit,
            &h.context_admin_auth(),
            "k-locked",
            false,
            "test",
        )
        .await
        .expect("restrict");
        mint_internal(&h, "k-inside").await;

        for channel in every_channel() {
            if matches!(channel, ExportChannel::HopByHop(_)) {
                // Refused before the key is read at all — asserted above.
                continue;
            }
            let err = export(&h, &h.audit, &h.super_admin_auth(), "k-locked", channel)
                .await
                .expect_err("non-exportable");
            assert!(
                matches!(&err, AppError::Forbidden(m) if m.contains("non-exportable")),
                "{channel:?}: {err:?}"
            );
            let err = export(&h, &h.audit, &h.super_admin_auth(), "k-inside", channel)
                .await
                .expect_err("internal");
            assert!(
                matches!(&err, AppError::Forbidden(m) if m.contains("internal key")),
                "{channel:?}: {err:?}"
            );
        }
    }

    /// VTI-VTA-003 "and MUST be audited": a successful export leaves one
    /// durable `key.secret_export` row naming who, which key, its context and
    /// the transport — and never the material.
    #[tokio::test]
    async fn vti_vta_003_a_successful_export_writes_a_durable_audit_row() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-audited").await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();
        let auth = h.context_admin_auth();

        let released = export(
            &h,
            &audit,
            &auth,
            "k-audited",
            ExportChannel::EndToEnd("trust-task/tsp"),
        )
        .await
        .expect("an admin of the key's context exports it end to end");

        let rows = sink.rows.lock().await;
        let exports: Vec<_> = rows
            .iter()
            .filter(|r| r.action == "key.secret_export")
            .collect();
        assert_eq!(exports.len(), 1, "exactly one export row: {rows:?}");
        let row = exports[0];
        assert_eq!(row.actor, auth.did);
        assert_eq!(row.resource.as_deref(), Some("k-audited"));
        assert_eq!(row.context_id.as_deref(), Some("test-ctx"));
        assert_eq!(row.channel.as_deref(), Some("trust-task/tsp"));
        assert_eq!(row.outcome, "success");
        let serialized = serde_json::to_string(row).unwrap();
        assert!(
            !serialized.contains(&released.private_key_multibase),
            "the audit row must never carry the key material"
        );
    }

    /// The row is a precondition of the release: a sink that cannot record
    /// means no key leaves.
    #[tokio::test]
    async fn an_export_that_cannot_be_audited_is_refused() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-unrecorded").await;
        let audit: vta_audit::SharedAuditSink = recording_sink(true);

        let err = export(
            &h,
            &audit,
            &h.super_admin_auth(),
            "k-unrecorded",
            ExportChannel::Local("cli"),
        )
        .await
        .expect_err("an unrecorded export is not permitted");
        assert!(
            matches!(&err, AppError::Internal(m) if m.contains("VTI-VTA-003")),
            "{err:?}"
        );
    }

    /// The VTA's own use of a key is recorded as `key.internal_use`, never as
    /// an export — so `key.secret_export` rows are exactly the keys that left.
    #[tokio::test]
    async fn internal_use_is_not_recorded_as_an_export() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-used").await;
        let sink = recording_sink(false);
        let audit: vta_audit::SharedAuditSink = sink.clone();
        get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-used",
            "test",
        )
        .await
        .expect("internal load");
        let rows = sink.rows.lock().await;
        assert!(
            rows.iter().any(|r| r.action == "key.internal_use"),
            "{rows:?}"
        );
        assert!(
            !rows.iter().any(|r| r.action == "key.secret_export"),
            "internal use must not read as an export: {rows:?}"
        );
    }

    /// A P-256 key's stored public key is the multicodec form (`p256-pub`),
    /// identical to what custody publishes when the key is exported — one
    /// encoding across record, export and document.
    #[tokio::test]
    async fn p256_record_and_export_agree_on_the_multicodec_public_key() {
        let h = TestHarness::new().await;
        let created = create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: false,
                key_type: KeyType::P256,
                derivation_path: None,
                key_id: Some("k-p256".into()),
                mnemonic: None,
                label: None,
                context_id: Some("test-ctx".into()),
            },
            "test",
        )
        .await
        .expect("mint P-256");
        let (_, bytes) = multibase::decode(&created.public_key).unwrap();
        assert!(bytes.starts_with(KeyType::P256.multicodec_public()));
        assert_eq!(bytes.len(), 2 + 33);

        let exported = get_key_secret(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &h.acl_ks,
            &h.seed_store,
            &h.audit,
            &h.super_admin_auth(),
            "k-p256",
            ExportChannel::Local("test"),
        )
        .await
        .expect("export");
        assert_eq!(exported.public_key_multibase, created.public_key);
    }

    /// Scope before existence: a caller restricted to `test-ctx` gets one
    /// refusal for a key in another context and for a key that does not
    /// exist — naming neither — on both the export and the signing oracle.
    #[tokio::test]
    async fn out_of_scope_and_absent_keys_are_indistinguishable() {
        let h = TestHarness::new().await;
        create_context(&h.contexts_ks, "other-ctx", "Other")
            .await
            .unwrap();
        create_key(
            &h.keys_ks,
            &h.internal_ks,
            &h.contexts_ks,
            &h.seed_store,
            &h.audit,
            &h.acl_ks,
            &h.super_admin_auth(),
            CreateKeyParams {
                internal: false,
                key_type: KeyType::Ed25519,
                derivation_path: None,
                key_id: Some("k-elsewhere".into()),
                mnemonic: None,
                label: None,
                context_id: Some("other-ctx".into()),
            },
            "test",
        )
        .await
        .unwrap();
        let auth = h.context_admin_auth();
        let refuse = |id: &'static str| {
            let h = &h;
            let auth = auth.clone();
            async move {
                let e = export(h, &h.audit, &auth, id, ExportChannel::Local("t"))
                    .await
                    .unwrap_err()
                    .to_string();
                let s = sign_as(h, &auth, id, SigningDomain::Opaque)
                    .await
                    .unwrap_err()
                    .to_string();
                (e.replace(id, "<id>"), s.replace(id, "<id>"))
            }
        };
        let real = refuse("k-elsewhere").await;
        let absent = refuse("k-nowhere").await;
        assert_eq!(real, absent);
        assert!(
            !real.0.contains("other-ctx"),
            "must not name the key's context: {real:?}"
        );
    }

    /// A revoked key's private half is not released, and internal authority
    /// does not load it for use either.
    #[tokio::test]
    async fn revoked_keys_are_neither_exported_nor_loaded() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-gone").await;
        revoke_key(
            &h.keys_ks,
            &h.imported_ks,
            &h.audit,
            &h.super_admin_auth(),
            "k-gone",
            None,
            "test",
        )
        .await
        .expect("revoke");
        let err = export(
            &h,
            &h.audit,
            &h.super_admin_auth(),
            "k-gone",
            ExportChannel::Local("t"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not active")),
            "{err:?}"
        );
        let err = get_key_secret_internal(
            &h.keys_ks,
            &h.imported_ks,
            &h.contexts_ks,
            &*h.seed_store,
            &h.audit,
            crate::operations::internal_authority::InternalAuthority::new("test"),
            "k-gone",
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, AppError::Forbidden(m) if m.contains("not active")),
            "{err:?}"
        );
    }
}
