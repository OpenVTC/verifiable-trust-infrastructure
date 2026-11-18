//! The capability gates every key operation passes before it touches key
//! material: export, sign, mint, and whether the caller may name a key at all.
//! Other operations import them (`ensure_may_*`, `require_key_nameable`).

use super::*;

/// The caller's stored ACL entry, for a capability gate.
///
/// `Ok(None)` means the caller has no entry and its role decides — the
/// process-local synthesized identities (the offline CLI's `cli:<channel>`
/// sentinel) and nothing else reach here without one. A store error **refuses**:
/// an unreadable entry must not become a grant, and the caller is told only that
/// the capability could not be confirmed while the operator gets the reason.
pub(super) async fn entry_for_capability_gate(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
    capability: &str,
) -> Result<Option<vti_common::acl::AclEntry>, AppError> {
    vti_common::acl::get_acl_entry(acl_ks, &auth.did)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e, did = %auth.did, capability,
                "could not read the ACL entry for a capability check; refusing"
            );
            AppError::Forbidden(format!(
                "{what} denied: could not confirm that {} carries the {capability} capability",
                auth.did
            ))
        })
}

/// Whether `entry` (or, with none, the caller's role) carries `cap` — the role's
/// set narrowed by the entry's own list, as every capability gate reads it.
pub(super) fn entry_or_role_has(
    entry: Option<&vti_common::acl::AclEntry>,
    auth: &AuthClaims,
    cap: Capability,
) -> bool {
    match entry {
        Some(entry) => vti_common::acl::entry_has_capability(entry, cap),
        None => vti_common::acl::role_has_capability(&auth.role, cap),
    }
}

/// The export gate: the caller must hold [`Capability::KeyExport`] (VTI-VTA-003).
///
/// This is the one implementation of it, and it lives here — in the operation,
/// not in a handler — because the export surface is reachable over REST, DIDComm
/// and the Trust-Task spine (itself carried over HTTPS, DIDComm and TSP). It used
/// to be applied by the `keys/export-secret` handler alone, so the same export
/// over `GET /keys/{id}/secret` or DIDComm `get-key-secret` checked only the
/// admin *role*: an admin narrowed without `key-export` could still take a key by
/// choosing a different transport. Checked in the operation, a transport added
/// later cannot be wired without it.
///
/// Reads the caller's **entry**, so a narrowing that removes `key-export` binds
/// the very next export. Runs before the key or context is looked up, so a
/// refused caller learns nothing about which ids exist.
///
/// The refusal names the exact command that fixes it — the caller is often a
/// service logging at boot, and the person reading that log is the one who has
/// to run it.
pub(crate) async fn ensure_may_export(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
) -> Result<(), AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, what, "key-export").await?;
    if entry_or_role_has(entry.as_ref(), auth, Capability::KeyExport) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "{what} denied: {} does not carry the key-export capability. Releasing a \
         private key is an export, and VTI-VTA-003 gates export on a capability \
         distinct from using the key; only an admin derives it, so a service that \
         holds a context's keys must be an admin scoped to that context. {}",
        auth.did,
        key_export_fix(entry.as_ref(), &auth.did)
    )))
}

/// The generic signing-oracle gate: the caller must hold [`Capability::Sign`].
///
/// `Sign` is "the capability to use the key" VTI-VTA-003 distinguishes export
/// from, and the capability VTI-VTA-007 distinguishes from the constrained
/// signing grants (`sign-trust-task`, `room-present`, …). Every role that can
/// reach the oracle derives it, so an un-narrowed entry loses nothing; what this
/// adds is that an operator who narrowed `sign` away from an entry gets the
/// refusal they asked for — before, the role floor was the only check, and the
/// narrowing was silently ignored on every transport.
pub(crate) async fn ensure_may_sign(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
) -> Result<(), AppError> {
    ensure_may_sign_caller(acl_ks, auth, what).await.map(drop)
}

/// [`ensure_may_sign`], returning the caller's row it read so the rest of a
/// signature (gate 4) uses the same one instead of reading it again.
pub(super) async fn ensure_may_sign_caller(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
) -> Result<CallerAcl, AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, what, "sign").await?;
    if entry_or_role_has(entry.as_ref(), auth, Capability::Sign) {
        return Ok(CallerAcl(entry));
    }
    Err(AppError::Forbidden(format!(
        "{what} denied: {} does not carry the sign capability",
        auth.did
    )))
}

/// The caller's own ACL row, read once per signature and shared by gate 0
/// ([`ensure_may_sign`]) and gate 4 ([`require_key_in_caller_scope`]).
///
/// Holding one means the read happened. There is no "not loaded yet" state for
/// a gate to mistake for "no row", which is the trap an
/// `Option<Option<AclEntry>>` sets: a caller passing `Some(None)` for a lookup
/// it skipped would silently pass gate 4. Inside, `None` is a caller with no
/// row, which gate 4 treats as nothing to narrow (see its docs).
#[derive(Debug)]
pub(super) struct CallerAcl(Option<vti_common::acl::AclEntry>);

impl CallerAcl {
    /// Read the caller's row. Read errors propagate: a gate that cannot see
    /// the row refuses rather than passes.
    pub(super) async fn read(acl_ks: &KeyspaceHandle, auth: &AuthClaims) -> Result<Self, AppError> {
        Ok(Self(
            vti_common::acl::get_acl_entry(acl_ks, &auth.did).await?,
        ))
    }
}

/// The key-creation gate: the caller must hold [`Capability::KeyMint`].
///
/// `key-mint` is the capability that gates "creating new keys within scope"
/// (VTI spec Appendix C.2), and VTI-ACL-030 makes the entry's effective set —
/// the role's ceiling narrowed by its own list — what decides. `keys/create`
/// used to check the admin *role* instead, at both of its surfaces (the Trust
/// Task handler and `POST /keys`), which was wrong in both directions: an
/// `initiator`, whose ceiling carries `KeyMint`, was refused (Keyring VTI-23 —
/// a least-privilege manager could not mint a persona's keys), and an admin
/// narrowed without `key-mint` was let through.
///
/// Here, in the operation, for the reason [`ensure_may_export`] gives: a
/// transport added later cannot be wired without it. `webvh/dids/create`
/// applies the same capability (`did_webvh::ensure_may_mint`); the context
/// check in [`create_key`] still bounds *where*, and key custody still refuses
/// a caller-chosen derivation path to anyone but a super-admin.
pub(crate) async fn ensure_may_mint_key(
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    what: &str,
) -> Result<(), AppError> {
    let entry = entry_for_capability_gate(acl_ks, auth, what, "key-mint").await?;
    if entry_or_role_has(entry.as_ref(), auth, Capability::KeyMint) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "{what} denied: {} does not carry the key-mint capability",
        auth.did
    )))
}

/// The command an operator runs so `did` may export.
///
/// Built from the caller's stored entry, because the right command depends on it:
///
/// - **no entry** — create one, as an admin of the context;
/// - **a non-admin with a context scope** — `change-role` to admin, which keeps the scope
///   (and, like any admin grant, confers the rest of what an admin of that context holds);
/// - **a non-admin with no context** — scope it first: promoting an entry with no contexts
///   would make it a *super*-admin, so that is never suggested;
/// - **an admin narrowed without `key-export`** — re-state the narrowing with `key-export`
///   added, rather than suggesting `--capabilities-all`, which would also undo whatever
///   else the narrowing deliberately removed.
pub(super) fn key_export_fix(entry: Option<&vti_common::acl::AclEntry>, did: &str) -> String {
    use vta_sdk::acl::ActScope;

    let Some(entry) = entry else {
        return format!(
            "Grant it with: pnm acl create --did {did} --role admin --contexts <CONTEXT>"
        );
    };
    if entry.role != crate::acl::Role::Admin {
        let promote = format!(
            "pnm acl change-role --did {did} --from {} --to admin",
            entry.role
        );
        let narrowed = restated_narrowing(entry);
        return match (entry.act_scope(), narrowed) {
            (ActScope::Contexts(_), None) => format!("Grant it with: {promote}"),
            (ActScope::Contexts(_), Some(caps)) => {
                format!("Grant it with: {promote} && pnm acl update {did} --capabilities {caps}")
            }
            // Authorized nowhere (or, defensively, anything else): scope first.
            _ => format!(
                "Scope it to the context first, then promote it: \
                 pnm acl update {did} --contexts <CONTEXT> && {promote}"
            ),
        };
    }
    match restated_narrowing(entry) {
        Some(caps) => format!("Grant it with: pnm acl update {did} --capabilities {caps}"),
        // An un-narrowed admin derives `KeyExport`, so reaching here means something other
        // than the narrowing withheld it — say what to look at rather than guess a command.
        None => format!("Inspect the entry with: pnm acl get {did}"),
    }
}

/// The entry's stored capability list with `key-export` added, as the comma-separated
/// value `pnm acl update --capabilities` takes — or `None` when the entry is not narrowed.
///
/// `--capabilities` *replaces* the list, so the command has to carry every name already
/// there; a bare `--capabilities key-export` would narrow an admin to that one power.
pub(super) fn restated_narrowing(entry: &vti_common::acl::AclEntry) -> Option<String> {
    if entry.capabilities.is_empty() {
        return None;
    }
    let name = |c: &Capability| {
        serde_json::to_value(c)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
    };
    let mut names: Vec<String> = entry.capabilities.iter().filter_map(name).collect();
    if let Some(key_export) = name(&Capability::KeyExport)
        && !names.contains(&key_export)
    {
        names.push(key_export);
    }
    Some(names.join(","))
}

/// Load the record `key_id` names **for a caller**, answering "absent" and
/// "not yours" identically.
///
/// A caller whose scope is restricted learns nothing about ids outside it: a
/// key that does not exist and a key in a context it cannot act in get the same
/// refusal, with a message that names neither the key's context nor whether it
/// exists. Only a super-admin — who can reach every key — is told a key is
/// absent. Without this, `keys/export-secret` and `keys/sign` were an existence
/// oracle for every key id in the VTA, and their "no access to context: X"
/// refusal also named the context the key lived in.
pub(crate) async fn load_record_in_caller_scope(
    keys_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
) -> Result<KeyRecord, AppError> {
    let out_of_reach =
        || AppError::Forbidden(format!("key `{key_id}` is not within the caller's scope"));
    let record: Option<KeyRecord> = keys_ks.get(keys::store_key(key_id)).await?;
    let Some(record) = record else {
        return Err(if auth.is_super_admin() {
            AppError::NotFound(format!("key {key_id} not found"))
        } else {
            out_of_reach()
        });
    };
    let reachable = match record.context_id.as_deref() {
        Some(ctx) => auth.has_context_access(ctx),
        None => auth.is_super_admin(),
    };
    if !reachable {
        return Err(out_of_reach());
    }
    Ok(record)
}

/// Whether `auth` may name `key_id` as [`sign_payload`] would let it — the key
/// is in the caller's scope, active, in a context the caller can act in, and
/// inside the caller's own key filter — without signing anything.
///
/// For an act whose entitlement is *control of a key* but which produces no
/// signature: founding a room's group (`rooms/owner/group/create`) is the same
/// gate as issuing the room's credentials, and burning a signature (and a
/// context's daily quota) only to prove the caller could have signed would be
/// a side effect with no purpose. The context policy's signing limit is not
/// consulted for the same reason: nothing is signed.
pub(crate) async fn require_key_nameable(
    keys_ks: &KeyspaceHandle,
    acl_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    key_id: &str,
) -> Result<KeyRecord, AppError> {
    let record = load_record_in_caller_scope(keys_ks, auth, key_id).await?;
    if record.status != KeyStatus::Active {
        return Err(AppError::Validation(format!("key `{key_id}` is revoked")));
    }
    if let Some(ref ctx) = record.context_id {
        auth.require_context(ctx)?;
        let caller = CallerAcl::read(acl_ks, auth).await?;
        require_key_in_caller_scope(&caller, key_id)?;
    }
    Ok(record)
}

/// Gate 4 of [`sign_payload`] (#818): the **actor-scoped** key filter.
///
/// Loads the caller's stored ACL row and asks its [`KeyScope`] whether
/// `key_id` is within the entry's `allowed_keys`. Complements the
/// resource-bound `ContextPolicy.signable_keys` (which binds every actor,
/// super-admin included); this one binds *this caller*, and only ever
/// narrows what the context gates already allowed.
///
/// Reads the store rather than the JWT deliberately: an operator narrowing
/// an entry's `allowed_keys` is a privilege reduction, and reading the row
/// live means the reduction binds the subject's **next** sign request — no
/// session revocation, no waiting out an access-token TTL (the trap the
/// VTC's `is_privilege_reduction` path exists to close for claims-borne
/// authority).
///
/// A caller with **no ACL row** passes: the only callers that reach here
/// without one are process-local synthesized identities (the offline CLI's
/// `cli:<channel>` sentinel), whose trust boundary is the OS, and a row
/// deleted mid-session — for whom this preserves today's behaviour exactly
/// (`None` on every existing row is byte-identical, and absence of a row
/// carries no `allowed_keys` to enforce). The decode goes through
/// [`AclEntry::key_scope`], never a bare emptiness test: `Some(∅)` means
/// authorized on **no** keys, the opposite of `None`.
///
/// [`KeyScope`]: vti_common::acl::KeyScope
/// [`AclEntry::key_scope`]: vti_common::acl::AclEntry::key_scope
///
/// `caller` is the row this signature read once (at gate 0 when it ran), so
/// both gates judge the same version of it.
pub(super) fn require_key_in_caller_scope(
    caller: &CallerAcl,
    key_id: &str,
) -> Result<(), AppError> {
    let Some(entry) = caller.0.as_ref() else {
        return Ok(());
    };
    if entry.key_scope().allows(key_id) {
        return Ok(());
    }
    Err(AppError::Forbidden(format!(
        "signing key {key_id} is not in the caller's allowed keys"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contexts::create_context;
    use crate::operations::keys::test_support::*;
    use vti_common::acl::Role;

    /// An `initiator` carries `key-mint`, so it creates a key in its own
    /// context. Before, `keys/create` demanded the admin role on both of its
    /// surfaces.
    #[tokio::test]
    async fn vti_23_an_initiator_holding_key_mint_creates_a_key_in_its_context() {
        let h = TestHarness::new().await;
        let auth = scoped_caller(&h, "did:key:zManager", Role::Initiator, vec![]).await;
        let key = create_as(&h, &auth, "test-ctx")
            .await
            .expect("an initiator derives key-mint");
        let record: KeyRecord = h
            .keys_ks
            .get(keys::store_key(&key.key_id))
            .await
            .unwrap()
            .expect("the key exists");
        assert_eq!(record.context_id.as_deref(), Some("test-ctx"));
    }

    /// `key-mint` decides whether; the context scope still decides where.
    #[tokio::test]
    async fn vti_23_key_mint_does_not_reach_outside_the_callers_context() {
        let h = TestHarness::new().await;
        create_context(&h.contexts_ks, "other-ctx", "Other")
            .await
            .expect("create context");
        let auth = scoped_caller(&h, "did:key:zManager", Role::Initiator, vec![]).await;
        let err = create_as(&h, &auth, "other-ctx")
            .await
            .expect_err("another context is out of reach");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    /// The entry is read: an admin narrowed without `key-mint` is refused — the
    /// role check let it through — and so is a role whose ceiling lacks it.
    #[tokio::test]
    async fn vti_23_key_create_is_refused_without_key_mint() {
        let h = TestHarness::new().await;
        let narrowed = scoped_caller(
            &h,
            "did:key:zNarrowedAdmin",
            Role::Admin,
            vec![Capability::Sign],
        )
        .await;
        let reader = scoped_caller(&h, "did:key:zReader", Role::Reader, vec![]).await;
        for auth in [narrowed, reader] {
            let err = create_as(&h, &auth, "test-ctx")
                .await
                .expect_err("no key-mint, no key");
            assert!(
                matches!(&err, AppError::Forbidden(m) if m.contains("key-mint")),
                "{}: {err:?}",
                auth.did
            );
        }
    }

    /// A caller holding `key-export` — an admin of the key's context — takes a
    /// key from its context over an end-to-end channel.
    #[tokio::test]
    async fn vti_23_a_holder_of_key_export_exports_a_key_in_its_context() {
        let h = TestHarness::new().await;
        let record = mint_derived(&h, "k-persona").await;
        let auth = scoped_caller(&h, "did:key:zCtxAdmin", Role::Admin, vec![]).await;
        let out = export(
            &h,
            &h.audit,
            &auth,
            "k-persona",
            ExportChannel::EndToEnd("didcomm"),
        )
        .await
        .expect("an admin of the key's context holds key-export");
        assert_eq!(out.key_id, record.key_id);
    }

    /// An `initiator` holds `sign` and not `key-export`, so it is refused on
    /// every channel, at the gate, naming the capability rather than a role.
    #[tokio::test]
    async fn vti_23_an_initiator_is_refused_export_at_the_key_export_gate() {
        let h = TestHarness::new().await;
        mint_derived(&h, "k-persona").await;
        let auth = scoped_caller(&h, "did:key:zManager", Role::Initiator, vec![]).await;
        for channel in every_channel() {
            let err = export(&h, &h.audit, &auth, "k-persona", channel)
                .await
                .expect_err("an initiator does not carry key-export");
            assert!(
                matches!(&err, AppError::Forbidden(m)
                    if m.contains("key-export") && !m.contains("admin role required")),
                "{channel:?}: {err:?}"
            );
        }
    }
}
