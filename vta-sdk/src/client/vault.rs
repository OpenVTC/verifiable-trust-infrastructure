//! `vault/*` Trust Task client methods.
//!
//! Drives the `vault/*` slice through the generic trust-task dispatcher
//! ([`VtaClient::dispatch_trust_task`]) — there is no dedicated REST route.
//! Powers the `pnm vault …` CLI and the agent-runtime SDK.
//!
//! Secret-bearing payloads use `didcomm-authcrypt` sealed envelopes:
//! - `vault_upsert` takes an already-sealed `sealedSecret` object (build it with
//!   [`VtaClient::seal_vault_secret`]); this method only attaches it.
//! - `vault_release` / `vault_get` return a response carrying a sealed `jwe` —
//!   open it with [`VtaClient::open_sealed_secret`].
//!
//! Keeping the seal/open out of these methods lets this module compile without
//! the `session` feature; the crypto lives in the DIDComm-only helpers.
//!
//! `#[allow(deprecated)]`: the dispatcher routes the canonical `0.1` URIs (see
//! `vta-service::trust_tasks::dispatch_table!`), which are marked deprecated in
//! favour of `0.2` — but `0.1` is what the VTA dispatches.
#![allow(deprecated)]

use serde_json::{Value, json};

use super::VtaClient;
use crate::error::VtaError;
use crate::trust_tasks;

/// Round-trip timeout (seconds) for vault trust tasks.
const VAULT_TT_TIMEOUT: u64 = 30;

impl VtaClient {
    /// `vault/list/0.1` — list vault-entry metadata (no secrets). Requires the
    /// `VaultRead` capability. `filters` is the wire filter object (`{}` for
    /// all).
    pub async fn vault_list(&self, filters: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(trust_tasks::TASK_VAULT_LIST_0_1, filters, VAULT_TT_TIMEOUT)
            .await
    }

    /// `vault/get/0.1` — fetch a single entry's metadata by id (no secret;
    /// release the secret with [`Self::vault_release`]). Requires `VaultRead`.
    pub async fn vault_get(&self, id: &str) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_GET_0_1,
            json!({ "id": id }),
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/upsert/0.1` — create or update an entry. Requires `VaultWrite`.
    /// `payload` carries the entry fields (`contextId`, `targets`, `label`,
    /// `secretKind`, …); `sealed_secret`, when present, is the
    /// `{ "envelope": "didcomm-authcrypt", "jwe": … }` object produced by
    /// sealing the cleartext secret (see [`Self::seal_vault_secret`]).
    pub async fn vault_upsert(
        &self,
        mut payload: Value,
        sealed_secret: Option<Value>,
    ) -> Result<Value, VtaError> {
        if let Some(env) = sealed_secret
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("sealedSecret".to_string(), env);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_UPSERT_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/delete/0.1` — delete an entry by id. Requires `VaultWrite`.
    /// `expected_version` enables optimistic-concurrency (reject on mismatch).
    ///
    /// Default (`force == false`) is a **recoverable** soft delete: the entry
    /// becomes a `Deleted` tombstone, restorable via [`Self::vault_restore`]
    /// until the sweeper purges it at the returned `graceUntil`. `force ==
    /// true` **hard-deletes immediately** (no recovery) — equivalent to
    /// [`Self::vault_purge`]. `reason` is recorded in the audit trail.
    /// `vault/upsert/0.1` from a typed body — the checked alternative to
    /// [`Self::vault_upsert`].
    ///
    /// Additive on purpose. `vault_upsert` takes the whole payload as a `Value`
    /// and stays exactly as it was: changing its signature would break every
    /// caller for a benefit they can opt into instead. This one names the
    /// members that exist today and carries an escape hatch for the rest, so a
    /// caller is never blocked on an SDK release to use a new one.
    ///
    /// `sealed_secret` is inserted here rather than taken on the body, because
    /// sealing needs the client's HPKE context and not the caller's.
    pub async fn vault_upsert_typed(
        &self,
        body: crate::protocols::vault_management::VaultUpsertBody,
        sealed_secret: Option<Value>,
    ) -> Result<Value, VtaError> {
        let mut payload = serde_json::to_value(body)?;
        if let Some(env) = sealed_secret
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("sealedSecret".to_string(), env);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_UPSERT_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    pub async fn vault_delete(
        &self,
        id: &str,
        expected_version: Option<u32>,
        force: bool,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        let payload = serde_json::to_value(crate::protocols::vault_management::VaultDeleteBody {
            id: id.to_string(),
            force,
            expected_version,
            reason: reason.map(str::to_string),
        })?;
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_DELETE_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/archive/0.1` — soft-disable an entry (hidden from default list,
    /// refused for use, restorable). Requires `VaultWrite`.
    pub async fn vault_archive(
        &self,
        id: &str,
        expected_version: Option<u32>,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.vault_lifecycle(
            trust_tasks::TASK_VAULT_ARCHIVE_0_1,
            id,
            expected_version,
            reason,
        )
        .await
    }

    /// `vault/unarchive/0.1` — return an archived entry to active. Requires
    /// `VaultWrite`.
    pub async fn vault_unarchive(
        &self,
        id: &str,
        expected_version: Option<u32>,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.vault_lifecycle(
            trust_tasks::TASK_VAULT_UNARCHIVE_0_1,
            id,
            expected_version,
            reason,
        )
        .await
    }

    /// `vault/restore/0.1` — undelete a soft-deleted entry (only within the
    /// grace window). Requires `VaultWrite`.
    pub async fn vault_restore(
        &self,
        id: &str,
        expected_version: Option<u32>,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.vault_lifecycle(
            trust_tasks::TASK_VAULT_RESTORE_0_1,
            id,
            expected_version,
            reason,
        )
        .await
    }

    /// `vault/purge/0.1` — irreversibly hard-delete an entry, skipping the
    /// grace window. Requires `VaultWrite`.
    pub async fn vault_purge(
        &self,
        id: &str,
        expected_version: Option<u32>,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.vault_lifecycle(
            trust_tasks::TASK_VAULT_PURGE_0_1,
            id,
            expected_version,
            reason,
        )
        .await
    }

    /// Shared body for the password-vault archival lifecycle verbs.
    async fn vault_lifecycle(
        &self,
        task: &str,
        id: &str,
        expected_version: Option<u32>,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "id": id });
        if let Some(v) = expected_version {
            payload["expectedVersion"] = json!(v);
        }
        if let Some(r) = reason {
            payload["reason"] = json!(r);
        }
        self.dispatch_trust_task(task, payload, VAULT_TT_TIMEOUT)
            .await
    }

    /// `vault/release/0.1` — release a secret sealed to the caller. Requires the
    /// `FillRelease` capability. The response carries a `didcomm-authcrypt`
    /// `jwe`; open it with [`Self::open_sealed_secret`]. `payload` is the wire
    /// request (`entryId` + optional `target`).
    ///
    /// Prefer [`Self::vault_release_entry`] — it builds the body for you, so the
    /// member name can't drift out of the schema.
    pub async fn vault_release(&self, payload: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_RELEASE_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/release/0.1` for the common case — release entry `entry_id`,
    /// optionally scoped to `target`.
    ///
    /// The typed front door to [`Self::vault_release`]. That method takes an
    /// opaque `Value`, so every caller re-derives the member names from prose
    /// and a wrong one is invisible to the compiler — which is exactly how both
    /// the CLI and the MCP bridge came to send `id` instead of `entryId`
    /// (VTI #947), a payload the VTA can only reject as `malformedRequest`.
    pub async fn vault_release_entry(
        &self,
        entry_id: &str,
        target: Option<Value>,
    ) -> Result<Value, VtaError> {
        self.vault_release(Self::vault_release_body(entry_id, target))
            .await
    }

    /// The wire body [`Self::vault_release_entry`] sends. Split out so it can be
    /// asserted against the published `vault/release/0.1` schema without a live
    /// transport — see this module's tests.
    pub fn vault_release_body(entry_id: &str, target: Option<Value>) -> Value {
        let mut payload = json!({ "entryId": entry_id });
        if let Some(t) = target {
            payload["target"] = t;
        }
        payload
    }

    /// `vault/proxy-login/0.1` — mint a session as the entry's principal.
    /// Requires the `ProxyLogin` capability. `payload` is the wire request.
    pub async fn vault_proxy_login(&self, payload: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/sign-trust-task/0.1` — sign a Trust Task envelope as the entry's
    /// principal DID. Requires the `SignTrustTask` capability. `payload` is the
    /// wire request (entry id + the envelope to sign).
    pub async fn vault_sign_trust_task(&self, payload: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_SIGN_TRUST_TASK_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    // ── Credential vault (the holder's held W3C credentials) ──────────────
    //
    // Distinct from the password-manager vault methods above: these drive the
    // `vault/credentials/*` slice that stores + retrieves credentials a holder
    // *holds* (invitations, memberships, …). A credential body is a presentable
    // VC, not a raw secret, so these carry plain JSON — no sealed envelope.

    /// `vault/credentials/receive/0.1` — verify + store a received credential
    /// (e.g. an invitation). Requires `VaultWrite`. `credential` is the VC JSON;
    /// `id` overrides the storage id (defaults to the VC's `id`). Returns the
    /// stored credential's descriptor (`{ id, types, purpose, status }`).
    pub async fn cred_vault_receive(
        &self,
        credential: Value,
        id: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "credential": credential });
        if let Some(id) = id
            && let Some(obj) = payload.as_object_mut()
        {
            obj.insert("id".to_string(), json!(id));
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_CREDENTIALS_RECEIVE_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/credentials/query/0.1` — filtered search over held credentials.
    /// Requires `VaultRead`. `filter` is a DCQL-shaped object (at least one of
    /// `type`, `communityDid`, `issuerDid`, `purpose`, `status`); an unfiltered
    /// query is refused. Returns `{ credentials: [descriptor] }`.
    ///
    /// By default only active credentials are returned. Two optional modifier
    /// keys opt into the archival lifecycle for management UX (they are *not*
    /// filters, so at least one real filter is still required):
    /// `includeArchived` and `includeDeleted` (booleans, default `false`).
    /// When set, archived / soft-deleted rows matching the filter are also
    /// returned; each descriptor then carries `lifecycle`
    /// (`active` | `archived` | `deleted`) alongside the existing validity
    /// `status`, plus `archivedAt` / `deletedAt` / `graceUntil` as applicable.
    pub async fn cred_vault_query(&self, filter: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_CREDENTIALS_QUERY_0_1,
            filter,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/credentials/get/0.1` — fetch one held credential's full body by
    /// id, for presentation. Requires `VaultRead`. Returns `{ credential }`.
    pub async fn cred_vault_get(&self, id: &str) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_CREDENTIALS_GET_0_1,
            json!({ "id": id }),
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/credentials/archive/0.1` — soft-disable a held credential
    /// (hidden from query, refused for presentation, restorable). Requires
    /// `CredentialWrite`.
    pub async fn cred_vault_archive(
        &self,
        id: &str,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.cred_lifecycle(
            trust_tasks::TASK_VAULT_CREDENTIALS_ARCHIVE_0_1,
            id,
            false,
            reason,
        )
        .await
    }

    /// `vault/credentials/unarchive/0.1` — return an archived credential to
    /// active. Requires `CredentialWrite`.
    pub async fn cred_vault_unarchive(
        &self,
        id: &str,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.cred_lifecycle(
            trust_tasks::TASK_VAULT_CREDENTIALS_UNARCHIVE_0_1,
            id,
            false,
            reason,
        )
        .await
    }

    /// `vault/credentials/delete/0.1` — soft-delete a held credential
    /// (recoverable tombstone). `force == true` hard-deletes immediately.
    /// Requires `CredentialWrite`.
    pub async fn cred_vault_delete(
        &self,
        id: &str,
        force: bool,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.cred_lifecycle(
            trust_tasks::TASK_VAULT_CREDENTIALS_DELETE_0_1,
            id,
            force,
            reason,
        )
        .await
    }

    /// `vault/credentials/restore/0.1` — undelete a soft-deleted credential
    /// (only within the grace window). Requires `CredentialWrite`.
    pub async fn cred_vault_restore(
        &self,
        id: &str,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.cred_lifecycle(
            trust_tasks::TASK_VAULT_CREDENTIALS_RESTORE_0_1,
            id,
            false,
            reason,
        )
        .await
    }

    /// `vault/credentials/purge/0.1` — irreversibly hard-delete a held
    /// credential and its index rows. Requires `CredentialWrite`.
    pub async fn cred_vault_purge(
        &self,
        id: &str,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        self.cred_lifecycle(
            trust_tasks::TASK_VAULT_CREDENTIALS_PURGE_0_1,
            id,
            false,
            reason,
        )
        .await
    }

    /// Shared body for the credential archival lifecycle verbs. `force` is
    /// meaningful only for `delete`.
    async fn cred_lifecycle(
        &self,
        task: &str,
        id: &str,
        force: bool,
        reason: Option<&str>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "id": id, "force": force });
        if let Some(r) = reason {
            payload["reason"] = json!(r);
        }
        self.dispatch_trust_task(task, payload, VAULT_TT_TIMEOUT)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published schema is the oracle, not a literal we typed twice: it is
    /// `additionalProperties: false` with `entryId` required, so it rejects both
    /// halves of the #947 defect — the missing member and the stray `id`.
    fn assert_conforms(payload: &Value) {
        let schema = trust_tasks_rs::schema_index::schema_for(trust_tasks::TASK_VAULT_RELEASE_0_1)
            .expect("vault/release/0.1 must have a published schema");
        trust_tasks_rs::validate::against_schema(schema, payload)
            .expect("payload must conform to vault/release/0.1");
    }

    #[test]
    fn release_body_uses_entry_id_not_id() {
        let payload = VtaClient::vault_release_body("entry-1", None);
        assert_eq!(payload["entryId"], json!("entry-1"));
        assert!(
            payload.get("id").is_none(),
            "`id` is not a member of vault/release/0.1 — the VTA reads `entryId`"
        );
        assert_conforms(&payload);
    }

    #[test]
    fn release_body_with_target_conforms() {
        let payload = VtaClient::vault_release_body(
            "entry-1",
            Some(json!({ "kind": "web-origin", "origin": "https://example.com" })),
        );
        assert_eq!(payload["target"]["kind"], json!("web-origin"));
        assert_conforms(&payload);
    }

    /// Guards the check itself: if the schema ever stopped rejecting unknown
    /// members, the two tests above would pass on a body the VTA refuses.
    #[test]
    fn release_body_shaped_the_old_way_is_rejected() {
        let schema = trust_tasks_rs::schema_index::schema_for(trust_tasks::TASK_VAULT_RELEASE_0_1)
            .expect("vault/release/0.1 must have a published schema");
        assert!(
            trust_tasks_rs::validate::against_schema(schema, &json!({ "id": "entry-1" })).is_err(),
            "the pre-#947 body must not validate"
        );
    }
}
