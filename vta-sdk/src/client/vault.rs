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
    pub async fn vault_delete(
        &self,
        id: &str,
        expected_version: Option<u32>,
    ) -> Result<Value, VtaError> {
        let mut payload = json!({ "id": id });
        if let Some(v) = expected_version {
            payload["expectedVersion"] = json!(v);
        }
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_DELETE_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
    }

    /// `vault/release/0.1` — release a secret sealed to the caller. Requires the
    /// `FillRelease` capability. The response carries a `didcomm-authcrypt`
    /// `jwe`; open it with [`Self::open_sealed_secret`]. `payload` is the wire
    /// request (entry `id` + optional `target`).
    pub async fn vault_release(&self, payload: Value) -> Result<Value, VtaError> {
        self.dispatch_trust_task(
            trust_tasks::TASK_VAULT_RELEASE_0_1,
            payload,
            VAULT_TT_TIMEOUT,
        )
        .await
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
}
