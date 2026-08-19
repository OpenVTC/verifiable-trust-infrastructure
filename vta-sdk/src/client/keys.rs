//! Key + seed management methods on [`VtaClient`].

use super::{
    CreateKeyRequest, CreateKeyResponse, GetKeySecretResponse, ImportKeyRequest, ImportKeyResponse,
    InvalidateKeyResponse, ListKeysResponse, ListSeedsResponse, RenameKeyResponse,
    RotateSeedRequest, RotateSeedResponse, SignResponse, Transport, VtaClient, WrappingKeyResponse,
};
use crate::error::VtaError;
use crate::keys::{KeyRecord, KeyType};
use crate::protocols::key_management::derive_and_sign::DeriveAndSignResultBody;
use crate::protocols::key_management::derive_and_sign_document::DeriveAndSignDocumentResultBody;
use crate::protocols::key_management::sign::SignAlgorithm;
use crate::trust_tasks;

#[cfg(feature = "client")]
impl VtaClient {
    // ── Key methods ─────────────────────────────────────────────────

    /// Create a key.
    ///
    /// Trust-task leg note: `spec/vta/keys/create/1.0` auto-generates the
    /// key id from the derivation path, so an explicit `req.key_id` only
    /// takes effect on the REST leg — exactly as it did on the legacy
    /// DIDComm message, which never carried `key_id` either.
    pub async fn create_key(&self, req: CreateKeyRequest) -> Result<CreateKeyResponse, VtaError> {
        // Built from the canonical body rather than a hand-rolled map: the map
        // spelled its members snake_case and carried `mnemonic` before the
        // registry had a member for it, so it was one rename away from
        // silently dropping the create-from-a-phrase path (see #884's
        // `update_acl`, the same failure with different members).
        let body = crate::protocols::key_management::create::CreateKeyBody {
            internal: None,
            key_type: req.key_type.clone(),
            derivation_path: req.derivation_path.clone().unwrap_or_default(),
            mnemonic: req.mnemonic.clone(),
            label: req.label.clone(),
            context_id: req.context_id.clone(),
        };
        let wrapped: crate::protocols::key_management::create::CreateKeyResponseBody = self
            .rpc_tt(
                trust_tasks::TASK_KEYS_CREATE_0_1,
                serde_json::to_value(&body)?,
                30,
            )
            .await?;
        let key = wrapped.key;
        Ok(CreateKeyResponse {
            origin: key.origin,
            key_id: key.key_id,
            key_type: key.key_type,
            derivation_path: key.derivation_path,
            public_key: key.public_key,
            status: key.status,
            label: key.label,
            created_at: key.created_at,
        })
    }

    /// Import an externally-created private key.
    ///
    /// Canonical `keys/import/0.1` on **every** transport. The carrier is a
    /// confidentiality decision the VTA enforces rather than a formatting one:
    /// `private_key_sealed` and `private_key_jwe` encrypt to the VTA and are
    /// accepted anywhere, while the cleartext `private_key_multibase` is
    /// accepted only where the transport is confidential end-to-end — DIDComm
    /// and TSP — and refused over REST, whose TLS terminates wherever the
    /// operator terminates it.
    ///
    /// The multibase carrier used to fork onto the legacy
    /// `key-management/1.0/import-key` message here. That was dead: the VTA has
    /// never routed that type, so the call failed with `unsupported message
    /// type` on DIDComm and was refused outright on REST. It works now.
    pub async fn import_key(&self, req: ImportKeyRequest) -> Result<ImportKeyResponse, VtaError> {
        let body = crate::protocols::key_management::import::ImportKeyBody {
            key_type: req.key_type.clone(),
            private_key_sealed: req.private_key_sealed.clone(),
            private_key_jwe: req.private_key_jwe.clone(),
            private_key_multibase: req.private_key_multibase.clone(),
            label: req.label.clone(),
            context_id: req.context_id.clone(),
        };
        let wrapped: crate::protocols::key_management::create::CreateKeyResponseBody = self
            .rpc_tt(
                trust_tasks::TASK_KEYS_IMPORT_0_1,
                serde_json::to_value(&body)?,
                30,
            )
            .await?;
        Ok(ImportKeyResponse {
            key_id: wrapped.key.key_id,
            key_type: wrapped.key.key_type,
            public_key: wrapped.key.public_key,
            status: wrapped.key.status,
            label: wrapped.key.label,
            origin: wrapped.key.origin,
            created_at: wrapped.key.created_at,
        })
    }

    pub async fn list_keys(
        &self,
        offset: u64,
        limit: u64,
        status: Option<&str>,
        context_id: Option<&str>,
    ) -> Result<ListKeysResponse, VtaError> {
        self.rpc_tt(
            trust_tasks::TASK_KEYS_LIST_0_1,
            serde_json::to_value(crate::protocols::key_management::list::ListKeysBody {
                offset: Some(offset),
                limit: Some(limit),
                status: status
                    .map(str::to_string)
                    .and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok()),
                context_id: context_id.map(str::to_string),
            })?,
            30,
        )
        .await
    }

    pub async fn get_key(&self, key_id: &str) -> Result<KeyRecord, VtaError> {
        // Canonical `keys/show/0.1` answers `{ key }`, with `key: null` for a
        // key the maintainer does not hold — a successful answer, not an error.
        // This method promises a record, so absence becomes `NotFound` here
        // rather than a decode failure the caller cannot interpret.
        let wrapped: crate::protocols::key_management::get::GetKeyResponseBody = self
            .rpc_tt(
                trust_tasks::TASK_KEYS_SHOW_0_1,
                serde_json::json!({ "keyId": key_id }),
                30,
            )
            .await?;
        wrapped
            .key
            .ok_or_else(|| VtaError::NotFound(format!("no key record for `{key_id}`")))
    }

    /// Export a key's secret material. The trust-task twin lives in the
    /// seeds slice (`spec/vta/seeds/export-mnemonic/1.0`) — same
    /// `{ key_id }` request and the same
    /// `operations::keys::get_key_secret` spine as the legacy message.
    pub async fn get_key_secret(&self, key_id: &str) -> Result<GetKeySecretResponse, VtaError> {
        self.rpc_tt(
            trust_tasks::TASK_SEEDS_EXPORT_MNEMONIC_1_0,
            serde_json::to_value(crate::protocols::key_management::secret::GetKeySecretBody {
                key_id: key_id.to_string(),
            })?,
            30,
        )
        .await
    }

    /// Sign a payload using a VTA-managed key.
    ///
    /// Sends the base64url-encoded payload to the VTA, which derives the key,
    /// signs in memory, and returns the signature. Key material never leaves VTA.
    pub async fn sign(
        &self,
        key_id: &str,
        payload: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<SignResponse, VtaError> {
        use base64::Engine;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        self.rpc_tt(
            trust_tasks::TASK_KEYS_SIGN_0_1,
            serde_json::json!({
                "keyId": key_id,
                "payload": payload_b64,
                "algorithm": algorithm,
            }),
            30,
        )
        .await
    }

    /// Ephemerally derive a key at `derivation_path` and sign `payload` —
    /// **without persisting a key record**. Admin-only on the VTA. Returns the
    /// derived public key + signature.
    ///
    /// This is how a client (e.g. a fleet manager whose fleet seed *is* this
    /// VTA's seed) acts as a derived child identity — e.g. a per-VTA super-admin
    /// at `m/26'/9'/<idx>'` — so the seed never leaves the VTA. REST:
    /// `POST /keys/derive-and-sign`; DIDComm: the `keys/derive-and-sign/1.0`
    /// trust task.
    pub async fn derive_and_sign(
        &self,
        key_type: KeyType,
        derivation_path: &str,
        payload: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<DeriveAndSignResultBody, VtaError> {
        use base64::Engine;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let body = serde_json::json!({
            "keyType": serde_json::to_value(&key_type)?,
            "derivationPath": derivation_path,
            "payload": payload_b64,
            "algorithm": algorithm,
        });
        self.rpc_tt(trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_0_1, body.clone(), 30)
            .await
    }

    /// Derive a key at `derivation_path` and attach an `eddsa-jcs-2022`
    /// Data-Integrity proof to `document`, signed **as the derived key** —
    /// persisting no key record. Admin-only. Returns the signer `did:key` + the
    /// signed document. This is how a fleet manager has its fleet VTA sign an
    /// auth document as a per-VTA super-admin without the seed leaving the VTA.
    pub async fn derive_and_sign_document(
        &self,
        key_type: KeyType,
        derivation_path: &str,
        document: serde_json::Value,
        proof_purpose: Option<&str>,
    ) -> Result<DeriveAndSignDocumentResultBody, VtaError> {
        // Built from the canonical body, not a hand-rolled map. The map spelled
        // `proofPurpose` unconditionally, so an unset purpose went on the wire
        // as `null` and `keys/derive-and-sign-document/0.1` — which types it
        // `"string"` — rejected the request. Omitting the member is what
        // selects the `assertionMethod` default, so the *documented* way to
        // call this was the one that could not work. Same defect as #919's
        // `keys/create`, and the same fix: let the body struct's
        // `skip_serializing_if` decide what reaches the wire.
        let body = serde_json::to_value(
            crate::protocols::key_management::derive_and_sign_document::DeriveAndSignDocumentBody {
                key_type,
                derivation_path: derivation_path.to_string(),
                document,
                proof_purpose: proof_purpose.map(str::to_string),
            },
        )?;
        self.rpc_tt(
            trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_DOCUMENT_0_1,
            body.clone(),
            30,
        )
        .await
    }

    pub async fn invalidate_key(&self, key_id: &str) -> Result<InvalidateKeyResponse, VtaError> {
        self.rpc_tt(
            trust_tasks::TASK_KEYS_REVOKE_0_1,
            serde_json::json!({ "keyId": key_id }),
            30,
        )
        .await
    }

    pub async fn rename_key(
        &self,
        key_id: &str,
        new_key_id: &str,
    ) -> Result<RenameKeyResponse, VtaError> {
        self.rpc_tt(
            trust_tasks::TASK_KEYS_RENAME_0_1,
            serde_json::json!({ "keyId": key_id, "newKeyId": new_key_id }),
            30,
        )
        .await
    }

    // ── Import key methods ──────────────────────────────────────────

    /// Fetch an ephemeral wrapping key for REST key import.
    pub async fn get_wrapping_key(&self) -> Result<WrappingKeyResponse, VtaError> {
        match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => {
                Self::ensure_token_valid(client, base_url, auth).await?;
                let token = auth.lock().await.token.clone();
                let req = client.get(format!("{base_url}/keys/import/wrapping-key"));
                let resp = Self::with_auth_token(req, &token).send().await?;
                Self::handle_response(resp).await
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => Err(VtaError::UnsupportedTransport(
                "wrapping key not needed for DIDComm transport".into(),
            )),
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => Err(VtaError::UnsupportedTransport(
                "wrapping key not needed for TSP transport".into(),
            )),
        }
    }

    // ── Seed methods ────────────────────────────────────────────────

    pub async fn list_seeds(&self) -> Result<ListSeedsResponse, VtaError> {
        self.rpc_tt(trust_tasks::TASK_SEEDS_LIST_1_0, serde_json::json!({}), 30)
            .await
    }

    pub async fn rotate_seed(
        &self,
        mnemonic: Option<String>,
    ) -> Result<RotateSeedResponse, VtaError> {
        let _body = RotateSeedRequest {
            mnemonic: mnemonic.clone(),
        };
        self.rpc_tt(
            trust_tasks::TASK_SEEDS_ROTATE_1_0,
            serde_json::json!({ "mnemonic": mnemonic }),
            30,
        )
        .await
    }
}
