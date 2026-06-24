//! Key + seed management methods on [`VtaClient`].

use super::{
    CreateKeyRequest, CreateKeyResponse, GetKeySecretResponse, ImportKeyRequest, ImportKeyResponse,
    InvalidateKeyResponse, ListKeysResponse, ListSeedsResponse, RenameKeyRequest,
    RenameKeyResponse, RotateSeedRequest, RotateSeedResponse, SignResponse, Transport, VtaClient,
    WrappingKeyResponse, encode_path_segment,
};
use crate::error::VtaError;
use crate::keys::{KeyRecord, KeyType};
use crate::protocols::key_management::derive_and_sign::DeriveAndSignResultBody;
use crate::protocols::key_management::derive_and_sign_document::DeriveAndSignDocumentResultBody;
use crate::protocols::key_management::sign::SignAlgorithm;
use crate::trust_tasks;

#[cfg(feature = "client")]
use crate::protocols::{key_management, seed_management};

#[cfg(feature = "client")]
impl VtaClient {
    // ── Key methods ─────────────────────────────────────────────────

    pub async fn create_key(&self, req: CreateKeyRequest) -> Result<CreateKeyResponse, VtaError> {
        self.rpc(
            key_management::CREATE_KEY,
            serde_json::json!({
                "key_type": serde_json::to_value(&req.key_type)?,
                "derivation_path": req.derivation_path.as_deref().unwrap_or_default(),
                "mnemonic": req.mnemonic.as_deref(),
                "label": req.label.as_deref(),
                "context_id": req.context_id.as_deref(),
            }),
            key_management::CREATE_KEY_RESULT,
            30,
            |c, url| c.post(format!("{url}/keys")).json(&req),
        )
        .await
    }

    pub async fn list_keys(
        &self,
        offset: u64,
        limit: u64,
        status: Option<&str>,
        context_id: Option<&str>,
    ) -> Result<ListKeysResponse, VtaError> {
        self.rpc(
            key_management::LIST_KEYS,
            serde_json::json!({
                "offset": offset,
                "limit": limit,
                "status": status,
                "context_id": context_id,
            }),
            key_management::LIST_KEYS_RESULT,
            30,
            |c, url| {
                let mut u = format!("{url}/keys?offset={offset}&limit={limit}");
                if let Some(s) = status {
                    u.push_str(&format!("&status={s}"));
                }
                if let Some(ctx) = context_id {
                    u.push_str(&format!("&context_id={ctx}"));
                }
                c.get(u)
            },
        )
        .await
    }

    pub async fn get_key(&self, key_id: &str) -> Result<KeyRecord, VtaError> {
        self.rpc(
            key_management::GET_KEY,
            serde_json::json!({ "key_id": key_id }),
            key_management::GET_KEY_RESULT,
            30,
            |c, url| c.get(format!("{url}/keys/{}", encode_path_segment(key_id))),
        )
        .await
    }

    pub async fn get_key_secret(&self, key_id: &str) -> Result<GetKeySecretResponse, VtaError> {
        self.rpc(
            key_management::GET_KEY_SECRET,
            serde_json::json!({ "key_id": key_id }),
            key_management::GET_KEY_SECRET_RESULT,
            30,
            |c, url| c.get(format!("{url}/keys/{}/secret", encode_path_segment(key_id))),
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
        self.rpc(
            key_management::SIGN_REQUEST,
            serde_json::json!({
                "key_id": key_id,
                "payload": payload_b64,
                "algorithm": algorithm,
            }),
            key_management::SIGN_RESULT,
            30,
            |c, url| {
                c.post(format!("{url}/keys/{}/sign", encode_path_segment(key_id)))
                    .json(&serde_json::json!({
                        "payload": payload_b64,
                        "algorithm": algorithm,
                    }))
            },
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
            "key_type": serde_json::to_value(&key_type)?,
            "derivation_path": derivation_path,
            "payload": payload_b64,
            "algorithm": algorithm,
        });
        self.rpc_tt(
            trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_1_0,
            body.clone(),
            30,
            move |c, url| c.post(format!("{url}/keys/derive-and-sign")).json(&body),
        )
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
        let body = serde_json::json!({
            "key_type": serde_json::to_value(&key_type)?,
            "derivation_path": derivation_path,
            "document": document,
            "proof_purpose": proof_purpose,
        });
        self.rpc_tt(
            trust_tasks::TASK_KEYS_DERIVE_AND_SIGN_DOCUMENT_1_0,
            body.clone(),
            30,
            move |c, url| {
                c.post(format!("{url}/keys/derive-and-sign-document"))
                    .json(&body)
            },
        )
        .await
    }

    pub async fn invalidate_key(&self, key_id: &str) -> Result<InvalidateKeyResponse, VtaError> {
        self.rpc(
            key_management::REVOKE_KEY,
            serde_json::json!({ "key_id": key_id }),
            key_management::REVOKE_KEY_RESULT,
            30,
            |c, url| c.delete(format!("{url}/keys/{}", encode_path_segment(key_id))),
        )
        .await
    }

    pub async fn rename_key(
        &self,
        key_id: &str,
        new_key_id: &str,
    ) -> Result<RenameKeyResponse, VtaError> {
        self.rpc(
            key_management::RENAME_KEY,
            serde_json::json!({ "key_id": key_id, "new_key_id": new_key_id }),
            key_management::RENAME_KEY_RESULT,
            30,
            |c, url| {
                c.patch(format!("{url}/keys/{}", encode_path_segment(key_id)))
                    .json(&RenameKeyRequest {
                        key_id: new_key_id.to_string(),
                    })
            },
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
        }
    }

    /// Import an externally-created private key into the VTA.
    pub async fn import_key(&self, req: ImportKeyRequest) -> Result<ImportKeyResponse, VtaError> {
        self.rpc(
            key_management::IMPORT_KEY,
            serde_json::to_value(&req)?,
            key_management::IMPORT_KEY_RESULT,
            30,
            |c, url| c.post(format!("{url}/keys/import")).json(&req),
        )
        .await
    }

    // ── Seed methods ────────────────────────────────────────────────

    pub async fn list_seeds(&self) -> Result<ListSeedsResponse, VtaError> {
        self.rpc(
            seed_management::LIST_SEEDS,
            serde_json::json!({}),
            seed_management::LIST_SEEDS_RESULT,
            30,
            |c, url| c.get(format!("{url}/keys/seeds")),
        )
        .await
    }

    pub async fn rotate_seed(
        &self,
        mnemonic: Option<String>,
    ) -> Result<RotateSeedResponse, VtaError> {
        let body = RotateSeedRequest {
            mnemonic: mnemonic.clone(),
        };
        self.rpc(
            seed_management::ROTATE_SEED,
            serde_json::json!({ "mnemonic": mnemonic }),
            seed_management::ROTATE_SEED_RESULT,
            30,
            |c, url| c.post(format!("{url}/keys/seeds/rotate")).json(&body),
        )
        .await
    }
}
