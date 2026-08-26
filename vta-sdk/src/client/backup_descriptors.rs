//! Backup-descriptor-pattern client helpers.
//!
//! Drives the 3-phase ceremony end-to-end so the CLI can call a
//! single async method per operation. See
//! `docs/05-design-notes/backup-descriptor-pattern.md` for the
//! protocol.
//!
//! Three high-level methods:
//!
//! - [`VtaClient::backup_export_via_descriptor`] — initiate, GET
//!   the blob, optionally complete-export. Returns raw bytes.
//! - [`VtaClient::backup_import_via_descriptor`] — initiate, POST
//!   the blob, finalize-import. Returns the finalize result.
//! - [`VtaClient::backup_abort_bundle`] — cancel an in-flight
//!   bundle by id.
//!
//! Plus low-level building blocks if a caller wants the
//! pieces separately:
//!
//! - [`VtaClient::post_trust_task`] — POST a typed trust-task
//!   envelope to `/trust-tasks` and deserialize the response.
//! - [`VtaClient::download_blob`] / [`VtaClient::upload_blob`] —
//!   raw byte transport against the descriptor's
//!   `transport_url`, carrying the `X-Backup-Token` header.
//!
//! REST-only: the descriptor pattern doesn't have a DIDComm path.
//! DIDComm clients fall back to the legacy `/backup/{export,import}`
//! routes via [`VtaClient::backup_export`] +
//! [`VtaClient::backup_import`].

use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::Transport;
use super::VtaClient;
use crate::error::VtaError;
use crate::protocols::backup_management::descriptors::{
    AbortBundleBody, AbortBundleResultBody, CompleteExportBody, CompleteExportResultBody,
    FinalizeImportBody, FinalizeImportResultBody, InitiateExportBody, InitiateExportResultBody,
    InitiateImportBody, InitiateImportResultBody,
};

/// HTTP header carrying the bundle's bearer token. Mirrors the
/// VTA-side constant in `vta-service::routes::backup_blob`.
const TOKEN_HEADER: &str = "X-Backup-Token";

impl VtaClient {
    // ─── High-level: full ceremony ──────────────────────────────────────

    /// Drive a full export ceremony — initiate, download bytes,
    /// optionally complete-export. Returns the encrypted `.vtabak`
    /// bytes ready for `std::fs::write` or further processing.
    ///
    /// REST-only. DIDComm callers should use
    /// [`Self::backup_export`] (legacy inline path) until a future
    /// release adds a DIDComm transport for the blob endpoint.
    pub async fn backup_export_via_descriptor(
        &self,
        password: &str,
        include_audit: bool,
    ) -> Result<Vec<u8>, VtaError> {
        let req = InitiateExportBody {
            password: password.to_string(),
            include_audit,
            algorithm: "stream".into(),
        };
        let result: InitiateExportResultBody = self
            .post_trust_task(crate::trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_0, req)
            .await?;

        // Download the bytes from the descriptor's transport URL.
        let bytes = self
            .download_blob(
                &result.descriptor.transport_url,
                &result.descriptor.transport_token,
            )
            .await?;

        // Wire-level integrity check independent of the encrypted
        // envelope's internal MAC. The VTA stages the bytes pre-hashed
        // and refuses on mismatch at the blob endpoint, so this is
        // mostly a defence-in-depth check the operator's CLI can
        // surface as a clear error rather than a silent corruption.
        let actual = sha256_hex(&bytes);
        if actual != result.descriptor.expected_sha256 {
            return Err(VtaError::Protocol(format!(
                "downloaded backup hash mismatch: expected {} got {}",
                result.descriptor.expected_sha256, actual
            )));
        }
        if bytes.len() as u64 != result.descriptor.expected_size_bytes {
            return Err(VtaError::Protocol(format!(
                "downloaded backup size mismatch: expected {} got {}",
                result.descriptor.expected_size_bytes,
                bytes.len()
            )));
        }

        // Best-effort complete-export ack. Closes the audit loop
        // (record transitions ExportDownloaded → ExportAcked). A
        // failure here is non-fatal — the bytes are already in
        // hand. Logged but not propagated.
        let ack_req = CompleteExportBody {
            bundle_id: result.descriptor.bundle_id.clone(),
        };
        let _: Result<CompleteExportResultBody, VtaError> = self
            .post_trust_task(crate::trust_tasks::TASK_BACKUP_COMPLETE_EXPORT_1_0, ack_req)
            .await;

        Ok(bytes)
    }

    /// Drive a full import ceremony — initiate, upload bytes,
    /// finalize. Returns the finalize result with status `"preview"`
    /// or `"committed"` and the per-table counts.
    ///
    /// `bytes` is the operator's `.vtabak` content as read from disk
    /// (the JSON-serialised `BackupEnvelope`). The VTA's wire-level
    /// integrity check uses the bytes as-is — the caller should not
    /// re-encode.
    pub async fn backup_import_via_descriptor(
        &self,
        bytes: &[u8],
        password: &str,
        confirm: bool,
    ) -> Result<FinalizeImportResultBody, VtaError> {
        let expected_sha256 = sha256_hex(bytes);
        let init_req = InitiateImportBody {
            expected_sha256,
            expected_size_bytes: bytes.len() as u64,
            algorithm: "stream".into(),
        };
        let result: InitiateImportResultBody = self
            .post_trust_task(
                crate::trust_tasks::TASK_BACKUP_INITIATE_IMPORT_1_0,
                init_req,
            )
            .await?;

        self.upload_blob(
            &result.descriptor.transport_url,
            &result.descriptor.transport_token,
            bytes,
        )
        .await?;

        let finalize_req = FinalizeImportBody {
            bundle_id: result.descriptor.bundle_id.clone(),
            password: password.to_string(),
            confirm,
        };
        self.post_trust_task(
            crate::trust_tasks::TASK_BACKUP_FINALIZE_IMPORT_1_0,
            finalize_req,
        )
        .await
    }

    /// Cancel an in-flight bundle by id. Idempotent on terminal
    /// states (returns `aborted: false` instead of erroring).
    pub async fn backup_abort_bundle(
        &self,
        bundle_id: &str,
    ) -> Result<AbortBundleResultBody, VtaError> {
        let req = AbortBundleBody {
            bundle_id: bundle_id.to_string(),
        };
        self.post_trust_task(crate::trust_tasks::TASK_BACKUP_ABORT_1_0, req)
            .await
    }

    // ─── Low-level: building blocks ─────────────────────────────────────

    /// POST a typed trust-task envelope to `/trust-tasks` and
    /// deserialise the response payload as `R`. Used by the descriptor
    /// flows above; exposed in case external integrators want to
    /// drive the slice manually.
    pub async fn post_trust_task<B, R>(
        &self,
        type_uri: &'static str,
        payload: B,
    ) -> Result<R, VtaError>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        let (client, base_url, auth) = match &self.transport {
            Transport::Rest {
                client,
                base_url,
                auth,
            } => (client, base_url, auth),
            #[cfg(feature = "tsp")]
            Transport::Tsp { .. } => {
                return Err(VtaError::Validation(
                    "backup descriptor pattern is REST-only; \
                     this client is on TSP transport"
                        .into(),
                ));
            }
            #[cfg(feature = "session")]
            Transport::DIDComm { .. } => {
                return Err(VtaError::Validation(
                    "backup descriptor pattern is REST-only; \
                     this client is on DIDComm transport"
                        .into(),
                ));
            }
        };
        Self::ensure_token_valid(client, base_url, auth).await?;
        let token = auth.lock().await.token.clone();

        // Construct the envelope as raw JSON to avoid making
        // `trust-tasks-rs` a runtime dep of every SDK consumer
        // (it's a dev-dep here for the URI-parsing test only;
        // pulling it into the regular dep tree would balloon the
        // CLI's transitive deps with a framework crate the SDK
        // only needs for one round-trip-shape contract). The wire
        // shape is just `{ id, type, payload }` — see
        // `docs/05-design-notes/trust-task-uri-registry.md`.
        let payload_value = serde_json::to_value(&payload)?;
        let doc = serde_json::json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload_value,
        });

        // `<base>/trust-tasks` — the same contract `rpc_tt` uses. This is a
        // second hand-built call site rather than a shared helper, which is
        // exactly why it carried the legacy prefix after the shared one moved.
        let url = format!("{}/trust-tasks", base_url);
        let req = client.post(url).json(&doc);
        let resp = Self::with_auth_token(req, &token).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtaError::from_http(status, body));
        }
        // Framework responses are themselves trust-task envelopes.
        // Walk to the `payload` field and deserialize as `R`.
        let response_doc: serde_json::Value = resp.json().await?;
        let payload = response_doc
            .get("payload")
            .ok_or_else(|| {
                VtaError::Protocol("trust-task response missing `payload` field".into())
            })?
            .clone();
        Ok(serde_json::from_value(payload)?)
    }

    /// GET the blob bytes for an export bundle. Carries the
    /// `X-Backup-Token` header; the VTA validates token + state
    /// machine + TTL server-side.
    pub async fn download_blob(
        &self,
        transport_url: &str,
        transport_token: &str,
    ) -> Result<Vec<u8>, VtaError> {
        let client = match &self.transport {
            Transport::Rest { client, .. } => client,
            #[cfg(feature = "session")]
            Transport::DIDComm { rest_client, .. } => rest_client.as_ref().ok_or_else(|| {
                VtaError::Validation(
                    "DIDComm transport has no REST client for blob download".into(),
                )
            })?,
            #[cfg(feature = "tsp")]
            Transport::Tsp { rest_client, .. } => rest_client.as_ref().ok_or_else(|| {
                VtaError::Validation("TSP transport has no REST client for blob download".into())
            })?,
        };
        let resp = client
            .get(transport_url)
            .header(TOKEN_HEADER, transport_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtaError::from_http(status, body));
        }
        Ok(resp.bytes().await?.to_vec())
    }

    /// POST blob bytes for an import bundle. Carries the
    /// `X-Backup-Token` header; the VTA validates token + state
    /// machine + TTL + size + SHA-256 server-side.
    pub async fn upload_blob(
        &self,
        transport_url: &str,
        transport_token: &str,
        bytes: &[u8],
    ) -> Result<(), VtaError> {
        let client = match &self.transport {
            Transport::Rest { client, .. } => client,
            #[cfg(feature = "session")]
            Transport::DIDComm { rest_client, .. } => rest_client.as_ref().ok_or_else(|| {
                VtaError::Validation("DIDComm transport has no REST client for blob upload".into())
            })?,
            #[cfg(feature = "tsp")]
            Transport::Tsp { rest_client, .. } => rest_client.as_ref().ok_or_else(|| {
                VtaError::Validation("TSP transport has no REST client for blob upload".into())
            })?,
        };
        let resp = client
            .post(transport_url)
            .header(TOKEN_HEADER, transport_token)
            .body(bytes.to_vec())
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VtaError::from_http(status, body));
        }
        // 202 Accepted with empty body; nothing to deserialise.
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
