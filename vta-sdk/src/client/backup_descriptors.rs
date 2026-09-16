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
    ///
    /// The document is built and signed by the shared
    /// [`dispatch_trust_task`](VtaClient::dispatch_trust_task) path — the same
    /// one every other trust-task surface uses — so the envelope carries the
    /// in-band `recipient` (the VTA DID, SPEC §7.2 item 5b), `issuer` (the
    /// caller DID, item 6), and a `proof` signed by the caller's key (item 7a)
    /// that all come from this client's [`ClientIdentity`](super::ClientIdentity).
    /// It used to hand-build a bare `{ id, type, issuedAt, payload }` envelope
    /// with none of those, which a §7.2-enforcing VTA rejects as
    /// `malformedRequest` — see FTL backup-export defect.
    pub async fn post_trust_task<B, R>(
        &self,
        type_uri: &'static str,
        payload: B,
    ) -> Result<R, VtaError>
    where
        B: Serialize,
        R: DeserializeOwned,
    {
        // The descriptor pattern is REST-only: the blob download/upload leg has
        // no DIDComm/TSP transport yet, so a client on a mediator transport
        // could initiate but never move the bytes. Gate here rather than let the
        // trust task go out over DIDComm/TSP and then strand the ceremony at
        // `download_blob`/`upload_blob`.
        match &self.transport {
            Transport::Rest { .. } => {}
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
        }

        // Delegate to the shared signed-dispatch path. It builds the envelope
        // via `build_task_document` (recipient + issuer from the identity),
        // signs it (item 7a proof), POSTs `<base>/trust-tasks`, parses a
        // `trust-task-error` document into a typed `VtaError`, and returns the
        // success reply's `payload`. The `timeout` argument is unused on the
        // REST arm (it paces only the DIDComm/TSP wait), so its value is
        // immaterial here.
        let payload_value = serde_json::to_value(&payload)?;
        let response_payload = self
            .dispatch_trust_task(type_uri, payload_value, 30)
            .await?;
        Ok(serde_json::from_value(response_payload)?)
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
            return Err(VtaError::from_response(resp).await);
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
            return Err(VtaError::from_response(resp).await);
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

/// The descriptor flow used to hand-build a bare `{ id, type, issuedAt, payload }`
/// envelope with no in-band `recipient` and no `proof`, so a §7.2-enforcing VTA
/// rejected `backup/initiate-export` (and `initiate-import`) as
/// `malformedRequest`. It now routes through the shared signed-dispatch path;
/// these tests pin that the two initiate requests carry the members §7.2
/// requires.
#[cfg(test)]
mod descriptor_envelope_tests {
    use super::super::{ClientIdentity, VtaClient};
    use crate::protocols::backup_management::descriptors::{
        InitiateExportBody, InitiateImportBody,
    };
    use crate::trust_tasks;

    const VTA_DID: &str = "did:key:z6MkVtaBackupTarget";

    /// A `did:key` caller identity, whose proof verifies with no network I/O.
    fn caller_identity() -> ClientIdentity {
        let seed = [0xb4u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let client_did = format!(
            "did:key:{}",
            crate::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, &buf);
        ClientIdentity {
            client_did,
            private_key_multibase,
            vta_did: VTA_DID.to_string(),
            verification_method: None,
        }
    }

    /// Build the document the descriptor flow would emit for `type_uri` and
    /// assert it is addressed to the VTA, issued by the caller, and carries a
    /// cryptographically valid proof by the caller's key.
    ///
    /// This walks the two steps `post_trust_task`'s delegate
    /// [`VtaClient::dispatch_trust_task`] takes before the transport, in the
    /// order it takes them: the payload-conformance gate, then
    /// `signed_task_document`. Running the gate here is what keeps the helper
    /// honest about being "what goes on the wire" — it is the one client-side
    /// refusal the delegation introduced, and a test that only built the
    /// envelope would pass on a payload the real call rejects before it ever
    /// builds one.
    async fn assert_conforming_request(type_uri: &'static str, payload: serde_json::Value) {
        let id = caller_identity();
        let client = VtaClient::new("http://vta.invalid").with_identity(id.clone());

        VtaClient::check_payload_conforms(type_uri, &payload)
            .unwrap_or_else(|e| panic!("{type_uri}: the payload does not conform: {e}"));

        let doc = client
            .signed_task_document(type_uri, payload)
            .await
            .unwrap_or_else(|e| panic!("{type_uri}: building the request failed: {e}"));

        assert_eq!(
            doc.get("recipient").and_then(|v| v.as_str()),
            Some(id.vta_did.as_str()),
            "{type_uri}: recipient must be the VTA DID (SPEC §7.2 item 5b)"
        );
        assert_eq!(
            doc.get("issuer").and_then(|v| v.as_str()),
            Some(id.client_did.as_str()),
            "{type_uri}: issuer must be the caller DID (item 6)"
        );

        let typed: trust_tasks_rs::TrustTask<serde_json::Value> =
            serde_json::from_value(doc).expect("the built document is a TrustTask");

        // The proof is present *and* verifies (item 7a) — not merely a proof
        // block, but a signature that checks out — and the proven signer is the
        // caller.
        let signer = crate::trust_task_proof::verify_trust_task_proof(&typed)
            .await
            .unwrap_or_else(|e| panic!("{type_uri}: the proof does not verify: {e:?}"));
        assert_eq!(
            signer, id.client_did,
            "{type_uri}: the proof must be signed by the caller's key"
        );

        // The VTA's own dispatch spine would run this exact check; running it
        // here fails the test if the registry ever drops the requirement.
        let policy = trust_tasks_rs::schema_index::spec_policy_for(type_uri)
            .unwrap_or_else(|| panic!("{type_uri} has no published policy"));
        policy
            .enforce(&typed)
            .unwrap_or_else(|r| panic!("{type_uri}: a conforming VTA would refuse this: {r:?}"));
    }

    #[tokio::test]
    async fn initiate_export_request_is_addressed_and_signed() {
        let body = InitiateExportBody {
            password: "correct horse battery staple".into(),
            include_audit: true,
            algorithm: "stream".into(),
        };
        assert_conforming_request(
            trust_tasks::TASK_BACKUP_INITIATE_EXPORT_1_0,
            serde_json::to_value(body).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn initiate_import_request_is_addressed_and_signed() {
        let body = InitiateImportBody {
            expected_sha256: super::sha256_hex(b"a backup blob"),
            expected_size_bytes: 13,
            algorithm: "stream".into(),
        };
        assert_conforming_request(
            trust_tasks::TASK_BACKUP_INITIATE_IMPORT_1_0,
            serde_json::to_value(body).unwrap(),
        )
        .await;
    }
}
