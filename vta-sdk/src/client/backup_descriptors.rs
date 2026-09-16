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
//! The transfer algorithm follows the client's Trust-Task transport, which
//! is itself chosen from what the VTA's DID document advertises:
//!
//! - **REST** → `stream`: the bytes move over the VTA's HTTPS blob
//!   endpoint (`initiate-*/1.0`, unchanged).
//! - **DIDComm / TSP** → `chunkedTrustTask`: the bytes move as
//!   `get-chunk` / `put-chunk` Trust Tasks over the same transport
//!   (`initiate-*/1.1`; see [`super::backup_chunked`]).
//!
//! Neither path falls back to the other. A DIDComm client's optional
//! `rest_url` is not evidence that the VTA advertises REST, so it is never
//! used to reach the blob endpoint behind the transport the client chose.
//! The legacy inline protocol message ([`VtaClient::backup_export`]) is not
//! a substitute either: its reply carries the whole envelope and is refused
//! by a mediator's 1 MiB message limit for any real VTA.

use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::VtaClient;
use super::backup_chunked::TransferProgress;
use super::{SurfaceTransport, Transport};
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
    /// `stream` on a REST client, `chunkedTrustTask` on a DIDComm/TSP one.
    /// See the module docs.
    pub async fn backup_export_via_descriptor(
        &self,
        password: &str,
        include_audit: bool,
    ) -> Result<Vec<u8>, VtaError> {
        self.backup_export_with_progress(password, include_audit, &mut |_| {})
            .await
    }

    /// [`Self::backup_export_via_descriptor`], reporting progress after each
    /// chunk of a chunked transfer. A `stream` transfer is one request and
    /// reports nothing.
    pub async fn backup_export_with_progress(
        &self,
        password: &str,
        include_audit: bool,
        progress: &mut (dyn FnMut(TransferProgress) + Send),
    ) -> Result<Vec<u8>, VtaError> {
        if self.trust_task_transport() != SurfaceTransport::Rest {
            let (bytes, bundle_id) = self
                .backup_export_chunked(password, include_audit, progress)
                .await?;
            // Best-effort, as for stream: it releases the staged copy now rather
            // than at expiry, and the bytes are already verified and in hand.
            let _: Result<CompleteExportResultBody, VtaError> = self
                .post_trust_task(
                    crate::trust_tasks::TASK_BACKUP_COMPLETE_EXPORT_1_0,
                    CompleteExportBody { bundle_id },
                )
                .await;
            return Ok(bytes);
        }
        descriptor_transport_gate(self.trust_task_transport())?;
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
        self.backup_import_with_progress(bytes, password, confirm, &mut |_| {})
            .await
    }

    /// [`Self::backup_import_via_descriptor`], reporting progress after each
    /// chunk of a chunked transfer.
    pub async fn backup_import_with_progress(
        &self,
        bytes: &[u8],
        password: &str,
        confirm: bool,
        progress: &mut (dyn FnMut(TransferProgress) + Send),
    ) -> Result<FinalizeImportResultBody, VtaError> {
        if self.trust_task_transport() != SurfaceTransport::Rest {
            let bundle_id = self.backup_import_chunked(bytes, progress).await?;
            return self
                .backup_finalize_import(&bundle_id, password, confirm)
                .await;
        }
        descriptor_transport_gate(self.trust_task_transport())?;
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

    /// Re-run `finalize-import` against a bundle whose bytes are already
    /// uploaded — typically the commit after a preview from
    /// [`Self::backup_import_via_descriptor`] with `confirm = false`.
    ///
    /// The VTA keeps a previewed bundle in `ImportPreviewed`, which accepts a
    /// commit, so the bytes do not need to cross the wire a second time. A
    /// bundle that expired meanwhile (its slot is short-lived) is refused as
    /// not-found or conflict; the caller decides whether to start over.
    pub async fn backup_finalize_import(
        &self,
        bundle_id: &str,
        password: &str,
        confirm: bool,
    ) -> Result<FinalizeImportResultBody, VtaError> {
        let req = FinalizeImportBody {
            bundle_id: bundle_id.to_string(),
            password: password.to_string(),
            confirm,
        };
        // 1.1 on a mediator transport, where the bundle is chunked and 1.1 is
        // what names a missing chunk; 1.0 on REST, so a VTA that predates the
        // chunked algorithm keeps finalizing stream bundles. The payloads and
        // responses are identical.
        let uri = if self.trust_task_transport() == SurfaceTransport::Rest {
            crate::trust_tasks::TASK_BACKUP_FINALIZE_IMPORT_1_0
        } else {
            crate::trust_tasks::TASK_BACKUP_FINALIZE_IMPORT_1_1
        };
        self.post_trust_task(uri, req).await
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
                VtaError::UnsupportedTransport(no_rest_leg("DIDComm", "download"))
            })?,
            #[cfg(feature = "tsp")]
            Transport::Tsp { rest_client, .. } => rest_client
                .as_ref()
                .ok_or_else(|| VtaError::UnsupportedTransport(no_rest_leg("TSP", "download")))?,
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
            Transport::DIDComm { rest_client, .. } => rest_client
                .as_ref()
                .ok_or_else(|| VtaError::UnsupportedTransport(no_rest_leg("DIDComm", "upload")))?,
            #[cfg(feature = "tsp")]
            Transport::Tsp { rest_client, .. } => rest_client
                .as_ref()
                .ok_or_else(|| VtaError::UnsupportedTransport(no_rest_leg("TSP", "upload")))?,
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

/// Refuse the `stream` algorithm on any Trust-Task surface other than REST.
///
/// The high-level methods choose `chunkedTrustTask` on DIDComm/TSP before this
/// is reached, so it guards the stream path itself: a client whose transport is
/// a mediator must never have its bytes routed to an HTTPS endpoint behind it.
/// [`VtaError::UnsupportedTransport`] rather than `Validation`, because nothing
/// about the request is invalid.
pub(crate) fn descriptor_transport_gate(surface: SurfaceTransport) -> Result<(), VtaError> {
    match surface {
        SurfaceTransport::Rest => Ok(()),
        other => Err(VtaError::UnsupportedTransport(format!(
            "the backup `stream` algorithm moves the bytes over the VTA's HTTPS blob \
             endpoint; this client's Trust-Task surface is on {other}, which uses the \
             `chunkedTrustTask` algorithm instead. Re-run with `--transport rest` to use \
             `stream` against a VTA that advertises REST"
        ))),
    }
}

fn no_rest_leg(transport: &str, direction: &str) -> String {
    format!(
        "{transport} transport has no REST client for the backup blob {direction}; \
         re-run with `--transport rest`"
    )
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

/// The descriptor flow is REST-only until the `chunkedTrustTask` algorithm
/// lands. A DIDComm/TSP client used to get `Validation`, which reads as "your
/// request is wrong" when the same request succeeds over REST.
#[cfg(test)]
mod transport_gate_tests {
    use super::super::{SurfaceTransport, VtaClient};
    use super::descriptor_transport_gate;
    use crate::error::VtaError;

    #[test]
    fn rest_surface_passes_the_gate() {
        descriptor_transport_gate(SurfaceTransport::Rest).expect("REST is the supported surface");
    }

    #[test]
    fn mediator_surfaces_are_unsupported_transport_not_validation() {
        for surface in [SurfaceTransport::Didcomm, SurfaceTransport::Tsp] {
            match descriptor_transport_gate(surface) {
                Err(VtaError::UnsupportedTransport(msg)) => {
                    assert!(
                        msg.contains("--transport rest"),
                        "{surface}: the refusal must name the fix, got: {msg}"
                    );
                    assert!(
                        msg.contains(&surface.to_string()),
                        "{surface}: the refusal must name the surface, got: {msg}"
                    );
                }
                other => panic!("{surface}: expected UnsupportedTransport, got {other:?}"),
            }
        }
    }

    /// A REST client is let through the gate: the call fails later, on the
    /// unreachable host, and not with the transport refusal.
    #[tokio::test]
    async fn rest_client_is_not_refused_by_the_gate() {
        let client = VtaClient::new("http://127.0.0.1:9");
        let err = client
            .backup_abort_bundle("3f2504e0-4f89-41d3-9a0c-0305e82c3301")
            .await
            .expect_err("nothing listens there");
        assert!(
            !matches!(err, VtaError::UnsupportedTransport(_)),
            "a REST client must pass the transport gate, got {err:?}"
        );
    }
}
