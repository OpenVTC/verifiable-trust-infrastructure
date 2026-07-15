//! `verify_foreign_vec` — the load-bearing M3.9 entry point.
//!
//! Verifies a foreign-issued (VEC, VMC) pair against four
//! invariants (in order, fail-closed):
//!
//! 1. Both proofs verify against the foreign issuer's
//!    `#key-0` public key.
//! 2. Each credential's `credentialStatus.statusListCredential`
//!    fetches, decodes, and the bit at `statusListIndex` is
//!    `0`.
//! 3. The foreign issuer DID is present in the trust-registry
//!    recognition graph (via the `TrustRegistryClient` trait).
//! 4. Both `validFrom <= now <= validUntil` hold.
//!
//! The returned [`VerifiedForeignCredential`] carries the
//! parsed role claim + the earliest `validUntil` across the
//! pair — the route layer (`POST /v1/auth/recognise`) clamps
//! the session TTL to that earliest expiry.
//!
//! ## Injectable resolver + status fetch
//!
//! Both surfaces are heavy: DID resolution can hit external
//! HTTPS, status-list fetching is unconditionally HTTP. Key
//! resolution goes through the DI library's
//! `VerificationMethodResolver` (the shared
//! [`crate::credentials::vm_resolver::DidVmResolver`]); status
//! fetching is behind the small [`StatusListFetcher`] trait.
//! Both are injected, so `verify_foreign_vec` is unit-testable
//! without a live DID resolver or status-list host.

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, VerificationMethodResolver, VerifyOptions};
use affinidi_vc::VerifiableCredential;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use thiserror::Error;
use vta_sdk::http::ForeignFetchError;

use crate::credentials::vm_resolver::check_issuer_binding;
use crate::registry::{RegistryError, TrustRegistryClient};

/// Failure modes the verifier surfaces. Mapped to HTTP 403
/// (Forbidden) at the route layer — never operator input,
/// always a foreign-credential property the caller couldn't
/// have predicted from their own state. The discriminator
/// drives the `denied` audit envelope's `reason` field.
#[derive(Debug, Clone, Error)]
pub enum RecognitionError {
    /// The foreign issuer's DID didn't resolve or the
    /// `#key-0` verification method couldn't be located.
    #[error("issuer DID resolution failed: {0}")]
    IssuerKeyUnresolved(String),
    /// VEC or VMC proof failed signature verification.
    #[error("foreign credential proof verification failed: {0}")]
    ProofInvalid(String),
    /// Status-list fetch / decode / status-bit check failed.
    /// Either the URL was unreachable, the response didn't
    /// parse, or the bit at `statusListIndex` was `1`.
    #[error("status-list check failed: {0}")]
    StatusListFailed(String),
    /// Foreign issuer is not in the trust-registry recognition
    /// graph. This is the "operator forgot to add the peer
    /// community" path — fail-closed by construction (plan
    /// D6).
    #[error("foreign issuer {0} is not recognised by this VTC")]
    IssuerNotRecognised(String),
    /// Trust-registry was unreachable during the recognise
    /// check. Distinct from `IssuerNotRecognised` so the
    /// route layer can map to 503 vs 403.
    #[error("trust registry unreachable: {0}")]
    RegistryUnreachable(String),
    /// Trust-registry was reachable but rejected the recognise
    /// query (a `RegistryError::Permanent` — bad request shape,
    /// an upstream/workspace fault, **not** a holder-driven "not
    /// recognised"). The route layer maps this to 502, not 403,
    /// so an operator isn't misled into thinking they forgot to
    /// add the peer community.
    #[error("trust registry rejected the recognise query: {0}")]
    RegistryRejected(String),
    /// `validFrom` is in the future or `validUntil` is in the
    /// past. Carries which credential failed for diagnostics.
    #[error("credential validity window: {0}")]
    ValidityWindow(String),
    /// Malformed credential shape — missing required field,
    /// unparsable RFC3339, etc. Distinct from `ProofInvalid`
    /// (which means the signature didn't match a valid shape).
    #[error("credential shape invalid: {0}")]
    Malformed(String),
}

impl RecognitionError {
    /// Short reason code for the audit envelope's `reason`
    /// field. Stable across releases — operators may build
    /// SIEM filters keyed on these strings.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::IssuerKeyUnresolved(_) => "issuer-key-unresolved",
            Self::ProofInvalid(_) => "proof-invalid",
            Self::StatusListFailed(_) => "status-list-failed",
            Self::IssuerNotRecognised(_) => "issuer-not-recognised",
            Self::RegistryUnreachable(_) => "registry-unreachable",
            Self::RegistryRejected(_) => "registry-rejected",
            Self::ValidityWindow(_) => "validity-window",
            Self::Malformed(_) => "malformed",
        }
    }
}

/// Fetches + decodes a status-list credential. Production
/// wires [`HttpStatusListFetcher`] (reqwest + JSON parse +
/// bitstring decode); tests inject a stub returning a known
/// bit value.
#[async_trait]
pub trait StatusListFetcher: Send + Sync {
    /// Fetch the status-list credential at `url` and return the
    /// status bit at `index`. `Ok(false)` = not revoked.
    ///
    /// `expected_issuer`, when `Some`, is the issuer the status-list
    /// credential MUST be signed by (and whose `issuer` it must
    /// declare) — supplied by callers that want substitution
    /// protection. Implementations that don't verify the list's own
    /// signature ignore it.
    async fn check_status_bit(
        &self,
        url: &str,
        index: usize,
        expected_issuer: Option<&str>,
    ) -> Result<bool, RecognitionError>;
}

/// Post-verification view of a (VEC, VMC) pair. Only
/// constructible by [`verify_foreign_vec`] — the route layer
/// taking this type as input is guaranteed to be looking at a
/// fully-verified pair (typestate discipline per workspace
/// CLAUDE.md).
#[derive(Debug, Clone)]
pub struct VerifiedForeignCredential {
    /// The foreign community's issuer DID — `vec.issuer ==
    /// vmc.issuer` by spec §6.1.
    pub foreign_issuer_did: String,
    /// The bearer's DID — the `credentialSubject.id` field on
    /// the VEC. The session is minted *to* this DID.
    pub subject_did: String,
    /// The role claim from the VEC's `credentialSubject.role`
    /// field. Fed into `cross_community_roles.rego` for local
    /// role mapping.
    pub foreign_role: String,
    /// The **earliest** `validUntil` across VEC + VMC. The
    /// route layer clamps session TTL to `min(jwt_default,
    /// this)` per spec §8.4.
    pub earliest_valid_until: DateTime<Utc>,
}

/// Run the four-step verification. See module docs for the
/// rationale on ordering + fail-closed semantics.
pub async fn verify_foreign_vec(
    vec: &VerifiableCredential,
    vmc: &VerifiableCredential,
    resolver: &dyn VerificationMethodResolver,
    status_fetcher: &dyn StatusListFetcher,
    registry: Arc<dyn TrustRegistryClient>,
    now: DateTime<Utc>,
) -> Result<VerifiedForeignCredential, RecognitionError> {
    // Spec §6.1 requires both credentials share an issuer.
    let issuer = vec.issuer.id();
    if issuer != vmc.issuer.id() {
        return Err(RecognitionError::Malformed(format!(
            "VEC issuer ({}) != VMC issuer ({})",
            issuer,
            vmc.issuer.id()
        )));
    }
    let issuer = issuer.to_string();

    // Spec §8.4: the VMC's only job here is the "is a live, non-revoked
    // member" gate, so it must name the **same subject** as the role VEC.
    // Without this, an attacker pairs member A's role VEC with member B's
    // (still-unrevoked) VMC — same issuer — and passes the membership gate
    // even after the foreign community revoked A. Checked before any
    // proof/network work so a mismatched pair fails fast.
    let vec_subject = subject_id(vec, "VEC")?;
    let vmc_subject = subject_id(vmc, "VMC")?;
    if vec_subject != vmc_subject {
        return Err(RecognitionError::Malformed(format!(
            "VEC subject ({vec_subject}) != VMC subject ({vmc_subject})"
        )));
    }

    // Step 1: proof verification. Cheap; runs first so a
    // malformed pair short-circuits before any network call.
    verify_proof(vec, &issuer, resolver, "VEC").await?;
    verify_proof(vmc, &issuer, resolver, "VMC").await?;

    // Step 4 (early): validity windows. Cheap RFC3339 parse +
    // comparison. Bumped before the network calls so an
    // expired credential doesn't waste a status-list fetch.
    let vec_until = parse_valid_until(vec, "VEC")?;
    let vmc_until = parse_valid_until(vmc, "VMC")?;
    if let Some(vf) = vec.valid_from.as_deref() {
        let vf = parse_rfc3339(vf)
            .map_err(|e| RecognitionError::ValidityWindow(format!("VEC validFrom: {e}")))?;
        if vf > now {
            return Err(RecognitionError::ValidityWindow(format!(
                "VEC validFrom {vf} is in the future"
            )));
        }
    }
    if let Some(vf) = vmc.valid_from.as_deref() {
        let vf = parse_rfc3339(vf)
            .map_err(|e| RecognitionError::ValidityWindow(format!("VMC validFrom: {e}")))?;
        if vf > now {
            return Err(RecognitionError::ValidityWindow(format!(
                "VMC validFrom {vf} is in the future"
            )));
        }
    }
    if vec_until <= now {
        return Err(RecognitionError::ValidityWindow(format!(
            "VEC validUntil {vec_until} is in the past"
        )));
    }
    if vmc_until <= now {
        return Err(RecognitionError::ValidityWindow(format!(
            "VMC validUntil {vmc_until} is in the past"
        )));
    }

    // Step 2: status-list revocation. Per-credential; either
    // a missing `credentialStatus` is treated as "no
    // revocation surface" (the credential never opted into
    // BitstringStatusList). A *present* status block whose
    // bit is set rejects the credential.
    check_status_list(vec, status_fetcher, &issuer, "VEC").await?;
    check_status_list(vmc, status_fetcher, &issuer, "VMC").await?;

    // Step 3: registry recognition. The most operator-visible
    // failure mode — fails when the operator hasn't added the
    // peer community to their recognition graph.
    let recognised = registry.recognise(&issuer).await.map_err(|e| match e {
        RegistryError::Unreachable(msg) | RegistryError::Transient(msg) => {
            RecognitionError::RegistryUnreachable(msg)
        }
        RegistryError::Permanent(msg) => RecognitionError::RegistryRejected(msg),
    })?;
    if !recognised {
        return Err(RecognitionError::IssuerNotRecognised(issuer));
    }

    // Extract bearer subject + role from the VEC.
    let (subject_did, foreign_role) = extract_role_claim(vec)?;

    Ok(VerifiedForeignCredential {
        foreign_issuer_did: issuer,
        subject_did,
        foreign_role,
        earliest_valid_until: vec_until.min(vmc_until),
    })
}

async fn verify_proof(
    vc: &VerifiableCredential,
    issuer_did: &str,
    resolver: &dyn VerificationMethodResolver,
    label: &str,
) -> Result<(), RecognitionError> {
    let proof_value = vc
        .proof
        .as_ref()
        .ok_or_else(|| RecognitionError::ProofInvalid(format!("{label} has no proof")))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| RecognitionError::ProofInvalid(format!("{label} parse proof: {e}")))?;

    let verification_method = proof_value
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RecognitionError::ProofInvalid(format!("{label} proof missing verificationMethod"))
        })?;
    // The signing key must sit under the foreign issuer (a key controlled by
    // some other DID must not sign this credential). The library `verify` then
    // resolves it + checks the signature.
    check_issuer_binding(verification_method, issuer_did)
        .map_err(|e| RecognitionError::ProofInvalid(format!("{label}: {e}")))?;

    let mut vc_without_proof = vc.clone();
    vc_without_proof.proof = None;

    proof
        .verify(&vc_without_proof, resolver, VerifyOptions::new())
        .await
        .map_err(|e| RecognitionError::ProofInvalid(format!("{label}: {e}")))?;
    Ok(())
}

async fn check_status_list(
    vc: &VerifiableCredential,
    fetcher: &dyn StatusListFetcher,
    expected_issuer: &str,
    label: &str,
) -> Result<(), RecognitionError> {
    let Some(status) = vc.credential_status.as_ref() else {
        // No status block → credential never opted into
        // BitstringStatusList. Treat as "not revocable" — a
        // foreign community that issues without a status list
        // is making an implicit "we don't revoke" claim.
        return Ok(());
    };
    let url = status.status_list_credential.as_deref().ok_or_else(|| {
        RecognitionError::Malformed(format!(
            "{label} credentialStatus has no statusListCredential URL"
        ))
    })?;
    let index_str = status.status_list_index.as_deref().ok_or_else(|| {
        RecognitionError::Malformed(format!("{label} credentialStatus has no statusListIndex"))
    })?;
    let index: usize = index_str.parse().map_err(|e| {
        RecognitionError::Malformed(format!("{label} statusListIndex {index_str}: {e}"))
    })?;
    // The status list MUST be signed by the foreign issuer (the same issuer that
    // signed the VEC/VMC). The production fetcher verifies this; a substituted or
    // forged list is rejected before the bit is read.
    let bit_set = fetcher
        .check_status_bit(url, index, Some(expected_issuer))
        .await?;
    if bit_set {
        return Err(RecognitionError::StatusListFailed(format!(
            "{label} status bit at {index} is set (revoked/suspended)"
        )));
    }
    Ok(())
}

fn parse_valid_until(
    vc: &VerifiableCredential,
    label: &str,
) -> Result<DateTime<Utc>, RecognitionError> {
    let raw = vc
        .valid_until
        .as_deref()
        .ok_or_else(|| RecognitionError::Malformed(format!("{label} has no validUntil")))?;
    parse_rfc3339(raw)
        .map_err(|e| RecognitionError::ValidityWindow(format!("{label} validUntil: {e}")))
}

fn parse_rfc3339(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| format!("parse RFC3339 {raw}: {e}"))
}

/// Extract `credentialSubject.id` from a credential (the first subject if
/// multiple). `label` names the credential in error messages.
fn subject_id(vc: &VerifiableCredential, label: &str) -> Result<String, RecognitionError> {
    use affinidi_vc::SubjectValue;
    let subject_map = match &vc.credential_subject {
        SubjectValue::Single(m) => m.clone(),
        SubjectValue::Multiple(v) => v.first().cloned().ok_or_else(|| {
            RecognitionError::Malformed(format!("{label} credentialSubject is empty"))
        })?,
    };
    subject_map
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            RecognitionError::Malformed(format!(
                "{label} credentialSubject.id missing or not a string"
            ))
        })
}

fn extract_role_claim(vec: &VerifiableCredential) -> Result<(String, String), RecognitionError> {
    use affinidi_vc::SubjectValue;
    let subject_did = subject_id(vec, "VEC")?;
    let subject_map = match &vec.credential_subject {
        SubjectValue::Single(m) => m.clone(),
        SubjectValue::Multiple(v) => v
            .first()
            .cloned()
            .ok_or_else(|| RecognitionError::Malformed("VEC credentialSubject is empty".into()))?,
    };
    // VEC shape per `build_role_vec`:
    // credentialSubject = { id, endorsement: { type, role, communityDid } }
    // The role lives under `endorsement.role`, not at the top level
    // of `credentialSubject`.
    let role = subject_map
        .get("endorsement")
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("role"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            RecognitionError::Malformed(
                "VEC credentialSubject.endorsement.role missing or not a string".into(),
            )
        })?;
    Ok((subject_did, role))
}

// ---------------------------------------------------------------------------
// Production trait impls
// ---------------------------------------------------------------------------

/// HTTP `StatusListFetcher` — fetches a BitstringStatusList
/// credential by URL, parses out the encoded list, and tests
/// the bit at `index`. Used by production deployments; tests
/// inject a stub.
///
/// When built with [`HttpStatusListFetcher::with_issuer_verification`], it also
/// verifies the fetched list credential's own `eddsa-jcs-2022` issuer signature
/// (bound to the list's `issuer`, and to the caller's `expected_issuer`) before
/// trusting any of its bytes — closing the fail-open hole where anyone able to
/// serve the URL could forge a (terminal) revocation, or hide a real one. Built
/// with [`HttpStatusListFetcher::new`] it does **not** verify (the recognition
/// path's current behaviour).
pub struct HttpStatusListFetcher {
    client: reqwest::Client,
    /// Resolves the list credential's issuer key for the signature check. `None`
    /// → no verification (fetch + decode only).
    key_resolver: Option<Arc<dyn VerificationMethodResolver>>,
}

impl HttpStatusListFetcher {
    /// A non-verifying fetcher (fetch + decode only). The list credential's own
    /// issuer signature is not checked. Uses the shared hardened client
    /// ([`foreign_fetch_client`]).
    pub fn new() -> Self {
        Self {
            client: foreign_fetch_client(),
            key_resolver: None,
        }
    }

    /// A fetcher that verifies each fetched list credential's `eddsa-jcs-2022`
    /// issuer signature via `key_resolver` before trusting it. Uses the shared
    /// hardened client ([`foreign_fetch_client`]).
    pub fn with_issuer_verification(key_resolver: Arc<dyn VerificationMethodResolver>) -> Self {
        Self {
            client: foreign_fetch_client(),
            key_resolver: Some(key_resolver),
        }
    }
}

impl Default for HttpStatusListFetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Cap on a fetched status-list body — the shared foreign-fetch default
/// ([`vta_sdk::http::DEFAULT_MAX_FOREIGN_BODY`], 2 MiB). The spec-minimum list
/// is ~16 KiB compressed; the cap refuses the multi-GB body a hostile host on
/// the unauthenticated recognise path could otherwise stream to OOM the daemon.
const MAX_STATUS_LIST_BODY: usize = vta_sdk::http::DEFAULT_MAX_FOREIGN_BODY;

/// Map a shared-layer [`ForeignFetchError`] (SSRF-guard rejection, body-cap
/// breach, mid-stream read failure) into a `RecognitionError`, tagging it with
/// the offending `url`. The route layer surfaces `StatusListFailed` as HTTP 403.
fn foreign_fetch_failed(url: &str, e: ForeignFetchError) -> RecognitionError {
    RecognitionError::StatusListFailed(format!("status list {url}: {e}"))
}

/// A clone of the shared hardened foreign-fetch client
/// ([`vta_sdk::http::foreign_fetch_client`]) — `redirect(none)` + finite
/// timeouts. The only client used on the attacker-controlled status-list fetch
/// path; no bare `reqwest::Client::new()`. Not following redirects closes the
/// SSRF-via-redirect bypass (CWE-918): a `3xx` lands as a non-2xx that
/// [`HttpStatusListFetcher::check_status_bit`] maps to `StatusListFailed`, so
/// the redirect target is never fetched. Consolidated with the VTA's
/// vault-present path so both share one chokepoint.
pub(crate) fn foreign_fetch_client() -> reqwest::Client {
    vta_sdk::http::foreign_fetch_client()
}

/// Read a response body into memory, refusing anything larger than `max` bytes.
/// Delegates to the shared [`vta_sdk::http::read_body_capped`] — chunk-by-chunk,
/// aborting the instant the cap is crossed so the oversized body is never fully
/// buffered — and tags any failure with `url`.
async fn read_body_capped(
    resp: reqwest::Response,
    max: usize,
    url: &str,
) -> Result<Vec<u8>, RecognitionError> {
    vta_sdk::http::read_body_capped(resp, max)
        .await
        .map_err(|e| foreign_fetch_failed(url, e))
}

/// Verify a fetched `BitstringStatusListCredential`'s own `eddsa-jcs-2022` issuer
/// signature, binding the proof to the list's `issuer` and — when
/// `expected_issuer` is supplied — binding that `issuer` to the credential whose
/// status is being checked (so a validly-signed but unrelated list can't be
/// substituted). Any failure is a `StatusListFailed` error.
async fn verify_status_list_signature(
    list_credential: &JsonValue,
    expected_issuer: Option<&str>,
    resolver: &dyn VerificationMethodResolver,
    url: &str,
) -> Result<(), RecognitionError> {
    let list_issuer = list_credential
        .get("issuer")
        .and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.get("id").and_then(JsonValue::as_str).map(str::to_string))
        })
        .ok_or_else(|| {
            RecognitionError::StatusListFailed(format!("status list {url} has no issuer to verify"))
        })?;

    if let Some(expected) = expected_issuer
        && list_issuer != expected
    {
        return Err(RecognitionError::StatusListFailed(format!(
            "status list {url} issuer {list_issuer} is not the credential's issuer {expected} \
             — refusing a substituted status list"
        )));
    }

    let proof_value = list_credential.get("proof").ok_or_else(|| {
        RecognitionError::StatusListFailed(format!("status list {url} has no proof to verify"))
    })?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone()).map_err(|e| {
        RecognitionError::StatusListFailed(format!("status list {url} unparseable proof: {e}"))
    })?;
    let vm = proof_value
        .get("verificationMethod")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RecognitionError::StatusListFailed(format!(
                "status list {url} proof missing verificationMethod"
            ))
        })?;
    // The signing key must belong to the list's own issuer.
    check_issuer_binding(vm, &list_issuer)
        .map_err(|e| RecognitionError::StatusListFailed(format!("status list {url} {e}")))?;

    // JCS is presence-sensitive: strip `proof` exactly as signing did.
    let mut signing_doc = list_credential.clone();
    if let Some(obj) = signing_doc.as_object_mut() {
        obj.remove("proof");
    }
    proof
        .verify(&signing_doc, resolver, VerifyOptions::new())
        .await
        .map_err(|e| {
            RecognitionError::StatusListFailed(format!(
                "status list {url} issuer signature did not verify: {e}"
            ))
        })?;
    Ok(())
}

/// Reject URLs that don't pass the SSRF allowlist before the recognise handler
/// fetches them. Delegates to the shared [`vta_sdk::http::guard_public_url`] —
/// one chokepoint shared with the VTA's vault-present path — which refuses
/// non-HTTPS schemes, embedded userinfo, and IP-literal hosts in loopback /
/// private / link-local / cloud-metadata (`169.254.169.254`) ranges for both
/// IPv4 and IPv6. Any rejection becomes `RecognitionError::StatusListFailed`.
///
/// `/v1/auth/recognise` is unauthenticated and the URL comes straight from an
/// attacker-controlled foreign credential; without this guard the daemon could
/// be turned into an SSRF proxy hitting internal hosts (CWE-918). Reaching an
/// internal host by *DNS name* still needs a network-level egress filter — the
/// guard can't resolve at parse time without a TOCTOU window.
pub(crate) fn guard_status_list_url(url: &str) -> Result<(), RecognitionError> {
    vta_sdk::http::guard_public_url(url).map_err(|e| foreign_fetch_failed(url, e))
}

#[async_trait]
impl StatusListFetcher for HttpStatusListFetcher {
    async fn check_status_bit(
        &self,
        url: &str,
        index: usize,
        expected_issuer: Option<&str>,
    ) -> Result<bool, RecognitionError> {
        guard_status_list_url(url)?;
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| RecognitionError::StatusListFailed(format!("fetch {url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            // With `redirect(none)`, a 3xx lands here too: the redirect target
            // (potentially an internal host the guard rejected) is never
            // fetched — the SSRF-via-redirect bypass is closed.
            return Err(RecognitionError::StatusListFailed(format!(
                "fetch {url} returned {status}"
            )));
        }
        let bytes = read_body_capped(resp, MAX_STATUS_LIST_BODY, url).await?;
        let body: JsonValue = serde_json::from_slice(&bytes)
            .map_err(|e| RecognitionError::StatusListFailed(format!("parse {url}: {e}")))?;

        // Verify the list credential's own issuer signature (when this fetcher
        // was built to) BEFORE trusting any of its bytes.
        if let Some(resolver) = &self.key_resolver {
            verify_status_list_signature(&body, expected_issuer, resolver.as_ref(), url).await?;
        }

        // BitstringStatusList encoding: the status-list
        // credential's `credentialSubject.encodedList` carries
        // a base64url-encoded GZIP'd bitstring. Capacity +
        // purpose are also in the subject; we infer capacity
        // from the encoded bytes.
        let encoded = body
            .pointer("/credentialSubject/encodedList")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RecognitionError::StatusListFailed(format!(
                    "status-list at {url} missing credentialSubject.encodedList"
                ))
            })?;
        let purpose_str = body
            .pointer("/credentialSubject/statusPurpose")
            .and_then(|v| v.as_str())
            .unwrap_or("revocation");
        let purpose = match purpose_str {
            "revocation" => affinidi_status_list::StatusPurpose::Revocation,
            "suspension" => affinidi_status_list::StatusPurpose::Suspension,
            other => {
                return Err(RecognitionError::StatusListFailed(format!(
                    "unsupported statusPurpose {other}"
                )));
            }
        };
        // Capacity defaults to 131,072 (16 KiB compressed) —
        // the spec-mandated minimum. Foreign status lists may
        // be larger; the decoder fails closed if the actual
        // bitstring is shorter than `index`.
        let capacity = body
            .pointer("/credentialSubject/statusSize")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(131_072);

        let decoded = affinidi_status_list::BitstringStatusList::decode(encoded, capacity, purpose)
            .map_err(|e| RecognitionError::StatusListFailed(format!("decode {url}: {e}")))?;
        if index >= capacity {
            return Err(RecognitionError::StatusListFailed(format!(
                "index {index} exceeds capacity {capacity} for {url}"
            )));
        }
        decoded
            .get(index)
            .map_err(|e| RecognitionError::StatusListFailed(format!("get {index}: {e}")))
    }
}

#[cfg(test)]
mod ssrf_guard_tests {
    use super::guard_status_list_url;

    #[test]
    fn allows_https_to_public_domain() {
        guard_status_list_url("https://example.com/status/list").expect("public https ok");
    }

    #[test]
    fn rejects_http_scheme() {
        let err = guard_status_list_url("http://example.com/status").expect_err("http blocked");
        assert!(format!("{err}").contains("must be https"));
    }

    #[test]
    fn rejects_loopback_ipv4() {
        guard_status_list_url("https://127.0.0.1/x").expect_err("loopback blocked");
        guard_status_list_url("https://127.1/x").expect_err("loopback short form blocked");
    }

    #[test]
    fn rejects_rfc1918() {
        guard_status_list_url("https://10.0.0.1/x").expect_err("10/8 blocked");
        guard_status_list_url("https://192.168.1.5/x").expect_err("192.168 blocked");
        guard_status_list_url("https://172.16.0.1/x").expect_err("172.16 blocked");
    }

    #[test]
    fn rejects_link_local_metadata() {
        // EC2 / GCP / Azure cloud-metadata endpoint.
        guard_status_list_url("https://169.254.169.254/latest/meta-data/")
            .expect_err("metadata IP blocked");
    }

    #[test]
    fn rejects_ipv6_loopback_and_ula() {
        guard_status_list_url("https://[::1]/x").expect_err("v6 loopback blocked");
        guard_status_list_url("https://[fc00::1]/x").expect_err("v6 ULA blocked");
        guard_status_list_url("https://[fe80::1]/x").expect_err("v6 link-local blocked");
    }

    #[test]
    fn rejects_userinfo() {
        guard_status_list_url("https://user:pass@example.com/x").expect_err("userinfo blocked");
    }

    #[test]
    fn rejects_unparseable_url() {
        guard_status_list_url("not a url").expect_err("garbage blocked");
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::acl::VtcRole;
    use crate::credentials::{
        CredentialStatusRef, LocalSigner, RoleVecParams, VmcParams, build_role_vec, build_vmc,
    };
    use crate::registry::client::MockRegistryClient;
    use affinidi_vc::IssuerValue;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory `VerificationMethodResolver`. Tests seed the key bytes they
    /// expect the verifier to use, keyed by issuer DID; `resolve_vm` looks them
    /// up by the base DID of the verificationMethod URI.
    struct StubKeyResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl StubKeyResolver {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }
        fn with(mut self, did: &str, key: Vec<u8>) -> Self {
            self.keys.insert(did.to_string(), key);
            self
        }
    }

    #[async_trait]
    impl VerificationMethodResolver for StubKeyResolver {
        async fn resolve_vm(
            &self,
            vm: &str,
        ) -> Result<affinidi_data_integrity::ResolvedKey, affinidi_data_integrity::DataIntegrityError>
        {
            let base = vm.split('#').next().unwrap_or(vm);
            let bytes = self.keys.get(base).cloned().ok_or_else(|| {
                affinidi_data_integrity::DataIntegrityError::Resolver(format!(
                    "no test key for {base}"
                ))
            })?;
            Ok(affinidi_data_integrity::ResolvedKey::new(
                affinidi_secrets_resolver::secrets::KeyType::Ed25519,
                bytes,
            ))
        }
    }

    /// In-memory status-list stub. Tests seed bits per URL.
    #[derive(Default)]
    struct StubStatusFetcher {
        bits: Mutex<HashMap<(String, usize), bool>>,
        next_error: Mutex<Option<RecognitionError>>,
    }

    impl StubStatusFetcher {
        fn new() -> Self {
            Default::default()
        }
        fn set_bit(&self, url: &str, index: usize, set: bool) {
            self.bits.lock().unwrap().insert((url.into(), index), set);
        }
        #[allow(dead_code)]
        fn fail_next(&self, err: RecognitionError) {
            *self.next_error.lock().unwrap() = Some(err);
        }
    }

    #[async_trait]
    impl StatusListFetcher for StubStatusFetcher {
        async fn check_status_bit(
            &self,
            url: &str,
            index: usize,
            _expected_issuer: Option<&str>,
        ) -> Result<bool, RecognitionError> {
            if let Some(e) = self.next_error.lock().unwrap().take() {
                return Err(e);
            }
            Ok(*self
                .bits
                .lock()
                .unwrap()
                .get(&(url.to_string(), index))
                .unwrap_or(&false))
        }
    }

    /// Build a signed (VEC, VMC) pair issued by a fresh
    /// `LocalSigner` with a fixed DID. Returns the signer's
    /// public bytes alongside so the test can seed the
    /// resolver.
    async fn fresh_pair(
        issuer_did: &str,
        subject_did: &str,
        role: VtcRole,
        validity_secs: i64,
    ) -> (VerifiableCredential, VerifiableCredential, Vec<u8>) {
        let seed = [0xCDu8; 32];
        let signer = LocalSigner::from_ed25519_seed(issuer_did.into(), &seed);
        let pubkey = signer.public_bytes().to_vec();

        let vec_params = RoleVecParams::new(subject_did, role)
            .with_validity(chrono::Duration::seconds(validity_secs))
            .with_id("urn:vec:test");
        let vec_vc = build_role_vec(&signer, vec_params)
            .await
            .expect("build vec");

        let vmc_params = VmcParams::new(subject_did)
            .with_validity(chrono::Duration::seconds(validity_secs))
            .with_id("urn:vmc:test");
        let vmc_vc = build_vmc(&signer, vmc_params).await.expect("build vmc");

        (vec_vc, vmc_vc, pubkey)
    }

    #[tokio::test]
    async fn happy_path_verifies_and_returns_earliest_expiry() {
        let issuer = "did:webvh:peer.example.com:abc";
        let subject = "did:key:zSubject";
        let (vec, vmc, pubkey) = fresh_pair(issuer, subject, VtcRole::Moderator, 3600).await;

        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        let mock_reg = MockRegistryClient::new();
        mock_reg.set_recognised(issuer).await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg);

        let verified = verify_foreign_vec(&vec, &vmc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect("happy path");
        assert_eq!(verified.foreign_issuer_did, issuer);
        assert_eq!(verified.subject_did, subject);
        assert_eq!(verified.foreign_role, "moderator");
        assert!(verified.earliest_valid_until > Utc::now());
    }

    #[tokio::test]
    async fn vmc_subject_mismatch_is_rejected_before_network_calls() {
        // The attack: pair member A's role VEC with member B's (still
        // unrecognised-as-revoked) VMC — same issuer — to pass the
        // membership gate as A after A was revoked. The subjects must match.
        let issuer = "did:webvh:peer.example.com:abc";
        let seed = [0xCDu8; 32];
        let signer = LocalSigner::from_ed25519_seed(issuer.into(), &seed);
        let pubkey = signer.public_bytes().to_vec();

        let vec_vc = build_role_vec(
            &signer,
            RoleVecParams::new("did:key:zAlice", VtcRole::Moderator)
                .with_validity(chrono::Duration::seconds(3600))
                .with_id("urn:vec:test"),
        )
        .await
        .expect("build vec");
        let vmc_vc = build_vmc(
            &signer,
            VmcParams::new("did:key:zBob") // different subject than the VEC
                .with_validity(chrono::Duration::seconds(3600))
                .with_id("urn:vmc:test"),
        )
        .await
        .expect("build vmc");

        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        let mock_reg = MockRegistryClient::new();
        mock_reg.set_recognised(issuer).await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg.clone());

        let err = verify_foreign_vec(&vec_vc, &vmc_vc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect_err("mismatched VEC/VMC subjects must be rejected");
        assert!(matches!(err, RecognitionError::Malformed(_)), "got {err:?}");
        assert!(format!("{err}").contains("subject"), "got {err}");
        assert_eq!(
            mock_reg.call_counts().await.recognise,
            0,
            "subject binding must be checked before any network call"
        );
    }

    #[tokio::test]
    async fn unrecognised_issuer_is_rejected_even_with_valid_proofs() {
        let issuer = "did:webvh:stranger.example";
        let (vec, vmc, pubkey) =
            fresh_pair(issuer, "did:key:zSubject", VtcRole::Member, 3600).await;

        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        // Mock registry: NO recognised issuers.
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(MockRegistryClient::new());

        let err = verify_foreign_vec(&vec, &vmc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect_err("must reject");
        assert!(matches!(err, RecognitionError::IssuerNotRecognised(_)));
        assert_eq!(err.reason_code(), "issuer-not-recognised");
    }

    #[tokio::test]
    async fn proof_mismatch_rejected_before_network_calls() {
        let issuer = "did:webvh:peer.example";
        let (vec, vmc, _pubkey) =
            fresh_pair(issuer, "did:key:zSubject", VtcRole::Member, 3600).await;

        // Wrong pubkey → proof verify fails.
        let resolver = StubKeyResolver::new().with(issuer, vec![0u8; 32]);
        let fetcher = StubStatusFetcher::new();
        let mock_reg = MockRegistryClient::new();
        mock_reg.set_recognised(issuer).await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg.clone());

        let err = verify_foreign_vec(&vec, &vmc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect_err("must reject");
        assert!(matches!(err, RecognitionError::ProofInvalid(_)));
        assert_eq!(
            mock_reg.call_counts().await.recognise,
            0,
            "recognise must not be called when proof fails"
        );
    }

    #[tokio::test]
    async fn revoked_credential_is_rejected() {
        // Build a VMC with a credentialStatus pointing at our
        // stub fetcher. (RoleVecParams doesn't currently
        // accept a status ref — the VMC carries the status
        // block in the workspace today, and that's where the
        // revocation surface lives in steady state.)
        let issuer = "did:webvh:peer.example";
        let subject = "did:key:zSubject";
        let seed = [0xCDu8; 32];
        let signer = LocalSigner::from_ed25519_seed(issuer.into(), &seed);
        let pubkey = signer.public_bytes().to_vec();

        let vec_vc = build_role_vec(
            &signer,
            RoleVecParams::new(subject, VtcRole::Member)
                .with_validity(chrono::Duration::seconds(3600))
                .with_id("urn:vec:fresh"),
        )
        .await
        .expect("build vec");

        let status_url = "https://peer.example/status-lists/revocation";
        let status_ref = CredentialStatusRef::revocation(status_url, 42);
        let vmc_vc = build_vmc(
            &signer,
            VmcParams::new(subject)
                .with_validity(chrono::Duration::seconds(3600))
                .with_id("urn:vmc:revoked")
                .with_status_ref(status_ref),
        )
        .await
        .expect("build vmc");

        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        fetcher.set_bit(status_url, 42, true);
        let mock_reg = MockRegistryClient::new();
        mock_reg.set_recognised(issuer).await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg);

        let err = verify_foreign_vec(&vec_vc, &vmc_vc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect_err("must reject");
        assert!(matches!(err, RecognitionError::StatusListFailed(_)));
        assert_eq!(err.reason_code(), "status-list-failed");
    }

    #[tokio::test]
    async fn expired_credential_is_rejected_before_network() {
        let issuer = "did:webvh:peer.example";
        // Issue with a 1-second window so it expires by `now`.
        let (vec, vmc, pubkey) = fresh_pair(issuer, "did:key:zSubject", VtcRole::Member, 1).await;
        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        let mock_reg = MockRegistryClient::new();
        mock_reg.set_recognised(issuer).await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg.clone());

        // Verify 10 minutes in the future → both expired.
        let now = Utc::now() + chrono::Duration::minutes(10);
        let err = verify_foreign_vec(&vec, &vmc, &resolver, &fetcher, reg, now)
            .await
            .expect_err("must reject");
        assert!(matches!(err, RecognitionError::ValidityWindow(_)));
        assert_eq!(
            mock_reg.call_counts().await.recognise,
            0,
            "validity check should short-circuit before recognise"
        );
    }

    #[tokio::test]
    async fn issuer_mismatch_between_vec_and_vmc_rejected() {
        let issuer_a = "did:webvh:peer-a.example";
        let issuer_b = "did:webvh:peer-b.example";
        let (vec, _vmc_a, _pk_a) =
            fresh_pair(issuer_a, "did:key:zSubject", VtcRole::Member, 3600).await;
        let (_vec_b, vmc, _pk_b) =
            fresh_pair(issuer_b, "did:key:zSubject", VtcRole::Member, 3600).await;

        let resolver = StubKeyResolver::new();
        let fetcher = StubStatusFetcher::new();
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(MockRegistryClient::new());

        let err = verify_foreign_vec(&vec, &vmc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect_err("must reject");
        assert!(matches!(err, RecognitionError::Malformed(_)));
    }

    #[tokio::test]
    async fn registry_unreachable_maps_to_distinct_error_variant() {
        let issuer = "did:webvh:peer.example";
        let (vec, vmc, pubkey) =
            fresh_pair(issuer, "did:key:zSubject", VtcRole::Member, 3600).await;
        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        let mock_reg = MockRegistryClient::new();
        mock_reg
            .fail_next_recognise(crate::registry::RegistryError::Unreachable("dns".into()))
            .await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg);

        let err = verify_foreign_vec(&vec, &vmc, &resolver, &fetcher, reg, Utc::now())
            .await
            .expect_err("must reject");
        assert!(matches!(err, RecognitionError::RegistryUnreachable(_)));
        assert_eq!(err.reason_code(), "registry-unreachable");
    }

    #[tokio::test]
    async fn earliest_valid_until_picks_the_shorter_window() {
        let issuer = "did:webvh:peer.example";
        let subject = "did:key:zSubject";
        let seed = [0xCDu8; 32];
        let signer = LocalSigner::from_ed25519_seed(issuer.into(), &seed);
        let pubkey = signer.public_bytes().to_vec();

        // VEC valid 1h, VMC valid 30min — expected earliest =
        // VMC's window.
        let vec_vc = build_role_vec(
            &signer,
            RoleVecParams::new(subject, VtcRole::Member)
                .with_validity(chrono::Duration::hours(1))
                .with_id("urn:vec:long"),
        )
        .await
        .unwrap();
        let vmc_vc = build_vmc(
            &signer,
            VmcParams::new(subject)
                .with_validity(chrono::Duration::minutes(30))
                .with_id("urn:vmc:short"),
        )
        .await
        .unwrap();

        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let fetcher = StubStatusFetcher::new();
        let mock_reg = MockRegistryClient::new();
        mock_reg.set_recognised(issuer).await;
        let reg: Arc<dyn TrustRegistryClient> = Arc::new(mock_reg);

        let now = Utc::now();
        let verified = verify_foreign_vec(&vec_vc, &vmc_vc, &resolver, &fetcher, reg, now)
            .await
            .unwrap();

        // Earliest expiry is the VMC's 30-min window.
        let delta_minutes = (verified.earliest_valid_until - now).num_minutes();
        assert!(
            (28..=32).contains(&delta_minutes),
            "earliest valid_until ({delta_minutes} min) should be around 30",
        );
    }

    #[test]
    fn issuer_id_extraction_handles_both_value_shapes() {
        let uri = IssuerValue::Uri("did:webvh:a".into());
        assert_eq!(uri.id(), "did:webvh:a");
        let obj = IssuerValue::Object {
            id: "did:webvh:b".into(),
            properties: serde_json::Map::new(),
        };
        assert_eq!(obj.id(), "did:webvh:b");
    }

    // ---- status-list credential signature verification -------------------

    /// Build + eddsa-jcs-2022-sign a minimal `BitstringStatusListCredential` and
    /// return it with the signer's public key bytes.
    async fn signed_status_list(issuer_did: &str) -> (JsonValue, Vec<u8>) {
        let signer = LocalSigner::from_ed25519_seed(issuer_did.into(), &[0x5A; 32]);
        let mut list = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": issuer_did,
            "credentialSubject": {
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": "uH4sIAAAAAAAA_-3BAQ0AAAACIGf6_2sMAAAAAAAAAAAAAAAAAAAAAADwbWxoAAAA",
            },
        });
        signer.sign_doc(&mut list).await.expect("sign status list");
        (list, signer.public_bytes().to_vec())
    }

    #[tokio::test]
    async fn status_list_signature_valid_and_issuer_matched_passes() {
        let issuer = "did:web:issuer.example";
        let (list, pubkey) = signed_status_list(issuer).await;
        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        verify_status_list_signature(&list, Some(issuer), &resolver, "https://x/sl")
            .await
            .expect("a correctly-signed, issuer-matched list verifies");
    }

    #[tokio::test]
    async fn status_list_substituted_issuer_is_rejected() {
        let issuer = "did:web:issuer.example";
        let (list, pubkey) = signed_status_list(issuer).await;
        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        // Validly signed, but the checked credential's issuer is someone else.
        let err = verify_status_list_signature(
            &list,
            Some("did:web:stranger.example"),
            &resolver,
            "https://x/sl",
        )
        .await
        .expect_err("a list whose issuer != the credential's must be refused");
        assert!(
            matches!(err, RecognitionError::StatusListFailed(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn status_list_tampered_fails_signature() {
        let issuer = "did:web:issuer.example";
        let (mut list, pubkey) = signed_status_list(issuer).await;
        // Flip the encoded bitstring after signing.
        list["credentialSubject"]["encodedList"] = serde_json::json!("uTAMPERED");
        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let err = verify_status_list_signature(&list, Some(issuer), &resolver, "https://x/sl")
            .await
            .expect_err("a tampered list must fail signature verification");
        assert!(
            matches!(err, RecognitionError::StatusListFailed(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn status_list_without_proof_is_rejected() {
        let issuer = "did:web:issuer.example";
        let (mut list, pubkey) = signed_status_list(issuer).await;
        list.as_object_mut().unwrap().remove("proof");
        let resolver = StubKeyResolver::new().with(issuer, pubkey);
        let err = verify_status_list_signature(&list, Some(issuer), &resolver, "https://x/sl")
            .await
            .expect_err("an unsigned list must be refused");
        assert!(
            matches!(err, RecognitionError::StatusListFailed(_)),
            "{err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // P0.4: foreign-fetch client hardening (SSRF via redirect, timeout, body
    // cap). These drive the shared hardened client against a real local socket
    // (`wiremock`). The client itself carries no scheme/host allowlist — that
    // is `guard_status_list_url`, exercised separately — so it can target the
    // loopback test server here.
    // -----------------------------------------------------------------------

    /// A status-list URL that passes the guard but `302`s to an internal host
    /// must NOT be followed: the redirect target is never fetched. With
    /// `redirect(none)`, the client returns the `302` itself, which
    /// `check_status_bit` maps to `StatusListFailed`.
    #[tokio::test]
    async fn foreign_fetch_client_does_not_follow_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/list"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
            )
            .mount(&server)
            .await;

        let url = format!("{}/list", server.uri());
        let resp = foreign_fetch_client().get(&url).send().await.expect("send");
        assert_eq!(
            resp.status().as_u16(),
            302,
            "the redirect must NOT be followed (no fetch of the internal target)"
        );
    }

    /// A body larger than the cap is rejected before it is fully buffered.
    #[tokio::test]
    async fn read_body_capped_rejects_oversized_body() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 8192]))
            .mount(&server)
            .await;

        let resp = foreign_fetch_client()
            .get(server.uri())
            .send()
            .await
            .expect("send");
        let err = read_body_capped(resp, 1024, "https://list.example")
            .await
            .expect_err("an oversized body must be refused");
        assert!(
            matches!(&err, RecognitionError::StatusListFailed(m) if m.contains("cap")),
            "{err:?}"
        );
    }

    /// A body within the cap reads back intact.
    #[tokio::test]
    async fn read_body_capped_allows_body_within_cap() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
            .mount(&server)
            .await;

        let resp = foreign_fetch_client()
            .get(server.uri())
            .send()
            .await
            .expect("send");
        let bytes = read_body_capped(resp, 1024, "https://list.example")
            .await
            .expect("a small body must read back");
        assert_eq!(bytes, b"hello");
    }

    /// A host that stalls past the deadline trips the client timeout rather
    /// than pinning the request open. Uses a dedicated short-timeout client
    /// built the same way as the shared one (200 ms vs the production 10 s) so
    /// the test stays fast and deterministic.
    #[tokio::test]
    async fn foreign_fetch_client_times_out_on_a_slow_host() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;

        let err = client
            .get(server.uri())
            .send()
            .await
            .expect_err("a stalled host must trip the timeout");
        assert!(err.is_timeout(), "expected a timeout error, got: {err}");
    }
}
