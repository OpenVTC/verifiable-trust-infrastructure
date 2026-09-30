//! Passkey-as-verificationMethod enrolment for VTA-managed
//! webvh DIDs.
//!
//! End-to-end ceremony:
//!
//! 1. [`start_enrollment`] — caller (admin on the DID's context)
//!    posts `{did}`; the VTA mints a WebAuthn `CreationChallengeResponse`
//!    via `webauthn-rs`, persists a [`CeremonyState`] keyed by an
//!    opaque ceremony id, and projects the challenge to the wallet's
//!    flat schema ([`EnrollPasskeyChallengeResponse`]).
//! 2. [`finish_enrollment`] — wallet returns the WebAuthn
//!    registration response + the ceremony id. The VTA:
//!    - looks up + consumes the ceremony state,
//!    - validates the DID matches,
//!    - calls `webauthn-rs`'s `finish_passkey_registration` to verify
//!      the attestation against the stored challenge,
//!    - re-parses the `authenticatorData` to extract the COSE
//!      public key and re-derives the Multikey **independently** so
//!      a browser that lied about the public key fails closed,
//!    - builds a Multikey [`PasskeyVerificationMethod`] with id
//!      `<did>#passkey-<base64url(sha256(credential_id))>`,
//!    - reads the current DID document, appends the VM to
//!      `verificationMethod` and references it from `authentication`,
//!    - drives `update_did_webvh` to publish the new document
//!      (the WebVH key rotation that happens as a side-effect of
//!      a doc-bearing update is intentional — passkey adds are
//!      treated as full updates),
//!    - clears any live step-up elevation the DID's sessions hold that
//!      was **not** reached with a passkey — from this point
//!      `trust_tasks::step_up::handle_approve_response` requires one for
//!      this subject and no longer accepts the did-signed gate.
//! 3. [`list_passkeys`] — reads the current DID document and
//!    returns every verificationMethod whose fragment starts with
//!    `passkey-`.
//! 4. [`revoke_passkey`] — removes the VM by id, then calls
//!    `update_did_webvh`. The WebVH history preserves the entry
//!    for audit.
//!
//! Auth model: every endpoint requires an admin-role bearer token
//! whose `contexts` claim covers the DID's context. The handler
//! routes use `AdminAuth`; this module asserts the per-DID context
//! gate.

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::{Base64UrlSafeData, PasskeyRegistration, RegisterPublicKeyCredential};
use webauthn_rs_proto::{AuthenticatorAttestationResponseRaw, RegistrationExtensionsClientOutputs};

use vta_sdk::protocols::did_management::passkey_vms::{
    EnrollPasskeyChallengeResponse, EnrollPasskeySubmitBody, EnrollPasskeySubmitResponse,
    ListPasskeyVmsResponse, PasskeyVerificationMethod as ApiVerificationMethod,
};
use vti_common::auth::passkey::build_webauthn;

use crate::auth::AuthClaims;
use crate::operations::did_webvh::{UpdateDidWebvhOptions, update_did_webvh};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

mod errors;
// `pub(crate)` rather than private: the soft authenticator in `test_support`
// derives the same Multikey the submission path re-derives, and sharing the one
// function is what makes them agree by construction rather than by two
// implementations that happen to match today.
pub(crate) mod multikey;

pub use errors::PasskeyVmError;
pub use multikey::{MultikeyError, cose_key_to_multikey, parse_auth_data_to_multikey};

/// How long an issued challenge is valid before the ceremony record
/// is treated as stale. Long enough for a relaxed authenticator
/// dialog (biometric prompt, hybrid QR scan); short enough that a
/// stolen challenge can't sit unused for hours.
const CEREMONY_TTL_SECONDS: u64 = 300;

/// Persisted ceremony record, keyed by ceremony id. Atomic-take
/// semantics: [`take_ceremony`] reads then deletes — concurrent
/// finish attempts can't both pass.
#[derive(Debug, Serialize, Deserialize)]
struct CeremonyState {
    did: String,
    registration: PasskeyRegistration,
    /// Unix epoch seconds at which the ceremony record stops being
    /// honoured.
    expires_at: u64,
    label: Option<String>,
}

fn ceremony_key(id: &str) -> String {
    format!("ceremony:{id}")
}

async fn put_ceremony(
    ks: &KeyspaceHandle,
    id: &str,
    state: &CeremonyState,
) -> Result<(), PasskeyVmError> {
    ks.insert(ceremony_key(id), state)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("put ceremony: {e}")))
}

async fn take_ceremony(
    ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<CeremonyState>, PasskeyVmError> {
    let key = ceremony_key(id);
    let value: Option<CeremonyState> = ks
        .get(key.as_str())
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get ceremony: {e}")))?;
    if value.is_some() {
        ks.remove(key.as_str())
            .await
            .map_err(|e| PasskeyVmError::Persistence(format!("remove ceremony: {e}")))?;
    }
    Ok(value)
}

fn now_seconds() -> u64 {
    Utc::now().timestamp() as u64
}

fn require_public_url(config: &crate::config::AppConfig) -> Result<&str, PasskeyVmError> {
    config.public_url.as_deref().ok_or_else(|| {
        PasskeyVmError::NotAvailable(
            "`public_url` is not configured — passkey VM enrolment requires the VTA's public origin"
                .into(),
        )
    })
}

/// Compute the URL-safe base64 (no-pad) of an arbitrary byte slice.
fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64u_decode(s: &str) -> Result<Vec<u8>, PasskeyVmError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| PasskeyVmError::InvalidAttestation(format!("base64url decode: {e}")))
}

/// Stable WebAuthn user handle for a DID. The handle is what the
/// authenticator binds the credential to — using a SHA-256 of the
/// DID gives each DID a deterministic, opaque 32-byte handle.
fn user_handle_for_did(did: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    hasher.finalize().to_vec()
}

/// The WebAuthn `user.name` / `user.displayName` for an enrolment.
///
/// **Not the DID.** This is the string an authenticator shows in the credential
/// picker, and WebAuthn L2 §5.4.3 lets an authenticator truncate it to 64
/// bytes — which the registry's `maxLength: 64` on `userName` /
/// `userDisplayName` mirrors. A `did:webvh` is routinely longer than that: the
/// SCID alone is ~46 characters before the host and path. Sending the raw DID
/// produced a response the 0.17 schema rejects outright, and before that a
/// picker entry truncated mid-SCID — unreadable, and identical between two DIDs
/// on the same host.
///
/// Nothing is lost by not sending it. `userHandle` is the DID-derived binding
/// (see [`user_handle_for_did`]) and is unbounded; `user.name` is a label for a
/// human, so it gets one:
///
/// * the operator's `label` when the enrolment supplied one, else
/// * the DID with its `did:<method>:<scid>:` prefix dropped — the host and path
///   are the part a person recognises, the SCID is the part they cannot.
///
/// Clamped on a `char` boundary so a multi-byte label cannot split.
fn display_name_for(did: &str, label: Option<&str>) -> String {
    const MAX: usize = 64;
    let base = match label {
        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
        _ => did
            .strip_prefix("did:")
            .and_then(|rest| rest.split_once(':'))
            .and_then(|(_method, rest)| rest.split_once(':'))
            .map(|(_scid, tail)| tail.to_string())
            .unwrap_or_else(|| did.to_string()),
    };
    if base.chars().count() <= MAX {
        return base;
    }
    // Keep the tail: for a path-shaped identifier the distinguishing part is at
    // the end (`…:dids:persona`), not the start.
    let skip = base.chars().count() - MAX + 1;
    format!("…{}", base.chars().skip(skip).collect::<String>())
}

/// VM fragment derivation: `passkey-<base64url(sha256(credential_id))>`.
fn fragment_for_credential(credential_id: &[u8]) -> String {
    let hash = Sha256::digest(credential_id);
    format!("passkey-{}", b64u(&hash))
}

// ---------------------------------------------------------------------------
// start_enrollment
// ---------------------------------------------------------------------------

/// Mint a WebAuthn registration challenge tied to `did`. Caller
/// must have `admin` role on the DID's context.
pub async fn start_enrollment(
    webvh_ks: &KeyspaceHandle,
    passkey_vms_ks: &KeyspaceHandle,
    config: &crate::config::AppConfig,
    auth: &AuthClaims,
    did: &str,
    label: Option<String>,
) -> Result<EnrollPasskeyChallengeResponse, PasskeyVmError> {
    let public_url = require_public_url(config)?;
    let webauthn = build_webauthn(public_url)
        .map_err(|e| PasskeyVmError::NotAvailable(format!("webauthn builder: {e}")))?;

    // Auth gate: caller must be admin on the DID's context.
    let record = webvh_store::get_did(webvh_ks, did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    auth.require_admin()
        .map_err(|e| PasskeyVmError::PermissionDenied(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id)
        .map_err(|_| PasskeyVmError::DidNotFound)?;

    // Stable per-DID user handle; opaque to the wallet.
    let user_handle = user_handle_for_did(did);
    let user_uuid = Uuid::from_slice(&user_handle[..16])
        .map_err(|e| PasskeyVmError::Internal(format!("derive user uuid from handle: {e}")))?;

    let display = display_name_for(did, label.as_deref());
    let (ccr, registration) = webauthn
        .start_passkey_registration(user_uuid, &display, &display, None)
        .map_err(|e| PasskeyVmError::Internal(format!("start_passkey_registration: {e}")))?;

    // Persist ceremony state. Use a fresh UUID as the ceremony id
    // separate from the user handle — handle is DID-stable, ceremony
    // id is per-attempt.
    let ceremony_id = Uuid::new_v4().to_string();
    let state = CeremonyState {
        did: did.to_string(),
        registration,
        expires_at: now_seconds() + CEREMONY_TTL_SECONDS,
        label,
    };
    put_ceremony(passkey_vms_ks, &ceremony_id, &state).await?;

    let public = ccr.public_key;
    let challenge_b64 = b64u(public.challenge.as_ref());
    let user_handle_b64 = b64u(public.user.id.as_ref());

    Ok(EnrollPasskeyChallengeResponse {
        ceremony_id,
        challenge: challenge_b64,
        rp_id: public.rp.id,
        rp_name: public.rp.name,
        user_handle: user_handle_b64,
        user_name: public.user.name,
        user_display_name: public.user.display_name,
        timeout_ms: public.timeout,
    })
}

// ---------------------------------------------------------------------------
// finish_enrollment
// ---------------------------------------------------------------------------

/// Verify the WebAuthn ceremony, build the passkey VM, append it
/// to the DID document, and publish via WebVH.
pub async fn finish_enrollment(
    deps: &crate::operations::did_webvh::WebvhDeps<'_>,
    passkey_vms_ks: &KeyspaceHandle,
    sessions_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    body: EnrollPasskeySubmitBody,
    vta_did: Option<&str>,
    config: &crate::config::AppConfig,
    channel: &str,
) -> Result<EnrollPasskeySubmitResponse, PasskeyVmError> {
    // 0. Service-availability + auth-context.
    let public_url = require_public_url(config)?;
    let webauthn = build_webauthn(public_url)
        .map_err(|e| PasskeyVmError::NotAvailable(format!("webauthn builder: {e}")))?;

    let record = webvh_store::get_did(deps.webvh_ks, &body.did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    auth.require_admin()
        .map_err(|e| PasskeyVmError::PermissionDenied(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id)
        .map_err(|_| PasskeyVmError::DidNotFound)?;

    // 1. Take ceremony state (atomic).
    let state = take_ceremony(passkey_vms_ks, &body.ceremony_id)
        .await?
        .ok_or(PasskeyVmError::UnknownCeremony)?;
    if state.expires_at < now_seconds() {
        return Err(PasskeyVmError::UnknownCeremony);
    }
    if state.did != body.did {
        return Err(PasskeyVmError::CeremonyDidMismatch);
    }
    let effective_label = body.label.clone().or_else(|| state.label.clone());

    // 2. Reconstruct the WebAuthn `RegisterPublicKeyCredential` from
    //    the wallet's flat fields, then drive webauthn-rs's finish.
    let cred = build_register_public_key_credential(&body)?;
    let _passkey = webauthn
        .finish_passkey_registration(&cred, &state.registration)
        .map_err(|e| PasskeyVmError::WebauthnFinishFailed(e.to_string()))?;

    // 3. Independent multikey derivation from authenticatorData.
    //    This is the anti-tamper gate: if the wallet's claimed
    //    `public_key_multibase` doesn't match what we extract from
    //    the attestation, fail closed.
    let auth_data_bytes = b64u_decode(&body.authenticator_data)?;
    let parsed = parse_auth_data_to_multikey(&auth_data_bytes)?;
    if parsed.multikey != body.public_key_multibase {
        return Err(PasskeyVmError::PublicKeyMismatch);
    }
    if parsed.cose_algorithm != body.cose_algorithm {
        return Err(PasskeyVmError::InvalidAttestation(format!(
            "cose_algorithm mismatch: claimed {} vs attested {}",
            body.cose_algorithm, parsed.cose_algorithm
        )));
    }

    // 4. Build the VM JSON.
    let credential_id_bytes = b64u_decode(&body.credential_id)?;
    let fragment = fragment_for_credential(&credential_id_bytes);
    let vm_id = format!("{}#{fragment}", record.did);
    let vm = ApiVerificationMethod {
        id: vm_id.clone(),
        vm_type: "Multikey".into(),
        controller: record.did.clone(),
        public_key_multibase: body.public_key_multibase.clone(),
        webauthn_credential_id: body.credential_id.clone(),
        webauthn_transports: body.transports.clone(),
        label: effective_label,
    };

    // 5. Read current document, append the VM, reference it from
    //    `authentication`.
    let did_log = webvh_store::get_did_log(deps.webvh_ks, &record.did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did_log: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    let current_doc = extract_latest_document(&did_log)?;
    let new_doc = append_vm_to_document(&current_doc, &vm)?;

    // 6. Publish via `update_did_webvh`. The doc-bearing path
    //    rotates WebVH update_keys as a side effect — intentional.
    let opts = UpdateDidWebvhOptions {
        document: Some(new_doc),
        pre_rotation_count: None,
        witnesses: None,
        watchers: None,
        ttl: None,
        label: Some(format!("enroll passkey VM {fragment}")),
        expected_version_id: None,
    };
    let result = update_did_webvh(deps, auth, &record.scid, opts, vta_did, channel).await?;

    // 7. This DID now has a passkey: `handle_approve_response` will refuse a
    //    did-signed approve-response for it from here on (`noGate`), so a live
    //    elevation it reached the did-signed way no longer reflects a factor
    //    the subject can still re-prove. Clear it. Best-effort: the enrolment
    //    itself already succeeded and published, and a stale elevation lapses
    //    on its own inside `STEP_UP_ELEVATION_TTL_SECS` regardless, so a store
    //    hiccup here does not warrant failing an otherwise-complete enrolment.
    if let Err(e) = clear_non_passkey_elevation_for_did(sessions_ks, &record.did).await {
        tracing::warn!(
            did = %record.did, error = %e,
            "passkey VM enrolled, but clearing any prior non-passkey step-up \
             elevation failed; it will still lapse at its own TTL"
        );
    }

    Ok(EnrollPasskeySubmitResponse {
        verification_method: vm,
        webvh_version: result.new_version_id,
    })
}

/// Clear a live, non-passkey step-up elevation on every session `did` holds
/// ([`crate::auth::session::Session::clear_non_passkey_elevation`]). Returns
/// how many session rows were rewritten.
async fn clear_non_passkey_elevation_for_did(
    sessions_ks: &KeyspaceHandle,
    did: &str,
) -> Result<usize, PasskeyVmError> {
    use crate::auth::session::{list_sessions, update_session};

    let mut cleared = 0usize;
    for mut session in list_sessions(sessions_ks)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("list sessions: {e}")))?
        .into_iter()
        .filter(|s| s.did == did)
    {
        if session.clear_non_passkey_elevation() {
            update_session(sessions_ks, &session)
                .await
                .map_err(|e| PasskeyVmError::Persistence(format!("update session: {e}")))?;
            cleared += 1;
        }
    }
    Ok(cleared)
}

fn build_register_public_key_credential(
    body: &EnrollPasskeySubmitBody,
) -> Result<RegisterPublicKeyCredential, PasskeyVmError> {
    let raw_id = b64u_decode(&body.credential_id)?;
    let attestation = b64u_decode(&body.attestation_object)?;
    let client_data = b64u_decode(&body.client_data_json)?;

    let transports = body
        .transports
        .iter()
        .filter_map(|t| serde_json::from_value(json!(t)).ok())
        .collect::<Vec<_>>();
    let transports = if transports.is_empty() {
        None
    } else {
        Some(transports)
    };

    Ok(RegisterPublicKeyCredential {
        id: body.credential_id.clone(),
        raw_id: Base64UrlSafeData::from(raw_id),
        response: AuthenticatorAttestationResponseRaw {
            attestation_object: Base64UrlSafeData::from(attestation),
            client_data_json: Base64UrlSafeData::from(client_data),
            transports,
        },
        type_: "public-key".into(),
        extensions: RegistrationExtensionsClientOutputs::default(),
    })
}

// ---------------------------------------------------------------------------
// list_passkeys
// ---------------------------------------------------------------------------

pub async fn list_passkeys(
    webvh_ks: &KeyspaceHandle,
    auth: &AuthClaims,
    did: &str,
) -> Result<ListPasskeyVmsResponse, PasskeyVmError> {
    let record = webvh_store::get_did(webvh_ks, did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    auth.require_context(&record.context_id)
        .map_err(|_| PasskeyVmError::DidNotFound)?;

    let did_log = webvh_store::get_did_log(webvh_ks, did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did_log: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    let current_doc = extract_latest_document(&did_log)?;

    let mut vms: Vec<ApiVerificationMethod> = Vec::new();
    if let Some(arr) = current_doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
    {
        for entry in arr {
            let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let frag = id.split('#').nth(1).unwrap_or_default();
            if !frag.starts_with("passkey-") {
                continue;
            }
            if let Ok(parsed) = serde_json::from_value::<ApiVerificationMethod>(entry.clone()) {
                vms.push(parsed);
            }
        }
    }

    Ok(ListPasskeyVmsResponse {
        verification_methods: vms,
    })
}

// ---------------------------------------------------------------------------
// Passkey-only step-up support (`trust_tasks::step_up`)
// ---------------------------------------------------------------------------

/// The passkey (fragment `passkey-*`) verification methods on `did`'s current
/// WebVH document, unauthenticated (internal, policy-driving reads — not a
/// caller-facing operation, so no admin/context gate like [`list_passkeys`]).
/// Empty for a DID this VTA does not manage.
///
/// Reads the last log line directly
/// ([`current_document_from_log`](crate::operations::protocol::document::current_document_from_log)),
/// not the chain-validated [`extract_latest_document`] `list_passkeys` and
/// the mutating operations use: this is a read-only, best-effort lookup that
/// drives a security *gate* (passkey-only step-up), not a document mutation,
/// and it should not fail closed on a chain-validation defect elsewhere in
/// the log history that has nothing to do with whether a passkey VM is on
/// the current document.
async fn passkey_vms_of(
    webvh_ks: &KeyspaceHandle,
    did: &str,
) -> Result<Vec<Value>, PasskeyVmError> {
    use crate::operations::protocol::document::current_document_from_log;

    let Some(did_log) = webvh_store::get_did_log(webvh_ks, did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did_log: {e}")))?
    else {
        return Ok(Vec::new());
    };
    let doc = current_document_from_log(&did_log)
        .map_err(|e| PasskeyVmError::Internal(format!("current_document_from_log: {e}")))?;
    Ok(doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|vm| {
                    vm.get("id")
                        .and_then(|v| v.as_str())
                        .and_then(|id| id.split('#').nth(1))
                        .is_some_and(|frag| frag.starts_with("passkey-"))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default())
}

/// Whether `did` has at least one enrolled passkey verification method. See
/// [`crate::trust_tasks::step_up`]'s passkey-only step-up: once true, a
/// did-signed approve-response for `did` is refused (`noGate`).
pub async fn has_passkey_vm(webvh_ks: &KeyspaceHandle, did: &str) -> Result<bool, PasskeyVmError> {
    Ok(!passkey_vms_of(webvh_ks, did).await?.is_empty())
}

/// Resolve a submitted WebAuthn `credential.id` to the verification-method id
/// of one of `did`'s enrolled passkeys, by comparing against each VM's stored
/// `webauthnCredentialId`.
///
/// This is the credential-id → VM binding the step-up webauthn gate needs.
/// Deliberately **not** routed through the generic DID resolver
/// (`operations::passkey_login::enumerate_passkey_vms`, still a "Phase 3"
/// stub there): `webauthnCredentialId` is a VTA-specific verification-method
/// property that a generic resolver's typed round-trip does not preserve.
/// Reading the local document — the same source [`list_passkeys`] reads —
/// sidesteps that; the signature itself is still verified afterwards through
/// the generic resolver, over the standard `publicKeyMultibase` field that
/// gap does not touch.
pub async fn find_passkey_vm_by_credential_id(
    webvh_ks: &KeyspaceHandle,
    did: &str,
    credential_id: &[u8],
) -> Result<Option<String>, PasskeyVmError> {
    for vm in passkey_vms_of(webvh_ks, did).await? {
        let Some(id) = vm.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(cred_b64) = vm.get("webauthnCredentialId").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(cred_bytes) = b64u_decode(cred_b64) else {
            continue;
        };
        if cred_bytes == credential_id {
            return Ok(Some(id.to_string()));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// revoke_passkey
// ---------------------------------------------------------------------------

pub async fn revoke_passkey(
    deps: &crate::operations::did_webvh::WebvhDeps<'_>,
    auth: &AuthClaims,
    did: &str,
    fragment: &str,
    vta_did: Option<&str>,
    channel: &str,
) -> Result<(), PasskeyVmError> {
    let record = webvh_store::get_did(deps.webvh_ks, did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    auth.require_admin()
        .map_err(|e| PasskeyVmError::PermissionDenied(format!("admin required: {e}")))?;
    auth.require_context(&record.context_id)
        .map_err(|_| PasskeyVmError::DidNotFound)?;

    if !fragment.starts_with("passkey-") {
        return Err(PasskeyVmError::DidNotFound);
    }
    let vm_id = format!("{did}#{fragment}");

    let did_log = webvh_store::get_did_log(deps.webvh_ks, did)
        .await
        .map_err(|e| PasskeyVmError::Persistence(format!("get_did_log: {e}")))?
        .ok_or(PasskeyVmError::DidNotFound)?;
    let current_doc = extract_latest_document(&did_log)?;
    let new_doc = remove_vm_from_document(&current_doc, &vm_id)?;

    let opts = UpdateDidWebvhOptions {
        document: Some(new_doc),
        pre_rotation_count: None,
        witnesses: None,
        watchers: None,
        ttl: None,
        label: Some(format!("revoke passkey VM {fragment}")),
        expected_version_id: None,
    };
    update_did_webvh(deps, auth, &record.scid, opts, vta_did, channel).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Document mutation helpers
// ---------------------------------------------------------------------------

/// Extract the most recent DID document from the JSONL log via
/// `state_from_jsonl`. Kept private so the operations module owns
/// the chain-validation invariant.
fn extract_latest_document(did_log: &str) -> Result<Value, PasskeyVmError> {
    use didwebvh_rs::log_entry::LogEntryMethods;

    let state = super::did_webvh::state_from_jsonl_pub(did_log)
        .map_err(|e| PasskeyVmError::Internal(format!("state_from_jsonl: {e}")))?;
    let last = state
        .log_entries()
        .last()
        .ok_or_else(|| PasskeyVmError::Internal("no log entries".into()))?;
    last.log_entry
        .get_did_document()
        .map_err(|e| PasskeyVmError::Internal(format!("get_did_document: {e}")))
}

fn append_vm_to_document(
    current: &Value,
    vm: &ApiVerificationMethod,
) -> Result<Value, PasskeyVmError> {
    let mut new_doc = current.clone();
    let obj = new_doc
        .as_object_mut()
        .ok_or_else(|| PasskeyVmError::Internal("DID document is not a JSON object".into()))?;

    let vm_json = vm.to_json_value();
    let vm_id = vm.id.clone();

    let vms = obj
        .entry("verificationMethod".to_string())
        .or_insert_with(|| Value::Array(vec![]));
    let arr = vms
        .as_array_mut()
        .ok_or_else(|| PasskeyVmError::Internal("verificationMethod is not an array".into()))?;
    if arr
        .iter()
        .any(|v| v.get("id").and_then(|i| i.as_str()) == Some(&vm_id))
    {
        return Err(PasskeyVmError::FragmentCollision(vm_id));
    }
    arr.push(vm_json);

    let auths = obj
        .entry("authentication".to_string())
        .or_insert_with(|| Value::Array(vec![]));
    if let Some(auth_arr) = auths.as_array_mut()
        && !auth_arr.iter().any(|v| v.as_str() == Some(&vm_id))
    {
        auth_arr.push(Value::String(vm_id));
    }

    Ok(new_doc)
}

fn remove_vm_from_document(current: &Value, vm_id: &str) -> Result<Value, PasskeyVmError> {
    let mut new_doc = current.clone();
    let obj = new_doc
        .as_object_mut()
        .ok_or_else(|| PasskeyVmError::Internal("DID document is not a JSON object".into()))?;

    let mut removed = false;
    if let Some(arr) = obj
        .get_mut("verificationMethod")
        .and_then(|v| v.as_array_mut())
    {
        let len_before = arr.len();
        arr.retain(|v| v.get("id").and_then(|i| i.as_str()) != Some(vm_id));
        if arr.len() < len_before {
            removed = true;
        }
    }
    if !removed {
        // The fragment isn't on the document — distinct from "DID not
        // found" so revoke can emit `revoke:fragmentNotFound` (#308).
        return Err(PasskeyVmError::FragmentNotFound);
    }
    for field in ["authentication", "assertionMethod", "keyAgreement"] {
        if let Some(arr) = obj.get_mut(field).and_then(|v| v.as_array_mut()) {
            arr.retain(|v| v.as_str() != Some(vm_id));
        }
    }
    Ok(new_doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use vti_common::config::StoreConfig;

    fn temp_webvh_ks() -> (Store, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store open");
        let webvh_ks = store
            .keyspace(crate::keyspaces::WEBVH)
            .expect("webvh keyspace");
        (store, webvh_ks, dir)
    }

    /// Write a minimal, single-entry did.jsonl whose current document is
    /// `doc` — enough for [`extract_latest_document`] (and therefore
    /// [`has_passkey_vm`] / [`find_passkey_vm_by_credential_id`]), with no
    /// proof-chain validity required (mirrors `server.rs`'s
    /// `preload_self_did_document` fixture).
    async fn seed_did_document(webvh_ks: &KeyspaceHandle, did: &str, doc: Value) {
        let log_line = json!({
            "versionId": "1-test",
            "versionTime": "2026-05-06T00:00:00Z",
            "parameters": {},
            "state": doc,
        });
        webvh_store::store_did_log(webvh_ks, did, &serde_json::to_string(&log_line).unwrap())
            .await
            .expect("store did log");
    }

    fn passkey_vm(did: &str, fragment: &str, credential_id_b64: &str) -> Value {
        json!({
            "id": format!("{did}#{fragment}"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": "zNotRealButUnused",
            "webauthnCredentialId": credential_id_b64,
        })
    }

    #[tokio::test]
    async fn has_passkey_vm_is_false_for_an_unmanaged_did() {
        let (_store, webvh_ks, _dir) = temp_webvh_ks();
        assert!(
            !has_passkey_vm(&webvh_ks, "did:key:zNeverEnrolled")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn has_passkey_vm_is_false_when_the_document_has_no_passkey_fragment() {
        let (_store, webvh_ks, _dir) = temp_webvh_ks();
        let did = "did:key:zNoPasskey";
        seed_did_document(
            &webvh_ks,
            did,
            json!({
                "id": did,
                "verificationMethod": [{
                    "id": format!("{did}#key-0"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": "zKey0",
                }],
            }),
        )
        .await;

        assert!(!has_passkey_vm(&webvh_ks, did).await.unwrap());
    }

    #[tokio::test]
    async fn has_passkey_vm_is_true_once_a_passkey_fragment_is_enrolled() {
        let (_store, webvh_ks, _dir) = temp_webvh_ks();
        let did = "did:key:zHasPasskey";
        seed_did_document(
            &webvh_ks,
            did,
            json!({
                "id": did,
                "verificationMethod": [passkey_vm(did, "passkey-x", "Y3JlZF8x")],
            }),
        )
        .await;

        assert!(has_passkey_vm(&webvh_ks, did).await.unwrap());
    }

    #[tokio::test]
    async fn find_passkey_vm_by_credential_id_resolves_the_matching_vm() {
        let (_store, webvh_ks, _dir) = temp_webvh_ks();
        let did = "did:key:zTwoPasskeys";
        seed_did_document(
            &webvh_ks,
            did,
            json!({
                "id": did,
                "verificationMethod": [
                    passkey_vm(did, "passkey-a", "Y3JlZF9h"),
                    passkey_vm(did, "passkey-b", "Y3JlZF9i"),
                ],
            }),
        )
        .await;

        let found = find_passkey_vm_by_credential_id(&webvh_ks, did, b"cred_b")
            .await
            .unwrap();
        assert_eq!(found.as_deref(), Some(format!("{did}#passkey-b").as_str()));

        // A credential id enrolled on no VM resolves to nothing.
        assert_eq!(
            find_passkey_vm_by_credential_id(&webvh_ks, did, b"cred_unknown")
                .await
                .unwrap(),
            None
        );
    }

    // ── Passkey-only step-up: clearing a prior elevation ─────────────

    fn fresh_sessions_ks() -> (Store, KeyspaceHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("store open");
        let sessions_ks = store
            .keyspace(crate::keyspaces::SESSIONS)
            .expect("sessions keyspace");
        (store, sessions_ks, dir)
    }

    #[tokio::test]
    async fn clear_non_passkey_elevation_for_did_downgrades_only_that_dids_non_passkey_sessions() {
        use crate::auth::session::{Session, SessionState, get_session, now_epoch, store_session};

        let (_store, sessions_ks, _dir) = fresh_sessions_ks();
        let did = "did:key:zEnrolling";
        let other_did = "did:key:zSomeoneElse";

        let base = |session_id: &str, did: &str| Session {
            session_id: session_id.into(),
            did: did.into(),
            challenge: String::new(),
            state: SessionState::Authenticated,
            created_at: now_epoch(),
            last_seen: now_epoch(),
            refresh_token: None,
            refresh_expires_at: None,
            tee_attested: false,
            amr: vec!["did".into()],
            acr: "aal2".into(),
            acr_expires_at: Some(now_epoch() + 900),
            token_id: None,
            session_pubkey_b58btc: None,
        };

        // This DID's did-signed elevation — must be cleared.
        store_session(&sessions_ks, &base("sess-1", did))
            .await
            .unwrap();
        // This DID's passkey-backed elevation — must be left alone.
        let mut passkey_backed = base("sess-2", did);
        passkey_backed.amr = vec!["did".into(), "passkey".into()];
        store_session(&sessions_ks, &passkey_backed).await.unwrap();
        // A different DID's did-signed elevation — must be left alone.
        store_session(&sessions_ks, &base("sess-3", other_did))
            .await
            .unwrap();

        let cleared = clear_non_passkey_elevation_for_did(&sessions_ks, did)
            .await
            .unwrap();
        assert_eq!(cleared, 1);

        let s1 = get_session(&sessions_ks, "sess-1").await.unwrap().unwrap();
        assert_eq!(s1.acr, "aal1");
        assert_eq!(s1.acr_expires_at, None);

        let s2 = get_session(&sessions_ks, "sess-2").await.unwrap().unwrap();
        assert_eq!(s2.acr, "aal2", "passkey-backed elevation left alone");

        let s3 = get_session(&sessions_ks, "sess-3").await.unwrap().unwrap();
        assert_eq!(
            s3.acr, "aal2",
            "a different DID's session must be untouched"
        );
    }

    #[test]
    fn user_handle_is_deterministic_per_did() {
        let a1 = user_handle_for_did("did:webvh:example.com:abc");
        let a2 = user_handle_for_did("did:webvh:example.com:abc");
        let b = user_handle_for_did("did:webvh:example.com:xyz");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(a1.len(), 32);
    }

    #[test]
    fn fragment_is_credential_id_sha256() {
        let frag = fragment_for_credential(b"some-cred-id");
        assert!(frag.starts_with("passkey-"));
        // 32-byte SHA-256 → 43 chars base64url-nopad
        assert_eq!(frag.len(), "passkey-".len() + 43);
    }

    #[test]
    fn append_vm_creates_authentication_reference() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:example.com:abc",
            "verificationMethod": [
                {
                    "id": "did:webvh:example.com:abc#key-0",
                    "type": "Multikey",
                    "controller": "did:webvh:example.com:abc",
                    "publicKeyMultibase": "zExisting",
                }
            ],
            "authentication": ["did:webvh:example.com:abc#key-0"],
        });

        let vm = ApiVerificationMethod {
            id: "did:webvh:example.com:abc#passkey-abcdef".into(),
            vm_type: "Multikey".into(),
            controller: "did:webvh:example.com:abc".into(),
            public_key_multibase: "zNew".into(),
            webauthn_credential_id: "credId".into(),
            webauthn_transports: vec![],
            label: None,
        };
        let new = append_vm_to_document(&doc, &vm).unwrap();
        let vms = new["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 2);
        let auths = new["authentication"].as_array().unwrap();
        assert!(
            auths.iter().any(|v| v.as_str() == Some(&vm.id)),
            "new VM id missing from authentication: {auths:?}"
        );
    }

    #[test]
    fn append_vm_refuses_duplicate_id() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:example.com:abc",
            "verificationMethod": [
                {
                    "id": "did:webvh:example.com:abc#passkey-x",
                    "type": "Multikey",
                    "controller": "did:webvh:example.com:abc",
                    "publicKeyMultibase": "zX",
                }
            ],
        });
        let vm = ApiVerificationMethod {
            id: "did:webvh:example.com:abc#passkey-x".into(),
            vm_type: "Multikey".into(),
            controller: "did:webvh:example.com:abc".into(),
            public_key_multibase: "zY".into(),
            webauthn_credential_id: "credId".into(),
            webauthn_transports: vec![],
            label: None,
        };
        let err = append_vm_to_document(&doc, &vm).unwrap_err();
        assert!(matches!(err, PasskeyVmError::FragmentCollision(_)));
    }

    #[test]
    fn remove_vm_drops_from_all_purpose_arrays() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:example.com:abc",
            "verificationMethod": [
                {
                    "id": "did:webvh:example.com:abc#passkey-x",
                    "type": "Multikey",
                    "controller": "did:webvh:example.com:abc",
                    "publicKeyMultibase": "zX",
                },
                {
                    "id": "did:webvh:example.com:abc#key-0",
                    "type": "Multikey",
                    "controller": "did:webvh:example.com:abc",
                    "publicKeyMultibase": "zK",
                }
            ],
            "authentication": [
                "did:webvh:example.com:abc#passkey-x",
                "did:webvh:example.com:abc#key-0"
            ],
        });
        let new = remove_vm_from_document(&doc, "did:webvh:example.com:abc#passkey-x").unwrap();
        let vms = new["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0]["id"], "did:webvh:example.com:abc#key-0");
        let auths = new["authentication"].as_array().unwrap();
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0], "did:webvh:example.com:abc#key-0");
    }

    #[test]
    fn remove_vm_absent_fragment_is_fragment_not_found() {
        // Revoking a fragment that isn't on the document must surface as
        // FragmentNotFound (→ `revoke:fragmentNotFound`), not DidNotFound.
        let doc = serde_json::json!({
            "verificationMethod": [{
                "id": "did:webvh:example.com:abc#key-0",
                "type": "Multikey",
                "controller": "did:webvh:example.com:abc",
                "publicKeyMultibase": "zK"
            }]
        });
        let err =
            remove_vm_from_document(&doc, "did:webvh:example.com:abc#passkey-missing").unwrap_err();
        assert!(
            matches!(err, PasskeyVmError::FragmentNotFound),
            "expected FragmentNotFound, got {err:?}"
        );
    }
}

#[cfg(test)]
mod display_name_tests {
    use super::display_name_for;

    /// The case that broke: a real `did:webvh` is longer than the schema's
    /// `maxLength: 64`, and the part a person recognises is the tail.
    #[test]
    fn a_webvh_did_loses_its_scid_and_fits() {
        let did =
            "did:webvh:QmSRTjKQF54iQfv58QjbbcunzZ1GiDzvuFFPERVHwUF4kX:webvh-host.test:dids:persona";
        assert!(
            did.chars().count() > 64,
            "the fixture must be over the bound"
        );
        let got = display_name_for(did, None);
        assert_eq!(got, "webvh-host.test:dids:persona");
        assert!(got.chars().count() <= 64);
    }

    /// An operator-supplied label wins — it is the whole reason `label` is on
    /// the enrolment payload.
    #[test]
    fn a_label_is_preferred() {
        assert_eq!(
            display_name_for("did:webvh:QmScid:example.com:dids:x", Some("Ops laptop")),
            "Ops laptop"
        );
    }

    /// Whitespace-only is not a label.
    #[test]
    fn a_blank_label_falls_back_to_the_did() {
        assert_eq!(
            display_name_for("did:webvh:QmScid:example.com:dids:x", Some("   ")),
            "example.com:dids:x"
        );
    }

    /// A DID that is not `did:method:scid:tail` shaped is left alone rather
    /// than mangled — `did:key` has no SCID to drop.
    #[test]
    fn a_short_did_key_is_left_whole() {
        let did = "did:key:z6MkAgent";
        assert_eq!(display_name_for(did, None), did);
    }

    /// Over-long input is clamped on a char boundary, keeping the tail.
    #[test]
    fn an_over_long_label_is_clamped_without_splitting_a_char() {
        let label = "é".repeat(200);
        let got = display_name_for("did:key:z6Mk", Some(&label));
        assert_eq!(got.chars().count(), 64, "clamped to the bound");
        assert!(got.starts_with('…'));
        assert!(got.is_char_boundary(got.len()));
    }
}
